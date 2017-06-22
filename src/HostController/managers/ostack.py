import logging
import time
import urllib2
import ipaddress
from threading import Thread, RLock
from openstack import connection
from openstack import profile
from openstack import utils
from netmons import BareNetMon, SnifferAlreadyRunningException
from uuid import uuid4
from HostController.miscellaneus import MacAddress
from HostController.logic.WorkerStatus import WorkerStatus
from machine_manager import IGuestManager, IGuest, MachineState, NETLOG_NAME, HTTPS_NETLOG_NAME
import os

__author__ = 'Alberto Geniola'

INTERNAL_NETWORK_PORT_NAME="sniffer_int_port"
EXTERNAL_NETWORK_PORT_NAME="sniffer_ext_port"

mapped_states = {
    "SHUTOFF": MachineState.stopped,
    "STOPPED": MachineState.stopped,
    "ACTIVE": MachineState.running,

    "ERROR": MachineState.error,
    "DELETED": MachineState.error,


    "BUILD": MachineState.busy,
    "HARD_REBOOT": MachineState.busy,
    "MIGRATING": MachineState.busy,
    "PASSWORD": MachineState.busy,
    "REBOOT": MachineState.busy,
    "REBUILD": MachineState.busy,
    "RESIZE": MachineState.busy,
    "REVERT_RESIZE": MachineState.busy,
    "DeletingSnapshotOnline": MachineState.busy,
    "SettingUp": MachineState.busy,
    "VERIFY_RESIZE": MachineState.busy,

    "UNKNOWN": MachineState.unknown,
    "SUSPENDED": MachineState.unknown,
    "SOFT_DELETED": MachineState.unknown,
    "SHELVED": MachineState.unknown,
    "SHELVED_OFFLOADED": MachineState.unknown,
    "PAUSED": MachineState.unknown,
    "RESCUE": MachineState.unknown
}


class OpenStackManager(IGuestManager):
    _auth_url = None
    _project_name = None
    _username = None
    _password = None

    _netmon = None
    _n_workers = None

    _sniffer_name=None
    _sniffer_flavor = None
    _sniffer_flavor_id = None
    _sniffer_image = None
    _sniffer_image_id = None
    _sniffer_port = None
    _sniffer_security_group = None

    _guest_flavor = None
    _guest_flavor_id = None
    _guest_image = None
    _guest_image_id = None
    _guest_security_group = None

    _public_network = None
    _external_router_name = None
    _public_network_id = None
    _internal_network = None
    _internal_network_id = None
    _intranet_subnetwork = None
    _intranet_subnetwork_id = None

    _sniffer_floating_ip = None

    _external_hc_ip = None
    _external_hc_port = None
    _internal_network_cidr = None

    _status_handler = None

    def get_connection(self):
        """
        Gets a connection to the openstack service handled by this object.
        :return:
        """

        return connection.Connection(auth_url=self._auth_url,
                             project_name=self._project_name,
                             username=self._username,
                             password=self._password)

    def __init__(self,
                 # Authentication settings
                 auth_url,
                 project_name,
                 username,
                 password,

                 # Instances
                 workers,
                 sniffer_instance_name,
                 sniffer_image_name,
                 sniffer_flavor,
                 sniffer_security_group,
                 guest_image_name,
                 guest_flavor,
                 guest_security_group,

                 # Network
                 public_network_name,
                 external_router_name,
                 internal_network_name,
                 intranet_subnetwork_name,
                 sniffer_port,
                 external_hc_ip,
                 external_hc_port,
                 internal_network_cidr):
        """
        Constructor.
        :return:
        """
        super(OpenStackManager,self).__init__()

        self._auth_url = auth_url
        self._project_name = project_name
        self._username = username
        self._password = password

        self._sniffer_name = sniffer_instance_name
        self._sniffer_flavor = sniffer_flavor
        self._sniffer_image = sniffer_image_name
        self._sniffer_port = sniffer_port
        self._sniffer_security_group = sniffer_security_group

        self._public_network = public_network_name
        self._external_router_name = external_router_name
        self._internal_network = internal_network_name
        self._intranet_subnetwork = intranet_subnetwork_name

        self._guest_flavor = guest_flavor
        self._guest_image = guest_image_name
        self._guest_security_group = guest_security_group

        self._n_workers = workers

        self._external_hc_ip = None if external_hc_ip == "" else external_hc_ip
        self._external_hc_port = external_hc_port

        self._internal_network_cidr=internal_network_cidr


    def set_machine_status_handler(self, handler):
        """
        Registers a status handler which should be notified by the manager every time a machine managed by this handler
        changes its status.
        :return:
        """
        self._status_handler = handler

    def _create_or_update_sniffer(self):
        """
        This method checks whether the sniffer is up to date (in terms of configuration). In case it is not,
        it will be deleted and configured from scratch, in accordance with the current configuration.
        This method also makes sure the sniffer is in the shutoff state, ready to be powered on.
        :return:
        """

        # Rebild the sniffer even if it was already available
        logging.info("Initializing sniffer...")
        sniffer = None
        conn = self.get_connection()
        sniffer = conn.compute.find_server(self._sniffer_name)
        if sniffer is not None:
            logging.warn("Sniffer %s was found, it will be deleted." % sniffer.name)
            sniffer = conn.compute.get_server(sniffer)
            conn.compute.delete_server(sniffer)
            conn.compute.wait_for_delete(sniffer)
            sniffer = None

        logging.info("Creating sniffer from scratch...")
        sniffer = conn.compute.create_server(name=self._sniffer_name,
                                             image_id=self._sniffer_image_id,
                                             flavor_id=self._sniffer_flavor_id,
                                             networks=[{'uuid': self._public_network_id}], #, {'uuid': self._internal_network_id}],
                                             security_groups=[{'name': self._sniffer_security_group}])

        logging.debug("Waiting for sniffer allocation...")
        conn.compute.wait_for_server(sniffer)
        logging.info("Sniffer created.")

        # Remove the previously created interface
        prev_int = list(conn.compute.server_interfaces(sniffer))[0]
        conn.compute.delete_server_interface(prev_int, server=sniffer)

        int_port = conn.network.find_port(INTERNAL_NETWORK_PORT_NAME)
        ext_port = conn.network.find_port(EXTERNAL_NETWORK_PORT_NAME)

        # Now add and interface to the private network of the sniffer
        external_if = conn.compute.create_server_interface(sniffer, port_id=ext_port.id)
        internal_if = conn.compute.create_server_interface(sniffer, port_id=int_port.id)
        sniffer = conn.compute.update_server(sniffer)

        # Now update the internal network and design the sniffer to be the gateway of the network
        subnet = conn.network.find_subnet(self._intranet_subnetwork)
        if subnet is None:
            raise Exception("Subnet was not initialized correctly. Cannot find it.")

        subnet.gateway_ip = int_port.fixed_ips[0].get('ip_address')
        subnet = conn.network.update_subnet(subnet)

        # Now add the floating ip to the sniffer
        unused_floating_ip = None
        logging.debug('Checking for unused Floating IP to be assigned to sniffer %s' % sniffer.name)
        for floating_ip in conn.network.ips():
            if not floating_ip.fixed_ip_address:
                unused_floating_ip = floating_ip
                break
        if not unused_floating_ip:
            logging.warn('No free unused Floating IPs. Allocating new Floating IP...')
            unused_floating_ip = conn.network.create_ip(floating_network_id=self._public_network_id)
            unused_floating_ip = conn.network.get_ip(unused_floating_ip)
            logging.info("Allocated floating ip %s" % unused_floating_ip)

        conn.compute.add_floating_ip_to_server(sniffer, unused_floating_ip.floating_ip_address)
        self._sniffer_floating_ip = unused_floating_ip.floating_ip_address

        # Make sure sniffer is powered off
        conn.compute.stop_server(sniffer)
        conn.compute.wait_for_status(sniffer, "SHUTOFF")
        logging.info("Sniffer has been prepared.")

    def get_internal_network_start_ip(self):
        """
        Return the second host available in the CIDR
        :return: 
        """
        cidr = ipaddress.ip_network(unicode(self._internal_network_cidr))
        return str(list(cidr.hosts())[1])

    def get_internal_network_end_ip(self):
        """
        Return the last host available in the CIDR
        :return: 
        """
        cidr = ipaddress.ip_network(unicode(self._internal_network_cidr))
        return str(list(cidr.hosts())[-1])

    def get_internal_network_gateway_ip(self):
        """
        Return the first HOST available in the CIDR
        :return: 
        """
        cidr = ipaddress.ip_network(unicode(self._internal_network_cidr))
        return str(list(cidr.hosts())[0])

    def _validate_conf(self):
        """
        Verifies the existence of provided regarding img, falvors and networks and retrieves relative IDs to be used
        with the API. In case network is not configured, it tries to set it up.
        :return:
        """
        conn = self.get_connection()

        # Sniffer Flavor
        flv = conn.compute.find_flavor(self._sniffer_flavor)
        if flv is None:
            raise Exception("Could not find any sniffer flavor matching name or id %s." % self._sniffer_flavor)
        self._sniffer_flavor_id = flv.id

        # Sniffer Image
        img = conn.compute.find_image(self._sniffer_image)
        if img is None:
            raise Exception("Could not find any image matching name or id %s." % self._sniffer_image)
        self._sniffer_image_id = img.id

        # Guest Flavor
        flv2 = conn.compute.find_flavor(self._guest_flavor)
        if flv2 is None:
            raise Exception("Could not find any guest flavor matching name or id %s." % self._guest_flavor)
        self._guest_flavor_id=flv2.id

        # Guest Image
        img2=conn.compute.find_image(self._guest_image)
        if img2 is None:
            raise Exception("Could not find any image matching name or id %s." % self._guest_image)
        self._guest_image_id = img2.id

        # Networking. Make sure public and internal network do exist.
        pub_network = conn.network.find_network(self._public_network)
        if pub_network is None:
            # If we cannot find this, raise an error. This must be configured by user.
            raise Exception("Cannot find any network named %s. Note that The user is in charge"
                            " of configuring the external network to be used by the sniffer."
                            % self._public_network)
        self._public_network_id = pub_network.id

        internal_net = conn.network.find_network(self._internal_network)
        if internal_net is None:
            logging.warn("Cannot find any network named %s. Trying to allocate it right now." % self._internal_network)
            net = conn.network.create_network(name=self._internal_network)
            self._internal_network_id = net.id
        else:
            self._internal_network_id = internal_net.id

        # At this stage, assume network is OK. Go ahead with subnet configuration.
        subnet = conn.network.find_subnet(self._intranet_subnetwork)
        if subnet is None:
            logging.warn("Cannot find any network named %s. Trying to allocate it right now." % self._intranet_subnetwork)

            subnet = conn.network.create_subnet(
                name=self._intranet_subnetwork,
                network_id=self._internal_network_id,
                enable_dhcp=True,
                ip_version='4',
                cidr=self._internal_network_cidr,
                allocation_pools=[{
                    'start': self.get_internal_network_start_ip(),
                    'end': self.get_internal_network_end_ip()}],
                gateway_ip=self.get_internal_network_gateway_ip(),
                dns_nameservers=[self.get_internal_network_gateway_ip()])

        self._intranet_subnetwork_id = subnet.id

        # Security groups.
        sniffer_sec_group = conn.network.find_security_group(self._sniffer_security_group)
        if sniffer_sec_group is None:
            logging.warn("Cannot find any security group named %s. Trying to allocate it right now." % self._sniffer_security_group)
            sec_group = conn.network.create_security_group(name=self._sniffer_security_group)
            # Setup rules for sniffer.
            # Outbound traffic is automatically granted to the VM. Just allow incoming traffic for sniffer's webservice
            # For now just open all ports on sniffer. We'll need to secure this later on
            # TODO
            conn.network.create_security_group_rule(
                    security_group_id=sec_group.id,
                    direction='ingress',
                    remote_ip_prefix=None,  # Any IP
                    protocol=None,  # Any protocol
                    port_range_max=None,  # Any port
                    port_range_min=None,  # Any port
                    ethertype='IPv4'        # For now, just IPv4
                    )

        guest_sec_group = conn.network.find_security_group(self._guest_security_group)
        if guest_sec_group is None:
            logging.warn(
                "Cannot find any security group named %s. Trying to allocate it right now." % self._guest_security_group)
            sec_group = conn.network.create_security_group(name=self._guest_security_group)
            # Setup rules for guests.
            # Outbound traffic is already granted. Just add rules for incoming traffic from the same lan
            conn.network.create_security_group_rule(
                security_group_id=sec_group.id,
                direction='ingress',
                remote_ip_prefix=self._internal_network_cidr,  # Any IP from internal network
                protocol=None,  # Any protocol
                port_range_max=None,  # Any port
                port_range_min=None,  # Any port
                ethertype='IPv4'  # For now, just IPv4
            )

        # Ports
        # INTPORT: Port for sniffer, attached to the internal network
        int_port = conn.network.find_port(INTERNAL_NETWORK_PORT_NAME)
        if int_port is not None:
            # Delete it and create it from scratch
            logging.info("Found any internal port named %s. Recreating it to match new conf" % INTERNAL_NETWORK_PORT_NAME)
            conn.network.delete_port(int_port)

        int_port = conn.network.create_port(
            name=INTERNAL_NETWORK_PORT_NAME,
            network_id=self._internal_network_id,
            fixed_ips=[{'subnet_id': subnet.id, 'ip_address': self.get_internal_network_gateway_ip()}],
            security_group_ids=[sniffer_sec_group.id])

        # Now allow this port to "spoof" its address.
        int_port.allowed_address_pairs=[{'mac_address': int_port.mac_address,'ip_address':'0.0.0.0/0'}]
        int_port = conn.network.update_port(int_port)

        # EXTPORT: Port for sniffer, attached to the external network
        ext_port = conn.network.find_port(EXTERNAL_NETWORK_PORT_NAME)
        if ext_port is not None:
            # Delete it and create it from scratch
            logging.info(
                "Found any internal port named %s. Recreating it to match new conf" % EXTERNAL_NETWORK_PORT_NAME)
            conn.network.delete_port(ext_port)

        ext_port = conn.network.create_port(
            name=EXTERNAL_NETWORK_PORT_NAME,
            network_id=self._public_network_id,
            security_group_ids=[sniffer_sec_group.id])

        # Allow traffic from ext port to internal port
        ext_port.allowed_address_pairs = [{'mac_address': ext_port.mac_address, 'ip_address': self._internal_network_cidr}]
        ext_port = conn.network.update_port(ext_port)

        # Finally, add routing for the sniffer
        router = conn.network.find_router(self._external_router_name)
        if router is None:
            raise Exception("Cannot find router named %s" % self._external_router_name)
        # TODO: this will "erase" the previous configuration of this router, which may be unwanted. Should we either create a new rule and add it if missing?
        router.routes = [{'nexthop':ext_port.fixed_ips[0]['ip_address'],'destination':self._internal_network_cidr}]
        router = conn.network.update_router(router)

        # That's it for now.

    def _start_sniffer(self, wait_for_state_running=True):
        conn = self.get_connection()
        sniffer = conn.compute.find_server(self._sniffer_name)
        conn.compute.start_server(sniffer)
        conn.compute.wait_for_status(sniffer, "ACTIVE")

    def publish_agents(self, agents_dict):
        """
        Publishes available agents on the sniffer
        :param agents_dict: 
        :return: 
        """
        count = 0
        for osver, agent_path in agents_dict.iteritems():
            platform, version, arch = osver
            self._netmon.post_agent(platform, version, arch, agent_path)
            count += 1
        if count == 0:
            logging.warn("No agent was found. for this manager. Be sure you've placed agents in the tight folder.")

    def publish_hc(self):
        """
        Tells to the sniffer what IP:Port should be used by agents in order to contact the HostController.
        :return: 
        """

        # Did the user specify which are the external address:port to be used? If no, try to guess that info. We won't
        # be able to detect NAT, though.

        if self._external_hc_ip is None:
            raise Exception("Cannot determine which address to bind to. Specify a valid os_external_hc_ip value to overcome this problem.")
        else:
            logging.info("Publishing %s:%d as HC address for the sniffer." % (self._external_hc_ip, self._external_hc_port))

        self._netmon.post_hc(self._external_hc_ip, self._external_hc_port)

    def prepare(self):
        """
        Check if we have enough VM to be used and create new ones if needed. Then check the sniffer is available and
        create/start if needed.
        :return:
        """
        logging.info("Preparing Openstack manager...")

        # Check the validity of user-provided configuration. This method will also lookup image and flavor ids,
        # so that we might use them quickly.
        self._validate_conf()

        # Create or Update sniffer configuration.
        self._create_or_update_sniffer()

        # Now start the sniffer again
        # Wait for the sniffer to come up.
        self._start_sniffer(True)
        logging.info("Waiting for sniffer to come up...")

        tries = 0
        success = False
        sniffer_url = "%s:%d" % (self._sniffer_floating_ip, self._sniffer_port) if self._sniffer_floating_ip.lower().startswith("http://") else ("http://%s:%d" % (self._sniffer_floating_ip, self._sniffer_port))

        while tries < 10:
            try:
                response = urllib2.urlopen(sniffer_url)
                if response.getcode() == 200 or response.getcode() == 204:
                    success = True
                    break
            except:
                # Wait some time and retry
                time.sleep(3)

        if not success:
            raise Exception("Cannot connect to sniffer. Check network cofiguration is ok.")

        logging.info("Sniffer seems OK.")
        self._netmon = BareNetMon(sniffer_url)

        # Time to register to the sniffer
        self.publish_hc()

        logging.info("Verifying workers...")
        available = self.list_guests()
        if self._status_handler is not None:
            for m in available:
                # TODO workerstatus might not be IDLE at this stage. It depends on the machine state.
                self._status_handler.register_worker(m.get_mac(), WorkerStatus.IDLE)

        self.stop_batch(available)

        # Stop all the machines
        for v in available:
            self.revert_guest(v)

        logging.info("Requesting %d vms, available %d" % (self._n_workers, len(available)))

        # TODO: Verify guest configuration. It must be consistent for each guest.

        if len(available) < self._n_workers:
            logging.info("Creating %d VMs" % (self._n_workers-len(available)))
            self.create_batch(self._n_workers-len(available))

    def create_batch(self, number):
        """
        Multithreaded shortcut for multiple VM creation
        :param number:
        :return:
        """
        threads = []
        for i in range(0, number):
            t = Thread(target=self.create_guest)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def create_guest(self):
        """
        Creates a Virtual Machine with a differencing disk based on an immutable image.
        The machine is not started.
        :return: IMachine
        """

        conn = self.get_connection()

        name = str(uuid4())
        logging.info("Creating VM %s" % name)

        srv = conn.compute.create_server(name=name,
                                             image_id=self._guest_image_id,
                                             flavor_id=self._guest_flavor_id,
                                             networks=[{'uuid': self._internal_network_id}],
                                             security_groups=[{'name': self._guest_security_group}],
                                             metadata={"IS_ANALYZER":"true"})
        logging.debug("Waiting for vm %s ..." % name)
        conn.compute.wait_for_server(srv, wait=180)
        mac = MacAddress.MacAddress(srv.addresses[self._internal_network][0]['OS-EXT-IPS-MAC:mac_addr'])

        if self._status_handler is not None:
            self._status_handler.register_worker(mac, WorkerStatus.IDLE)

        logging.info("Machine %s created correctly." % name)

        return OSMachine(manager=self,mac=mac, id=srv.id)

    def get_machine_state(self,
                          guest  # type: IGuest
                          ):
        if not isinstance(guest, OSMachine):
            raise Exception("Machine must be a reference to OSMachine.")

        with guest.lock:
            conn = self.get_connection()
            m = conn.compute.get_server(guest.get_id())
            state = m.status

            # Now return a status that is mapped into the machine state.
            s = mapped_states.get(str(state))
            if s is None:
                return MachineState.unknown
            else:
                return s

    def start_network_sniffing(self,
                               guest  # type: IGuest
                               ):

        mac = MacAddress.MacAddress(guest.get_mac())
        logging.debug("Staring sniffer/network monitor for mac %s" % mac)
        try:
            self._netmon.start(mac=mac)
        except SnifferAlreadyRunningException as ex:
            logging.warn("Sniffer for mac %s was already running. I will stop it and start it again." % mac)
            self._netmon.stop(mac=mac)
            self._netmon.start(mac=mac)

    def stop_network_sniffing(self,
                               guest  # type: IGuest
                               ):

        # Stop the sniffer, if present
        mac = MacAddress.MacAddress(guest.get_mac())
        id = guest.get_id()
        logging.debug("Stopping associated network sniffers to %s (traffic for/from %s)" % (id, mac))
        status = self._netmon.query_status(mac)
        if status is None:
            logging.debug("There is no sniffer for mac %s" % mac)
        else:
            logging.debug("Sniffer status is %s" % status)
            if status == "running":
                logging.debug("Stopping sniffer for mac %s" % mac)
                self._netmon.stop(mac)

    def start_guest(self,
              guest  # type: IGuest
            ):

        if not isinstance(guest, OSMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with guest.lock:
            # Retrieve the machine os ID
            id = guest.get_id()

            logging.debug("Starting machine %s" % id)

            m = None
            conn = self.get_connection()
            server = conn.compute.get_server(id)
            conn.compute.start_server(id)
            conn.compute.wait_for_status(server, "ACTIVE")
            if self._status_handler is not None:
                self._status_handler.notify_machine_status(machine_mac=guest.get_mac(),
                                                           worker_status=WorkerStatus.BOOTING)

    def revert_guest(self,
               guest  # type: IGuest
               ):
        """
        Reverts the VM state by rebuild the instance from a fresh image.
        :param machine: OSMachine
        :return: void
        """

        if not isinstance(guest, OSMachine):
            raise Exception("Machine must be a reference to OSMachine.")

        with guest.lock:
            logging.debug("Reverting machine %s" % guest.get_id())
            conn = self.get_connection()
            server = conn.compute.get_server(guest.get_id())
            conn.compute.rebuild_server(server, server.name, "", image=server.image.get('id'))
            if self._status_handler is not None:
                self._status_handler.notify_machine_status(machine_mac=guest.get_mac(),
                                                           worker_status=WorkerStatus.REVERTING)
            conn.compute.wait_for_status(server, "SHUTOFF")
            if self._status_handler is not None:
                self._status_handler.notify_machine_status(machine_mac=guest.get_mac(),
                                                           worker_status=WorkerStatus.IDLE)
            logging.debug("Machine %s reverted" % guest.get_id())

    def stop_batch(self,
                   machines  # type: [IGuest]
                   ):
        threads = []
        for m in machines:
            t = Thread(target=self.stop_guest, args=(m,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def stop_guest(self,
                   machine  # type: IGuest
                   ):
        if not isinstance(machine, OSMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with machine.lock:
            conn = self.get_connection()
            logging.debug("Stopping machine %s" % machine.get_id())
            server = conn.compute.get_server(machine.get_id())
            if server.vm_state == 'paused':
                conn.compute.unpause_server(server)
                conn.compute.wait_for_status(server, "ACTIVE")
            if server.status != "SHUTOFF":
                conn.compute.stop_server(server.id)
                conn.compute.wait_for_status(server, "SHUTOFF")
                if self._status_handler is not None:
                    self._status_handler.notify_machine_status(machine_mac=machine.get_mac(),
                                                               worker_status=WorkerStatus.IDLE)

    def delete_guest(self,
                     guest  # type: IGuest
                     ):
        if not isinstance(guest, OSMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        conn = self.get_connection()
        server = conn.compute.get_server(guest.get_id())

        # Check if the machine is already down. If not, throw an exception
        if self.get_machine_state(guest) not in (MachineState.stopped, MachineState.error):
            raise Exception("Machine id %s cannot be stopped because it is not in a valid state." % guest.get_id())

        # Otherwise remove it
        conn.compute.delete_server(guest.get_id())
        conn.compute.wait_for_delete(server)

    def get_netlog(self,
                   machine,  # type: OSMachine
                   directory  # type:str
                   ):

        # This method may take FOREVER due to the great amount of data to be downloaded and analyzed.
        # So we hold the lock just for the strict needed time.
        mac = None

        if not isinstance(machine, OSMachine):
            raise Exception("Machine must be a reference to OSMachine.")

        with machine.lock:
            conn = self.get_connection()

            m = None
            try:
                m = conn.compute.get_server(machine.get_id())
            except:
                raise Exception("Cannot find machine %s" + machine.get_id())

            mac = MacAddress.MacAddress(str(m.addresses[self._internal_network][0].get('OS-EXT-IPS-MAC:mac_addr')))

            pcap_file = os.path.join(directory, NETLOG_NAME)
            self._netmon.collect(mac, pcap_file)

            cap_file_https = os.path.join(directory, HTTPS_NETLOG_NAME)
            self._netmon.collect_https(mac, cap_file_https)

            return pcap_file, cap_file_https

    def get_name(self):
        return "Openstack-"+self._auth_url

    def list_guests(self):
        """
        Returns the list of all Machines handled by this manager.
        A machine belongs to the list of handled if it contains a metadata tag IS_ANALYZER=TRUE.
        This method returns all the machines that share that tag.
        # conn.compute.set_server_metadata(server, IS_INSTALLER="True")
        :return: IMachine[]
        """
        res = []

        conn = self.get_connection()
        for s in conn.compute.servers():
            metadata = conn.compute.get_server_metadata(s).metadata.get("IS_ANALYZER")
            if metadata is not None and metadata.lower() == "true":
                logging.debug("Found machine %s with IS_INSTALLER flag." % s.id)
                res.append(OSMachine(self,s.addresses.values()[0][0].get("OS-EXT-IPS-MAC:mac_addr"),s.id))

        return res  # type: list<OSMachine>

    def get_guest_by_mac(self,
                   mac  # type: MacAddress
                   ):
        """
        If the given mac matches any VM handled by this manager, an instance
        of the VM is returned. Otherwise None is returned.
        :return:
        """
        mac = MacAddress.MacAddress(mac)
        vms = self.list_guests()
        for v in vms:
            if v.get_mac() == mac:
                return v  # type: OSMachine

        return None


class OSMachine(IGuest):
    _manager = None
    # Private ID used internally for vbox manager
    _id = None
    _mac = None
    lock = None

    def __init__(self,
                 manager,  # type:IGuestManager
                 mac,  # type:MacAddress
                 id  # type:str
                 ):
        if not isinstance(manager, OpenStackManager):
            raise Exception("VBoxMachine requires VBoxManger to be specified as manager")

        self._manager = manager
        self._mac = MacAddress.MacAddress(mac)
        self._id = str(id)

        self.lock = RLock()

    def get_mac(self):
        return self._mac

    def get_manager(self):
        return self._manager

    def get_id(self):
        return self._id
