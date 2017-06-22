import logging
import threading
import time
import urllib2
import uuid
import os
from os import path
from HostController.miscellaneus.debug import LogLock
from vboxapi import VirtualBoxManager, VirtualBox_constants
from HostController.settings import CFG
from HostController.miscellaneus import MacAddress
from HostController.logic.WorkerStatus import WorkerStatus
from machine_manager import IGuestManager, IGuest, MachineState, NETLOG_NAME, HTTPS_NETLOG_NAME
from netmons import BareNetMon, SnifferAlreadyRunningException

__author__ = 'Alberto Geniola'

# Default Maximum timeout in ms to wait for a VM operation to complete.
DEFAULT_OP_TIMEOUT = 10000

mapped_states = {
    "PoweredOff": MachineState.stopped,

    "Running": MachineState.running,
    "FirstOnline": MachineState.running,
    "LastOnline": MachineState.running,

    "Aborted": MachineState.error,
    "Stuck": MachineState.error,

    "Saving": MachineState.busy,
    "Stopping": MachineState.busy,
    "Starting": MachineState.busy,
    "Restoring": MachineState.busy,
    "Snapshotting": MachineState.busy,
    "OnlineSnapshotting": MachineState.busy,
    "LineSnapshotting": MachineState.busy,
    "Teleporting": MachineState.busy,
    "DeletingSnapshotOnline": MachineState.busy,
    "SettingUp": MachineState.busy,

    "Saved": MachineState.unknown,
    "Paused": MachineState.unknown,
}


class VBoxManager(IGuestManager):
    # We need to synchronize access to this manager because many different connections/threads may require
    # VM operations. In our case, we only support one operation at a time. In the future, this architecture may
    # change.
    _root_clone = None
    _conf = None
    _vm_group = None
    _base_disk_location = None
    _diff_disk_dir = None
    _vbox_url = None
    _netmon = None

    _external_hc_ip = None
    _external_hc_port = None

    _status_handler = None

    class ManagedMgr:
        def __init__(self, vbox_user=None, vbox_pass=None, vbox_url=None, external_hc_ip=None, external_hc_port=None):
            self._vbox_url = vbox_url
            self._vbox_user = vbox_user
            self._vbox_pass = vbox_pass
            self.mgr = None
            self.vbox = None

            if self._vbox_url:
                self.mgr = VirtualBoxManager("WEBSERVICE", {
                    'url': self._vbox_url,
                    'user': self._vbox_user,
                    'password': self._vbox_pass
                })
            else:
                if os.name == 'nt':
                    import pythoncom
                    pythoncom.CoInitialize()
                self.mgr = VirtualBoxManager(None, None)

            try:
                self.vbox = self.mgr.getVirtualBox()
            except:
                logging.exception("Cannot connect to VBOX. Check service is installed and running, and verify the user "
                                "has valid credentials to access that service.")
                raise

            self._external_hc_ip = external_hc_ip
            self._external_hc_port = external_hc_port

    def getMgr(self):
        return self.ManagedMgr(vbox_url=self._vbox_url, vbox_user=CFG.vbox_user, vbox_pass=CFG.vbox_password)

    def __init__(self):
        """
        Constructor. Initialize vbox object and check we have all we need to use the vbox manager. This method will
        look for base disk and check if that is IMMUTABLE. In case it is not, we will make it immutable right here.
        We also setup the network sniffer handled by this manager, i.e. BareNetmon.
        :return:
        """
        super(VBoxManager,self).__init__()
        self._vbox_url = CFG.vbox_url

        self._conf = CFG.vbox_default_vm_cfg
        self._vm_group = CFG.vbox_default_group

        ctx = self.getMgr()

        if not path.exists(CFG.vbox_base_disk_path):
            raise Exception("Cannot find vbox base disk in %s" % CFG.vbox_base_disk_path)
        else:
            self._base_disk_location = CFG.vbox_base_disk_path

        if not path.exists(CFG.vbox_diff_disk_dir):
            raise Exception("Cannot find vbox base disk in %s" % CFG.vbox_diff_disk_dir)
        else:
            self._diff_disk_dir = CFG.vbox_diff_disk_dir

        base_disk = ctx.vbox.openMedium(self._base_disk_location, # location
                                        ctx.mgr.constants.DeviceType_HardDisk, # devtype
                                        ctx.mgr.constants.AccessMode_ReadOnly, # accessmode
                                        False # force new uuid
                                        )

        if base_disk.type != ctx.mgr.constants.MediumType_Immutable:
            logging.warn("Base disk %s was is not immutable. Trying to set it immutable..." % self._base_disk_location)
            base_disk.type = ctx.mgr.constants.MediumType_Immutable
            logging.warn("Base disk is now immutable.")

        if not self._vm_group.startswith('/', 0):
            raise Exception("VMGroup parameter must start with '/'. Example: '/test'.")

        self._netmon = BareNetMon(url=self._derive_netmon_addr())

    def set_machine_status_handler(self, handler):
        self._status_handler = handler

    def _derive_netmon_addr(self):
        """
        Calculates the netmon address according to the current configuration, then returns it.
        :return:
        """
        # At the moment, the only supported topology requires the HostController to be on the same node of Virtualbox.
        # Therefore, access to the sniffer is performed via the HostOnly network interface.

        return "http://%s:%d/" % (CFG.vbox_sniffer_ip, CFG.vbox_sniffer_port)

    def _create_or_update_sniffer(self):
        conf = CFG.vbox_sniffer_cfg
        ctx = self.getMgr()

        # Check if the sniffer is present. If so, shut it down and unregister it. We will recreate it from scratch.
        m = None
        try:
            m = ctx.vbox.findMachine(CFG.vbox_sniffer_name)
        except:
            m = None

        if m is not None:
            if m.state in [ctx.mgr.constants.MachineState_Running,ctx.mgr.constants.MachineState_Paused, ctx.mgr.constants.MachineState_Stuck]:
                session = ctx.mgr.getSessionObject(ctx.vbox)
                try:
                    m.lockMachine(session, ctx.mgr.constants.LockType_Shared)
                    progress = session.console.powerDown()
                    progress.waitForCompletion(-1)
                    logging.info("Sniffer stopped")
                    time.sleep(1)  # BAD, but really had no other choice.
                except:
                    logging.exception("Error when stopping Sniffer")
                    raise
                finally:
                    if session.state == ctx.mgr.constants.SessionState_Locked:
                        session.unlockMachine()

            media = m.unregister(ctx.mgr.constants.CleanupMode_Full)
            # Delete everything but do not delete detached media. So we pass an empty media array
            m.deleteConfig([])

        # Create it again
        name = str(CFG.vbox_sniffer_name)
        logging.info("Creating sniffer as %s" % name)

        ostype = 'Linux_64'
        m = ctx.vbox.createMachine('', # Settings file
                                   name, # Machine name
                                   [], # Machine groups
                                   ostype,
                                   'forceOverwrite=1' # Flags
                                   )
        ctx.vbox.registerMachine(m)
        logging.debug("Sniffer VM created and registered.")

        logging.debug("Configuring external network interface for sniffer...")

        # Set up created machine
        session = ctx.mgr.getSessionObject(ctx.vbox)
        try:
            m.lockMachine(session, ctx.mgr.constants.LockType_Write)
            mutable = session.machine

            # CPU, ram, vram
            logging.debug("Configuring VM %s" % name)
            mutable.CPUCount = int(conf['cpu_count'])
            mutable.memorySize = int(conf['memory_size'])
            mutable.VRAMSize = int(conf['vram_size'])
            mutable.accelerate3DEnabled = str(conf['accelerate_3d_enabled'])
            mutable.accelerate2DVideoEnabled = str(conf['accelerate_2d_video_enabled'])

            # Configure INTERNET access on ETH0
            eth0 = mutable.getNetworkAdapter(0)
            eth0.enabled = 1
            eth0.adapterType = ctx.mgr.constants.all_values('NetworkAdapterType')[str(conf['adapter_internet_type'])]
            eth0.attachmentType = ctx.mgr.constants.NetworkAttachmentType_NATNetwork
            eth0.NATNetwork = CFG.vbox_wan_nat_name

            # Configure INTRANET access on ETH1
            eth1 = mutable.getNetworkAdapter(1)
            eth1.enabled = 1
            eth1.adapterType = ctx.mgr.constants.all_values('NetworkAdapterType')[str(conf['adapter_intranet_type'])]
            eth1.attachmentType = ctx.mgr.constants.NetworkAttachmentType_Internal
            eth1.internalNetwork = CFG.vbox_intranet_network_name

            # Configure HOSTONLY access on ETH2
            eth2 = mutable.getNetworkAdapter(2)
            eth2.enabled = 1
            eth2.adapterType = ctx.mgr.constants.all_values('NetworkAdapterType')[str(conf['adapter_hostonly_type'])]
            eth2.attachmentType = ctx.mgr.constants.NetworkAttachmentType_HostOnly
            eth2.hostOnlyInterface = CFG.vbox_host_only_interface_name

            base = ctx.vbox.openMedium(CFG.sniffer_base_disk,
                                       ctx.mgr.constants.DeviceType_HardDisk,
                                       ctx.mgr.constants.AccessMode_ReadOnly,
                                       False)

            sata_controller = mutable.addStorageController('sata_disk',
                                                           ctx.mgr.constants.StorageBus_SATA)
            # Limit the maximum number of SATA ports for this controller in order to reduce boot time
            sata_controller.portCount = 1
            mutable.attachDevice('sata_disk', # Name
                                 0,  # Controller port
                                 0,  # Device port
                                 ctx.mgr.constants.DeviceType_HardDisk,
                                 base)

            mutable.BIOSSettings.IOAPICEnabled = True

            logging.debug("Saving settings for VM %s" % name)
            mutable.saveSettings()

            logging.info("Machine %s successfully created" % name)

        except Exception as e:
            logging.exception("Error occurred during vm configuration %s" % name)

            # Exception occurred. Discard any change and raise again.
            try:
                if session.state == ctx.mgr.constants.SessionState_Locked:
                    session.unlockMachine()
            except Exception:  # varoius errors (xpcom.Exception)
                pass
            media = m.unregister(ctx.mgr.constants.CleanupMode_DetachAllReturnHardDisksOnly)

            # Delete attached mediums
            for medium in media:
                medium.deleteStorage()

            # No matter if you can recover, raise again.
            raise
        finally:
            try:
                if session.state == ctx.mgr.constants.SessionState_Locked:
                    session.unlockMachine()
            except Exception:  # varoius errors (xpcom.Exception)
                pass

    def _check_network_conf(self):
        """
        Verifies if the virtualbox setup is consistent with the supported network topology. If possible, it tries to
        fix it directly over here.
        :return:
        """

        ctx = self.getMgr()
        # HostOnly adapter: must be available, matching the name vbox_host_only_interface_name and should acquire
        # vbox_host_only_interface_ip over mask vbox_host_only_interface_mask.
        ho_net = None
        host_only_networks = ctx.vbox.host.findHostNetworkInterfacesOfType(ctx.mgr.constants.HostNetworkInterfaceType_HostOnly)

        # Check if the user has specified any HostOnly network to be used as adapter
        logging.info("Trying to use %s as host only adapter." % CFG.vbox_host_only_interface_name)
        for net in host_only_networks:
            if net.name == CFG.vbox_host_only_interface_name:
                ho_net = net
                break

        if ho_net is None:
            raise Exception("Unable to identify and use network interface %s" % CFG.vbox_host_only_interface_name)

        # Configure the HostOnly adapter to acquire Static IP address
        ho_net.enableStaticIPConfig(CFG.vbox_host_only_interface_ip, CFG.vbox_host_only_interface_mask)

        # NatNetwork: check if network specified in vbox_wan_nat_name is available. If not, create a NAT network with
        # that name. Then configure with the CIDR provided by vbox_wan_nat_cidr.
        nat_net = None
        try:
            nat_net = ctx.vbox.findNATNetworkByName(CFG.vbox_wan_nat_name)
        except:
            logging.warn("Could not find nat network <<%s>>. Trying to create it..." % CFG.vbox_wan_nat_name)
            nat_net = ctx.vbox.createNATNetwork(CFG.vbox_wan_nat_name)
            logging.info("Created network <<%s>>." % CFG.vbox_wan_nat_name)

        nat_net.needDhcpServer = 0
        nat_net.enabled = 1
        nat_net.network = CFG.vbox_wan_nat_cidr

    def publish_hc(self):
        """
        Tells to the sniffer what IP:Port should be used by agents in order to contact the HostController.
        :return: 
        """

        # Did the user specify which are the external address:port to be used? If no, try to guess that info. We won't
        # be able to detect NAT, though.
        port = None
        if self._external_hc_port is None:
            port = CFG.bind_host_port

        ip = None
        if self._external_hc_ip is None:
            # Try to get it by using the OS default routing table. This is a trick!
            s = None
            try:
                import socket
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                # The following won't actually connect, but will query the OS routing table to find the source IP
                # that we are looking for.
                s.connect((CFG.vbox_sniffer_ip, CFG.vbox_sniffer_port))
                ip = s.getsockname()[0]
            except:
                # We failed to get it. This might be a serius problem. Just use the one we have used to bind.
                ip = CFG.bind_host_address
            finally:
                logging.warn("No HostController IP has been specified for the sniffer. Using %s:%d" % (ip, port))
                if s is not None:
                    s.close()
        else:
            logging.info("Publishing %s:%d as HC address for the sniffer." % (ip, port))

        self._external_hc_ip = ip
        self._external_hc_port = port

        self._netmon.post_hc(self._external_hc_ip, self._external_hc_port)

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

    def prepare(self):
        """
        Check if we have enough VM to be used and create new ones if needed. Then check the sniffer is available and
        create/start if needed.
        :return:
        """
        logging.info("Preparing VBox manager...")
        ctx = self.getMgr()

        logging.info("Verifying network topology...")
        self._check_network_conf()

        # Now create/update the sniffer again so we are sure its status will be consistent with current settings.
        logging.info("Verifying sniffer state...")
        self._create_or_update_sniffer()

        m = ctx.vbox.findMachine(CFG.vbox_sniffer_name)

        # Now start the sniffer again
        logging.info("Starting up sniffer...")
        session = ctx.mgr.getSessionObject(ctx.vbox)
        try:
            p = m.launchVMProcess(session, # Session
                                  'headless', # name
                                  '' # environment
                                 )
            p.waitForCompletion(DEFAULT_OP_TIMEOUT)
        except:
            logging.exception("Cannot start sniffer")
            raise
        finally:
            if session.state == ctx.mgr.constants.SessionState_Locked:
                session.unlockMachine()

        # Wait for the sniffer to come up.
        logging.info("Waiting for sniffer to become active...")

        tries = 0
        success = False
        while tries < 10:
            try:
                logging.debug("Attempt %d" % (tries+1))
                response = urllib2.urlopen(self._derive_netmon_addr())
                if response.getcode() == 200 or response.getcode() == 204:
                    success = True
                    break
            except:
                # Wait some time and retry
                time.sleep(3)
                tries += 1

        if not success:
            raise Exception("Cannot connect to sniffer. Please check if the sniffer is running. Also check if the IP:PORT provided for contacting the sniffer are consistent with the topology choosen. Please also verify the network topology. Finally, if everything was ok, check if the sniffer service is running on the sniffer device.")

        # Time to register to the sniffer
        self.publish_hc()

        logging.info("Verifying workers...")
        available = self.list_guests()
        if self._status_handler is not None:
            for m in available:
                # TODO workerstatus might not be IDLE at this stage. It depends on the machine state.
                self._status_handler.register_worker(m.get_mac(), WorkerStatus.IDLE)

        # Stop all the machines
        for v in available:
            self.stop_network_sniffing(v)
            self.stop_guest(v)

        logging.info("Requesting %d vms, available %d" % (CFG.vbox_workers, len(available)))

        if len(available) < CFG.vbox_workers:
            logging.info("Creating %d VMs" % (CFG.vbox_workers-len(available)))
            self.create_batch(CFG.vbox_workers-len(available))

        # If any VM was running, we force them off
        logging.info("Stopping vms...")
        self.stop_batch(self.list_guests())

    def create_batch(self, number):
        """
        Multithreaded shortcut for multiple VM creation
        :param number:
        :return:
        """
        threads = []
        for i in range(0, number):
            t = threading.Thread(target=self.create_guest)
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

        ctx = self.getMgr()

        name = str(uuid.uuid4())
        diff_path = path.join(self._diff_disk_dir, name + '.vmdk')

        logging.info("Creating VM %s" % name)

        # Create and register a new machine
        # TODO parametrize ostype?
        ostype = 'Windows7'

        m = ctx.vbox.createMachine('', # Settings file
                                   name, # Name
                                   [self._vm_group], # groups
                                   ostype, # OS Type
                                   'forceOverwrite=0' # flags
                                   )
        ctx.vbox.registerMachine(m)
        logging.debug("VM %s created and registered" % name)

        # Set up created machine
        session = ctx.mgr.getSessionObject(ctx.vbox)

        try:
            m.lockMachine(session, ctx.mgr.constants.LockType_Write)
            mutable = session.machine

            # CPU, ram, vram
            logging.debug("Configuring VM %s" % name)
            mutable.CPUCount = int(self._conf['cpu_count'])
            mutable.memorySize = int(self._conf['memory_size'])
            mutable.VRAMSize = int(self._conf['vram_size'])
            mutable.accelerate3DEnabled = int(self._conf['accelerate_3d_enabled'])
            mutable.accelerate2DVideoEnabled = int(self._conf['accelerate_2d_video_enabled'])

            eth0 = mutable.getNetworkAdapter(0)
            eth0.adapterType = ctx.mgr.constants.all_values('NetworkAdapterType')[str(self._conf['adapter_intranet_type'])]
            eth0.attachmentType = ctx.mgr.constants.all_values('NetworkAttachmentType')[str(self._conf['adapter_intranet_attachment'])]
            eth0.internalNetwork = CFG.vbox_intranet_network_name
            eth0.enabled = True

            logging.debug("Creating diff VHD for VM %s in %s" % (name, diff_path))
            # Storage: create differential disk and attach it to the new machine.
            # The diff disk will be created with autoreset = True, so next time we don't need to
            # make this operation again.
            base = ctx.vbox.openMedium(self._base_disk_location,
                                       ctx.mgr.constants.DeviceType_HardDisk,
                                       ctx.mgr.constants.AccessMode_ReadOnly,
                                       False)

            medium = ctx.vbox.createMedium('vmdk', # format
                                           diff_path, # location
                                           ctx.mgr.constants.AccessMode_ReadWrite,
                                           ctx.mgr.constants.DeviceType_HardDisk
                                           )

            p = base.createDiffStorage(medium, [ctx.mgr.constants.MediumVariant_Diff])
            p.waitForCompletion(DEFAULT_OP_TIMEOUT)
            medium.autoReset = True
            sata_controller = mutable.addStorageController('sata_disk', ctx.mgr.constants.StorageBus_SATA)
            # Limit the maximum number of SATA ports for this controller in order to reduce boot time
            sata_controller.portCount = 1
            mutable.attachDevice('sata_disk',
                                 0,
                                 0,
                                 ctx.mgr.constants.DeviceType_HardDisk,
                                 medium)

            mutable.BIOSSettings.IOAPICEnabled = True

            logging.debug("Saving settings for VM %s" % name)
            mutable.saveSettings()

            mac = str(m.getNetworkAdapter(0).MACAddress)

            # At this point everything went ok, add the machien to the list of managed machines
            tmp = VBoxMachine(manager=self, mac=mac, id=m.id)

            logging.info("Machine %s successfully created" % name)

            if self._status_handler is not None:
                self._status_handler.register_worker(machine_mac=MacAddress.MacAddress(mac),
                                                           worker_status=WorkerStatus.IDLE)

            return tmp  # type: VBoxMachine

        except Exception as e:
            logging.exception("Error occurred during vm configuration %s" % name)

            # Exception occurred. Discard any change and raise again.
            try:
                if session.state == ctx.mgr.constants.SessionState_Locked:
                    session.unlockMachine()
            except Exception:  # varoius errors (xpcom.Exception)
                pass
            media = m.unregister(ctx.mgr.constants.all_values('CleanupMode')['DetachAllReturnHardDisksOnly'])

            # Delete attached mediums
            for medium in media:
                medium.deleteStorage()

            # No matter if you can recover, raise again.
            raise
        finally:
            try:
                if session.state == ctx.mgr.constants.SessionState_Locked:
                    session.unlockMachine()
            except Exception:  # varoius errors (xpcom.Exception)
                pass

    def get_machine_state(self,
                          guest  # type: VBoxMachine
                          ):
        if not isinstance(guest, VBoxMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with guest.lock:
            """
            d = dict()
            self._getMgr(d)
            mgr = d['mgr']
            vbox = d['vbox']
            """

            # Retrieve the VBox ID
            ctx = self.getMgr()
            m = ctx.vbox.findMachine(guest.get_id())
            state = m.state

            # Now return a status that is mapped into the machine state.
            s = mapped_states.get(str(state))
            if s is None:
                return MachineState.unknown
            else:
                return s

    def start_network_sniffing(self,
                               guest  # type: VBoxMachine
                               ):
        mac = guest.get_mac()
        logging.debug("Staring sniffer/network monitor for mac %s" % mac)
        try:
            self._netmon.start(mac=mac)
        except SnifferAlreadyRunningException as ex:
            logging.warn("Sniffer for mac %s was already running. I will stop it and start it again." % mac)
            self._netmon.stop(mac=mac)
            self._netmon.start(mac=mac)

    def stop_network_sniffing(self,
                               guest  # type: VBoxMachine
                               ):
        # Stop the sniffer, if present
        mac = guest.get_mac()
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
        if not isinstance(guest, VBoxMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with guest.lock:
            """
            d = dict()
            self._getMgr(d)
            mgr = d['mgr']
            vbox = d['vbox']
            """
            ctx = self.getMgr()

            # Retrieve the VBox ID
            id = guest.get_id()

            logging.debug("Starting machine %s" % id)

            m = None
            try:
                m = ctx.vbox.findMachine(id)
            except:
                raise Exception("Cannot find machine " + id)

            # Start a session to begin VM launch
            session = ctx.mgr.getSessionObject(ctx.vbox)
            try:
                logging.debug("Launching machine %s" % id)

                p = m.launchVMProcess(session,
                                      'headless',
                                      '')
                if self._status_handler is not None:
                    self._status_handler.notify_machine_status(machine_mac=guest.get_mac(),
                                                               worker_status=WorkerStatus.BOOTING)

                p.waitForCompletion(DEFAULT_OP_TIMEOUT)
                logging.debug("Machine %s started." % id)

            except:
                logging.exception("Exception occurred when starting vm id %s" % id)
                if self._status_handler is not None:
                    self._status_handler.notify_machine_status(machine_mac=guest.get_mac(),
                                                               worker_status=WorkerStatus.ERROR)
                raise Exception("Cannot launch VM " + id)
            finally:
                try:
                    if session.state == ctx.mgr.constants.SessionState_Locked:
                        session.unlockMachine()
                except Exception:  # varoius errors (xpcom.Exception)
                    pass

    def revert_guest(self,
               guest  # type: IGuest
               ):
        """
        Reverts the VM state. In this implementation this method simply shuts down the VM.
        The image is automatically reverted being an autoreset diff disk of an immutable base disk.
        :param machine: VBoxMachine
        :return: void
        """
        if not isinstance(guest, VBoxMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with guest.lock:
            if self._status_handler is not None:
                self._status_handler.notify_machine_status(machine_mac=guest.get_mac(),
                                                           worker_status=WorkerStatus.REVERTING)
            logging.debug("Reverting machine %s" % guest.get_id())
            self.stop_guest(guest)
            logging.debug("Machine %s reverted" % guest.get_id())

    def stop_batch(self,
                   machines  # type: [VBoxMachine]
                   ):
        threads = []
        for m in machines:
            t = threading.Thread(target=self.stop_guest, args=(m,))
            threads.append(t)
            t.start()
        for t in threads:
            t.join()

    def stop_guest(self,
                   machine  # type: VBoxMachine
                   ):
        if not isinstance(machine, VBoxMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with machine.lock:
            """
            d = dict()
            self._getMgr(d)
            mgr = d['mgr']
            vbox = d['vbox']
            """
            ctx = self.getMgr()
            id = machine.get_id()

            m = None
            try:
                m = ctx.vbox.findMachine(machine.get_id())
            except:
                raise Exception("Cannot find machine %s" % id)

            logging.debug("Stopping machine %s" % id)
            # If machine is running, stop it.
            if m.state != 'PoweredOff':
                session = ctx.mgr.getSessionObject(ctx.vbox)
                m.lockMachine(session, ctx.mgr.constants.LockType_Shared)
                try:
                    # BUG: session object won't be available when using XPCOM on Windows and different architecture
                    # for VirtualBox and Python. If you want to use python x32 and virtualbox x64, we either need
                    # to use the remote service or use same architecture for both.
                    if m.state in [ctx.mgr.constants.MachineState_Running,ctx.mgr.constants.MachineState_Paused, ctx.mgr.constants.MachineState_Stuck]:
                        progress = session.console.powerDown()
                        if self._status_handler is not None:
                            self._status_handler.notify_machine_status(machine_mac=machine.get_mac(),
                                                                       worker_status=WorkerStatus.SHUTTING_DOWN)
                        progress.waitForCompletion(DEFAULT_OP_TIMEOUT)
                        if self._status_handler is not None:
                            self._status_handler.notify_machine_status(machine_mac=machine.get_mac(),
                                                                       worker_status=WorkerStatus.IDLE)
                except:
                    if self._status_handler is not None:
                        self._status_handler.notify_machine_status(machine_mac=machine.get_mac(),
                                                                   worker_status=WorkerStatus.ERROR)
                finally:
                    try:
                        if session.state == ctx.mgr.constants.SessionState_Locked:
                            session.unlockMachine()
                    except Exception:  # varoius errors (xpcom.Exception)
                        pass

    def delete_guest(self,
                     guest  # type: VBoxMachine
                     ):
        ctx = self.getMgr()
        id = guest.get_id()
        m = ctx.vbox.findMachine(id)
        # Check if the machine is already down. If not, throw an exception
        if self.get_machine_state(guest) not in (MachineState.stopped, MachineState.error):
            raise Exception("Machine id %s cannot be stopped because it is not in a valid state." % id)

        # Otherwise remove it
        media = m.unregister(VirtualBox_constants.VirtualBoxReflectionInfo(False).all_values("CleanupMode").get("Full"))
        m.deleteConfig(list(media))

    def get_netlog(self,
                   machine,  # type: VBoxMachine
                   directory  # type:str
                   ):
        # This method may take FOREVER due to the great amount of data to be downloaded and analyzed.
        # So we hold the lock just for the strict needed time.
        mac = None

        if not isinstance(machine, VBoxMachine):
            raise Exception("Machine must be a reference to VBoxMachine.")

        with machine.lock:
            """
            d = dict()
            self._getMgr(d)
            mgr = d['mgr']
            vbox = d['vbox']
            """
            ctx = self.getMgr()
            id = machine.get_id()

            m = None
            try:
                m = ctx.vbox.findMachine(machine.get_id())
            except:
                raise Exception("Cannot find machine " + id)

            mac = MacAddress.MacAddress(m.getNetworkAdapter(0).MACAddress)

            pcap_file = os.path.join(directory, NETLOG_NAME)
            self._netmon.collect(mac, pcap_file)

            cap_file_https = os.path.join(directory, HTTPS_NETLOG_NAME)
            self._netmon.collect_https(mac, cap_file_https)

            return pcap_file, cap_file_https

    def get_name(self):
        return "VirtualBox Manager"

    def list_guests(self):
        """
        Returns the list of all Machines handled by this manager.
        This implementation will return all the VM belonging to the group specified
        by the constructor (vm_group)
        :return: IMachine[]
        """
        res = []
        #with self.lock:
        """
        d = dict()
        self._getMgr(d)
        mgr = d['mgr']
        vbox = d['vbox']
        """
        ctx = self.getMgr()
        vms = ctx.vbox.getMachinesByGroups([self._vm_group])
        for v in vms:
            t = VBoxMachine(manager=self, mac=MacAddress.MacAddress(v.getNetworkAdapter(0).MACAddress), id=v.id)
            res.append(t)

        return res  # type: list[VBoxMachine]

    def get_guest_by_mac(self,
                   mac  # type: MacAddress
                   ):
        """
        If the given mac matches any VM handled by this manager, an instance
        of the VM is returned. Otherwise None is returned.
        :return:
        """
        #with self.lock:
        """
        d = dict()
        self._getMgr(d)
        """
        ctx = self.getMgr()
        # VBox driver only supports mac without any colon or dash
        mmac = str(mac).strip().replace(':', '').replace('-', '')

        vms = ctx.vbox.getMachinesByGroups([self._vm_group])
        for v in vms:
            if v.getNetworkAdapter(0).MACAddress == mmac:
                return VBoxMachine(manager=self, mac=mac, id=v.id)  # type: MacAddress

        return None


class VBoxMachine(IGuest):
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
        if not isinstance(manager, VBoxManager):
            raise Exception("VBoxMachine requires VBoxManger to be specified as manager")

        self._manager = manager
        self._mac = MacAddress.MacAddress(mac)
        self._id = str(id)

        self.lock = LogLock("VboxMachine %s" % self._mac)

    def get_mac(self):
        return self._mac

    def get_manager(self):
        return self._manager

    def get_id(self):
        return self._id
