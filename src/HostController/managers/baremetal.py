__author__ = 'Alberto Geniola'
import logging
import threading
import time
import os
import wmi
import flask
import json
from threading import Thread
from HostController.utils import validate_mac
from jsonschema import validate, ValidationError
from HostController.miscellaneus import MacAddress
from HostController.managers.machine_manager import IGuestManager, IGuest, MachineState, NETLOG_NAME, HTTPS_NETLOG_NAME
from HostController.managers.netmons import BareNetMon, SnifferAlreadyRunningException
from HostController.logic.WorkerStatus import WorkerStatus
from HostController.managers.smart_plug.hs100 import HS1XX

DEFAULT_OP_TIMEOUT = 3000
IPXE_TEMPLATE = "#!ipxe\nsanboot iscsi:{ip}::::{iqn}"

schema = {
    "type": "array",
    "items": {
        "type": "object",
        "properties": {
            "sandbox_mac": {"type": "string", "pattern": "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"},
            "smartplug_ip": {"type": "string", "pattern": "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"},
        },
        "required": ["sandbox_mac", "smartplug_ip"]
    }

}


class FlaskWrapper:
    _t = None
    _flask_srv = flask.Flask("BareMetalManager")
    _host = None
    _port = None
    _started = None

    def __init__(self, host, port, manager):
        self._host = host
        self._port = port
        self._flask_srv.config['bare_metal_manager'] = manager
        self._t = Thread(target=self._flask_srv.run, kwargs={'port':self._port, 'host':self._host, 'threaded':True})
        self._started = False

    def start(self):
        if self._started:
            raise Exception("Server was already started")

        self._t.start()
        self._started = True

    @staticmethod
    @_flask_srv.route("/boot/<mac>")
    def boot(mac):
        # This function is called whenever a client performs a request to the /boot/<mac> entrypoint.
        # when this happens, flask calls appropriate methods of the BareMetalManager
        if not validate_mac(mac):
            return "#!ipxe\nEcho INVALID MAC ADDRESS PROVIDED: %s" % mac, 400
        else:
            mac = MacAddress.MacAddress(mac)  # type: MacAddress.MacAddress

        # Check if the mac is among the registered machines. If so, revert it.
        mgr = flask.current_app.config['bare_metal_manager']
        machine = mgr.get_guest_by_mac(mac)
        if machine is None:
            logging.warn("Web boot: Machine with mac %s does not exist on this manager." % mac)
            return ('#!ipxe\nEcho Mac address %s not registered with the manager.' % mac, 404)
        else:
            logging.info("Wb boot: requested boot of machine with mac %s." % mac)
            # Given a mac, calculate target name and VHD paths
            name, diff_path, base_path = mgr._calculate_iscsi_params(mac)

            # Remove / recreate the iscsi target
            iqn = create_differencing_disk(name, base_path, diff_path, mac)

            # TODO: use the new templates
            # Now compose the iPXE script file to be returned to the caller
            data = IPXE_TEMPLATE.format(ip=mgr._iscsi_server_ip, iqn=iqn)

            return data, 200


mapped_states = {
    0: MachineState.stopped,
    1: MachineState.running,
}


class BareMetalManager(IGuestManager):
    _netmon = None
    _machines = []
    # The IPXE_HTTP_SERVER is a Flask instance used to server IPXE script files to the clients requesting the boot
    _ipxe_server = None

    _iscsi_server_ip = None
    _binding_host = None
    _binding_port = None

    _child_vhd_folder = None
    _base_vhd_path = None

    _status_handler=None

    # The following IP-PORT are communicated to the sniffer as the
    # "IP to be used by snadboxes to reach the Host Controller". It is useful in cases of particular network topology
    # where nat and firewall come to play.
    _external_hc_port=None
    _external_hc_ip = None

    def __init__(self,
                 diff_vhd_folder,
                 base_vhd_path,
                 sniffer_url,
                 iscsi_server_ip,
                 machines_conf,
                 external_hc_ip,
                 external_hc_port,
                 binding_host,
                 binding_port=8181):
        super(BareMetalManager, self).__init__()
        self._child_vhd_folder = diff_vhd_folder
        self._base_vhd_path = base_vhd_path
        self._netmon = BareNetMon(sniffer_url)

        self._iscsi_server_ip = iscsi_server_ip
        self._binding_host = binding_host
        self._binding_port = binding_port
        self._ipxe_server = FlaskWrapper(host=self._binding_host, port=self._binding_port, manager=self)

        self._external_hc_ip=external_hc_ip
        self._external_hc_port=external_hc_port

        machines = None

        # If the machines parameter is provided in string form, load it into a convenient json obj
        if isinstance(machines_conf, str):
            try:
                machines = json.loads(machines_conf)
            except:
                raise ValueError("Invalid machines_conf parameter specified. Such parameter must either be a valid json string or a dictionary")

        # Now validate its schema
        try:
            validate(machines, schema)
        except Exception:
            raise ValueError("Invalid machines_conf parameter specified. "
                             "Json object was not in a correct form. Please specify it as an array of objects, each one"
                             " containing two properties: sandbox_mac (mac address as string) and smartplug_ip "
                             "(ip address as string)")

        # Ok, load the machines
        for m in machines:
            tmp = BareMetalMachine(manager=self,
                                   mac=MacAddress.MacAddress(m['sandbox_mac']),
                                   smartplug_ip=str(m['smartplug_ip']))
            self._machines.append(tmp)

    def set_machine_status_handler(self, handler):
        """
        Registers a status handler which should be notified by the manager every time a machine managed by this handler
        changes its status.
        :return:
        """
        self._status_handler = handler

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

        logging.info("Publishing %s:%d as HC address for the sniffer." % (self._external_hc_ip, self._external_hc_port))

        self._netmon.post_hc(self._external_hc_ip, self._external_hc_port)

    def prepare(self):
        if self._status_handler is not None:
            for m in self._machines:  # type: BareMetalMachine
                status = m.get_smartplug_obj().get_status()
                if status == 1:
                    self._status_handler.register_worker(m.get_mac(), WorkerStatus.ERROR)
                elif status == 0:
                    self._status_handler.register_worker(m.get_mac(), WorkerStatus.IDLE)

        # Time to register to the sniffer
        self.publish_hc()

        # Unfortunately calling RUN on the Flask app will block. We need to allocate a new thread or a new process for this.
        self._ipxe_server.start()

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
                return v  # type: BareMetalMachine

        return None

    def create_guest(self):
        raise NotImplementedError("This method is not supported by this manager. Bare metal guests cannot be created, "
                                  "instead they are registered in accordance with the configuration dictionary passed "
                                  "to the contructor.")

        #self._status_handler.notify_machine_status(self, self._mac, WorkerStatus.IDLE)

    def delete_guest(self, guest):
        raise NotImplementedError("This method is not supported by this manager. Bare metal guests cannot be deleted.")

    def get_netlog(self,
                   machine,  # type: BareMetalMachine
                   directory  # type:str
                   ):

        if not isinstance(machine, BareMetalMachine):
            raise Exception("Machine must be a reference to BareMetalMachine.")

        mac = machine.get_mac()
        pcap_file = os.path.join(directory, NETLOG_NAME)
        self._netmon.collect(mac, pcap_file)

        cap_file_https = os.path.join(directory, HTTPS_NETLOG_NAME)
        self._netmon.collect_https(mac, cap_file_https)

        return pcap_file, cap_file_https

    def start_network_sniffing(self,
                               guest  # type: BareMetalMachine
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
                               guest  # type: BareMetalMachine
                               ):

        # Stop the sniffer, if present
        mac = MacAddress.MacAddress(guest.get_mac())
        logging.debug("Stopping associated network sniffers to (traffic for/from %s)" % mac)
        status = self._netmon.query_status(mac)
        if status is None:
            logging.debug("There is no sniffer for mac %s" % mac)
        else:
            logging.debug("Sniffer status is %s" % status)
            if status == "running":
                logging.debug("Stopping sniffer for mac %s" % mac)
                self._netmon.stop(mac)

    def start_guest(self, machine):
        if not isinstance(machine, BareMetalMachine):
            raise ValueError("Machine argument must be an instance of BareMetalMachine class")

        sp = machine.get_smartplug_obj()  # type:HS1XX
        sp.switch_on()
        self._status_handler.notify_machine_status(machine.get_mac(), WorkerStatus.BOOTING)

    def revert_guest(self, machine):
        if not isinstance(machine, BareMetalMachine):
            raise ValueError("Machine argument must be an instance of BareMetalMachine class")

        sp = machine.get_smartplug_obj()  # type:HS1XX
        sp.switch_off()
        self._status_handler.notify_machine_status(machine.get_mac(), WorkerStatus.REVERTING)
        time.sleep(1)
        sp.switch_on()
        self._status_handler.notify_machine_status(machine.get_mac(), WorkerStatus.BOOTING)

    def get_machine_state(self,
                          machine  # type: BareMetalMachine
                          ):
        if not isinstance(machine, BareMetalMachine):
            raise ValueError("Machine argument must be an instance of BareMetalMachine class")

        sp = machine.get_smartplug_obj()  # type:HS1XX
        status = sp.get_status()
        s = mapped_states.get(str(status))
        return s

    def stop_guest(self, machine):
        if not isinstance(machine, BareMetalMachine):
            raise ValueError("Machine argument must be an instance of BareMetalMachine class")

        sp = machine.get_smartplug_obj()  # type:HS1XX
        sp.switch_off()
        self._status_handler.notify_machine_status(machine.get_mac(), WorkerStatus.SHUTTING_DOWN)
        time.sleep(1)
        self._status_handler.notify_machine_status(machine.get_mac(), WorkerStatus.IDLE)


    def get_name(self):
        return "BareMetalManager"

    def list_guests(self):
        return self._machines

    def _calculate_iscsi_params(self, mac):
        """
        Given a mac address string as input, calculates the iscsi target name and the path of the differencing vhd to be created
        :param mac:
        :return:
        """
        if mac is None:
            raise ValueError("Invalid mac address provided")

        name = None
        name = str(MacAddress.MacAddress(mac))

        name = name.lower().strip()
        name = name.replace("-","")
        name = name.replace(":","")

        return name, os.path.join(self._child_vhd_folder, name + ".vhdx"), self._base_vhd_path


class BareMetalMachine(IGuest):
    _manager = None
    _sandbox_mac = None
    _smartplug_ip = None
    _smart_plug = None

    def __init__(self, manager, mac, smartplug_ip):
        if not isinstance(manager, BareMetalManager):
            raise Exception("BareMetalMachine can be registered only to a BareMetalManager.")

        self._manager = manager

        self._mac = MacAddress.MacAddress(mac)
        self._smartplug_ip = str(smartplug_ip)
        self._smart_plug = HS1XX(ip = self._smartplug_ip)

    def get_mac(self):
        return self._mac

    def get_manager(self):
        return self._manager

    def get_smartplug_ip(self):
        return self._smartplug_ip

    def get_smartplug_obj(self):
        return self._smart_plug

"""
This module only works with Windows Server 2012.
Beside, we locally invoke methods. In the future we might be able to offload this duty to a distributed node.
"""


def create_differencing_disk(iscsi_target_name, parent_vhdx_path, child_vhdx_path, initiator_mac, iqn=None):
    import pythoncom; pythoncom.CoInitialize()

    initiator_mac = MacAddress.MacAddress(initiator_mac)

    connection = wmi.WMI(moniker='//./root/wmi')
    conn_cimv2 = wmi.WMI(moniker='//./root/cimv2')

    # Make sure we are on Win platform and we can connect to the WMI service
    _ensure_wt_provider_available(connection)

    """
    Creates a new diff_disk_vhdx extending the given parent_vhdx_path, and registers it to the specified isci target
    with the given iqn. If child disk exists, it will be disconnected, removed and created again. Returns the IQN of the
    newly created target.
    :param iscsi_target_name:
    :param iqn:
    :param parent_vhdx_path:
    :param child_vhdx_path:
    :return:
    """
    # NOTE! The MS iSCSI service only supports VHDX format. If you try to use any other format you'll get a stupid
    # non-sense error. So we make sure the parent path points to a VHDX file.
    _check_parent_image(parent_vhdx_path)

    # Retrieve any WT_DISK associated with the child image disk, if any.
    wtd_child = _get_wt_disk(connection, child_vhdx_path)

    # In case we found anyone, make sure there is no lun attached to it. If so, remove it.
    if wtd_child is not None:
        logging.info("Disk %s exists. Checking LUN attachments..." % wtd_child.DevicePath)
        lun = _get_lun_by_wtd(connection, wtd_child)
        if lun is not None:
            # The lun exists. Delete the mapping before proceeding
            logging.info("Disk %s id attached to lun %s. I need to remove this lun/mapping." %(wtd_child.DevicePath,
                                                                                               lun.TargetIQN))
            # TODO: shutdown all the connections?

            lun.RemoveAllWTDisks()
            logging.info("All disks detached from lun %s." % lun.TargetIQN)

        # Now that the lun is disconnected, delete the WT_DISK
        logging.info("Deleting disk %s..." % wtd_child.DevicePath)
        files = wtd_child.DevicePath
        wtd_child.Delete_()

        # Also delete the files from the disk
        vhdfiles = conn_cimv2.query("Select * from CIM_DataFile where Name = '" + files + "'")
        if len(vhdfiles) > 0:
            vhdfiles[0].Delete()

    # At this point we can proceed by creating a new disk and attaching it to the lun
    delta_disk = connection.WT_Disk.NewDiffWTDisk(ParentPath=parent_vhdx_path, DevicePath=child_vhdx_path)[0]
    logging.info("Differencing disk created.")

    # Make sure the lun exists and is correctly configured
    host = _get_or_create_target(connection, iscsi_target_name)
    if iqn is not None:
        host.TargetIQN = iqn
    logging.info("ISCSI target created/configured %s <-> %s." % (host.HostName, host.TargetIQN))

    # Now attach that disk to the lun
    host.AddWTDisk(delta_disk.WTD)
    logging.info("ISCSI disk %s attached to lun %s %s." % (delta_disk.Devicepath, host.HostName, host.TargetIQN))

    # Allow to the configured mac to attach to this target:
    id = connection.WT_IDMethod.SpawnInstance_()
    id.HostName=host.HostName
    id.Method=3
    id.Value=str(initiator_mac).replace(":","-")
    id.Put_()

    return host.TargetIQN


def _get_or_create_target(wmi_connection, target_name):
    # Check if target exists.
    wt_host_list = wmi_connection.WT_HOST(HostName=target_name)
    if wt_host_list is None or len(wt_host_list)==0:
        # We did not find it. Let's create it.
        wt_host = wmi_connection.WT_HOST.NewHost(HostName=target_name)
        wt_host = wmi_connection.WT_HOST(HostName=target_name)[0]
    else:
        wt_host=wt_host_list[0]

    return wt_host


def _get_wt_disk(wmi_connection, diskPath):
    """
    Given a disk path, check if we already have an associated wt_disk. Unfortunately, we need to query the whole db
    and perform a research. If we find the wt_disk, we return it, otherwise we return None. So the caller must always
    return value of this function.
    :param diskPath:
    :return:
    """
    wt_disks = wmi_connection.WT_Disk()
    for i in wt_disks:
        if i.DevicePath.lower() == diskPath.lower():
            return i

    return None


def _get_lun_by_wtd(wmi_connection, wtd):

    try:
        luns = wmi_connection.WT_LUNMapping(WTD=wtd.WTD)
        if luns > 0:
            return wmi_connection.WT_Host(HostName=luns[0].HostName)[0]
    except:
        return None
    return None


def _check_parent_image(parent):
    """
    Raise exceptions whether the parent file does not exist or if it is not in VHDX format
    :param self:
    :param parent:
    :return:
    """

    fname, extension = os.path.splitext(parent)
    if extension.lower() not in (".vhd",".vhdx"):
        raise Exception("The parent virtual disk image must be in VHD or VHDX format.")


def _ensure_wt_provider_available(wmi_connection):
    try:
        wmi_connection.WT_Portal
    except AttributeError:
        err_msg = "The Windows iSCSI target provider is not available."
        raise Exception(err_msg)
