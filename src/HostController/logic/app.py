import Queue
import json
import logging as Logging
import os
import socket
import struct
import threading
import time
from SocketServer import ThreadingMixIn, TCPServer, BaseRequestHandler
from HostController.logic import db
from HostController.settings import CFG
from network_synthetizer import NetworkSynthetizerClient
from HostController.utils import *
from HostController.miscellaneus import MacAddress
from HostController.utils import _get_output_report_dir
from HostController.logic.WorkerStatus import WorkerStatus
import argparse
import sys

BUFFER_SIZE = 8192
MAX_CONN_RETRIES = 20
RETRY_INTERVAL = 30

ctrl = None
synthetizer = None


# Logging: App
app_log = Logging.getLogger("app")
fname = os.path.join(CFG.logs_directory, "app.log")
hdlr = FileHandler(fname, mode='w')
formatter = Logging.Formatter('%(asctime)s %(levelname)s %(processName)s %(message)s')
hdlr.setFormatter(formatter)
app_log.setLevel(Logging.getLevelName(CFG.log_level))
app_log.addHandler(hdlr)


class MachineStatusHandler:
    _lock = threading.RLock()

    def register_worker(self, machine_mac, worker_status):
        with self._lock:
            db.jobmanager.register_worker(host_controller_id=CFG.host_controller_id,
                                      mac_address=str(MacAddress.MacAddress(machine_mac)),
                                      worker_status=worker_status)

    def notify_machine_status(self, machine_mac, worker_status):
        mac = MacAddress.MacAddress(machine_mac)
        with self._lock:
            db.jobmanager.update_worker_status(worker_mac=mac, hc_id=CFG.host_controller_id, status=worker_status)


class Connection(BaseRequestHandler):
    """
    This class implements specific TCP handler for requests incoming from guest agents. The server can either be
    iterative or multithreading (the latter is advised for better performance when using a large number of guest
    machines). Method HANDLE() (called by the bnase class) will serve each request according to the specific message
    received. In particular, GET_WORK and REPORT_WORK messages are the most important.
    """

    class ProtocolException(Exception):
        """
        Just a dummy extension to be used in our logic
        """
        pass

    def __read_sock(self,
                    datalen  # type: int
                    ):
        """
        Helper function (blocking) to read exactly datalen bytes from socket.
        If error occurs an exception is raised.
        :param datalen: Number of bytes to read from socket.
        :return: the string containing read data.
        """

        tot = 0
        res = []
        while tot<datalen:
            buf = self.request.recv(datalen)
            if not buf:
                raise Exception("Cannot read from socket, socket might be closed.")

            tot += len(buf)
            res.append(buf)

        return ''.join(res)  # type: str

    def __write_sock(self,
                     data  # type: bytes
                     ):
        """
        Helper function (blocking) to write all the bytes passed as argument through the socket.
        If error occurs an exception is raised.
        :param data: Data to be written into the socket.
        """
        self.request.sendall(data)

    def __send_file(self,
                    filepath  # type:str
                    ):
        """
        Send the file in filepath through the socket.
        :param filepath: path of the file to be sent
        :return: void
        """
        with open(filepath,'rb') as f:
            data = f.read(BUFFER_SIZE)
            while data:
                self.request.sendall(data)
                data = f.read(BUFFER_SIZE)

    def __recv_file(self,
                    destinationpath,  # type:str
                    filelen  # type:long
                    ):
        """
        Reads the file from the socket saving it to destinationpath.
        :param filepath: Where to save the file
        :param filelen: long representing how many bytes to read
        :return: void
        """
        tot = 0
        with open(destinationpath,'wb') as f:
            while tot < filelen:
                self.request.settimeout(5)
                data = self.request.recv(filelen)
                if not data:
                    raise Exception("IO Error when receiving data")
                tot += len(data)
                f.write(data)

            self.request.settimeout(None)

    """
    Each message is encoded as 4 byte little endian unsigned int
    followed by UTF-8 encoded json message.
    """
    def _read_message(self):
        """
        Reads a json message from the socket.
        :return: json parsed message (dictionary)
        """
        # Read a json message from the socket. The logic I am using simply requires an 4-bytes unsigned int
        # representing the message length in bytes, followed by the UTF-8 encoded json.
        # Firstly, we read the msg length, then we read the following data and finally we parse it into a json
        # object.
        data = self.__read_sock(4)
        bytes = struct.unpack('!I', data)[0]

        data = self.__read_sock(bytes)
        dec_data = data.decode(encoding='UTF-8', errors='strict')
        obj = json.loads(dec_data)
        return obj  # type: dict

    def _write_message(self,
                       msg  # type:dict
                       ):
        """
        Writes a dictionary into a json message through the socket.
        :return: void
        """
        # Write a json message to the socket. The logic I am using simply requires an 4-bytes unsigned int
        # representing the message length in bytes, followed by the UTF-8 encoded json.
        # Firstly, I'll compute the json representation of the dictionary, then I count the bytes needed and
        # send the bytes (4bytes unsigned) followed by the json encoding.
        if not isinstance(msg, dict):
            raise Exception("This method only accepts DICT type as msg")

        data = json.dumps(msg, encoding='utf-8')
        datalen = len(data)

        # Send the length of the message
        bytes = struct.pack('!I',datalen)
        self.__write_sock(bytes)

        # Send the message
        self.__write_sock(data)

    def _handle_get_work(self,
                         msg  # type: dict
                         ):
        """
        This method handles the request GET_WORK. It takes care of polling the db for a job, serve it to the client,
        and start the network sniffing.
        :param msg:
        :return:
        """
        client_address = ":".join([str(x) for x in self.request.getpeername()])
        cur_thread = threading.current_thread().getName()
        app_log.info("%s: Handling GET_WORK request from %s" % (cur_thread, client_address))

        # Parse all the info within the message from client
        if 'mac' not in msg:
            raise self.ProtocolException("Protocol error. The GET_WORK request did not contain any mac attribute.")
        if not validate_mac(msg['mac']):
            raise self.ProtocolException("Protocol error. GET_WORK request contained an invalid mac (%s)." % msg['mac'])

        mac = MacAddress.MacAddress(msg['mac'])

        # Let's pop a job from the db and then send data to the client
        mgr = db.jobmanager
        id, path = mgr.get_work(mac)

        # If get_work() returns a NONE ID, it means we have nothing more to do at the moment.
        if id is None:
            app_log.info("No work for client %s" % client_address)
            return mac, None

        # Otherwise we got a valid job ID to be processed.
        # Convert the obtained path into a locally valid path
        path = db.translate_installer_path(path)

        file_dim = 0
        file_name = None

        # Given the path, extract the name and the dimension of the file. We assume the file exists.
        file_name = os.path.basename(path)
        file_dim = os.path.getsize(path)

        app_log.info("%s: Sending work id %d (%s) to client %s" % (cur_thread, id, file_name, client_address))

        response = {'response': 'GET_WORK_RESP',
                    'work_id': id,
                    'file_name': file_name,
                    'file_dim': file_dim}

        # Send the get_work_response to client
        self._write_message(response)

        # Wait for GET_WORK_FILE message...
        answer = self._read_message()
        if 'command' not in answer:
            raise self.ProtocolException("Message from the client does not contain response command.")
        if answer['command'] != 'GET_WORK_FILE':
            raise self.ProtocolException("Unexpected command received by client: %s, expecting GET_WORK_FILE" % answer['command'])

        # Send the binary to analyze
        self.__send_file(path)

        # Wait for client's WORK_FILE_RECEIVED message.
        answer = self._read_message()
        if 'command' not in answer:
            raise self.ProtocolException("Message from the client does not contain response command.")
        if answer['command'] != 'GET_WORK_FILE_RECEIVED':
            raise self.ProtocolException("Unexpected command received by client: %s, expecting GET_WORK_FILE_RECEIVED" % answer['command'])

        # Start the sniffer addociated to this guest
        if not self.server._app_manager._manager_disabled:
            app_log.info("%s: Starting sniffer for machine with mac %s" % (cur_thread, mac))
            machine = self.server._app_manager.lookup_by_mac(mac)
            machine.get_manager().start_network_sniffing(machine)

        response = {'response': 'GET_WORK_START'}

        # Now let the guest agent start the work
        self._write_message(response)

        self.server._app_manager._machine_status_handler.notify_machine_status(machine_mac=mac, worker_status=WorkerStatus.ANALYZING)

        # Done!
        return mac, id

    def _handle_report_work(self,
                            msg  # type:dict
                            ):
        """
        Handles the REPORT_WORK message type. In particular, this method collects report and network context from the
        guest machine and stores it into the central DB.
        :param msg:
        :return:
        """
        client_address = ":".join([str(x) for x in self.request.getpeername()])
        cur_thread = threading.current_thread().getName()
        app_log.info("%s: Handling REPORT_WORK request from %s" % (cur_thread, client_address))

        exp_id = None

        # Parse all the info within the message from client
        if 'mac' not in msg:
            raise self.ProtocolException("Protocol error. The REPORT_WORK request did not contain any mac attribute.")
        if not validate_mac(msg['mac']):
            raise self.ProtocolException("Protocol error. REPORT_WORK request contained an invalid mac (%s)." % msg['mac'])

        mac = MacAddress.MacAddress(msg['mac'])

        if 'status' not in msg:
            raise self.ProtocolException("Protocol error. The REPORT_WORK request did not contain any status attribute.")

        if 'report_bytes_len' not in msg:
            raise self.ProtocolException("Protocol error. The REPORT_WORK request did not contain any report_bytes_len attribute.")

        if 'network_conf' not in msg:
            raise self.ProtocolException("Protocol error. The REPORT_WORK request did not contain any network_conf attribute.")

        length = 0
        try:
            length = int(msg['report_bytes_len'])
        except ValueError:
            raise self.ProtocolException("Protocol error. REPORT_WORK request contained an invalid report_bytes_len (%s)." % msg['report_bytes_len'])

        if length<0:
            raise self.ProtocolException("Protocol error. REPORT_WORK request contained a negative report_bytes_len (%d)." % length)

        work_id = -1
        if 'work_id' not in msg:
            raise self.ProtocolException("Protocol error. The REPORT_WORK request did not contain any work_id attribute.")
        try:
            work_id = int(msg['work_id'])
            exp_id = db.lookup_experiment_id_by_work_id(work_id)
            if exp_id is None:
                raise self.ProtocolException("The worker id provided did not match any experiment.")
        except ValueError:
            raise self.ProtocolException("Protocol error. REPORT_WORK request contained an invalid work_id (%s)." % msg['work_id'])

        self.server._app_manager._machine_status_handler.notify_machine_status(machine_mac=mac, worker_status=WorkerStatus.REPORTING)
        # The client also has to provide its current network context. We need its IP and its DEFAULT_GW. We will also
        # add info about
        network_conf = msg['network_conf']
        if not validate_network_conf(network_conf):
            raise self.ProtocolException("Protocol error. Invalid or incomplete network_conf json string: %s." % msg['network_conf'])

        if not self.server._app_manager._manager_disabled:
            # Now the client expects a sort of ACK to start report transmission. Before giving this ACK, we want to stop
            # the associated sniffer, so that report transmission does not impact on collected traffic.
            app_log.info("%s: Stopping sniffer for machine with mac %s" % (cur_thread, mac))
            machine = self.server._app_manager.lookup_by_mac(mac)
            machine.get_manager().stop_network_sniffing(machine)

        answer = {'response': 'REPORT_WORK_RESP'}
        self._write_message(answer)

        # Receive the file
        dest = build_output_report_fullpath(exp_id)
        app_log.info("%s: REPORT_WORK request from %s - Receiving file to %s" % (cur_thread, client_address,dest))
        self.__recv_file(destinationpath=dest, filelen=length)
        app_log.info("%s: REPORT_WORK request from %s - Received file to %s" % (cur_thread, client_address,dest))

        # Ok, let the client know we are done with file transfer
        answer = {'response': 'REPORT_WORK_REPORT_RECEIVED'}
        self._write_message(answer)

        app_log.info("%s: REPORT_WORK request from %s HANDLED OK" % (cur_thread, client_address))

        # Done!
        return work_id, dest, network_conf

    def handle(self):
        """
        This method implements the main logic of the sewrver. It basically routes all the incoming requests to 
        specific sub-methods, each one in charge of a particular message type. Every message, indeed, must contain the
        "command" field, which identifies the action to be taken by the server.
        
        Note that no integrity/identity check is performed at this stage. Future implementations might take this part 
        into account and implement security in some way.
        
        :return:
        """
        try:
            client_address = ":".join([str(x) for x in self.request.getpeername()])
            app_log.info("Connection from %s" % client_address)

            # Read the first message
            msg = self._read_message()
            app_log.debug("Received message from %s: %s" % (client_address, msg))

            # Check basic message format: at least each message should include MAC and COMMAND
            if 'command' not in msg or 'mac' not in msg:
                raise self.ProtocolException("The message read from the socket is wrong: command or mac missing.")

            if 'mac' not in msg:
                raise self.ProtocolException(
                    "Protocol error. The REPORT_WORK request did not contain any mac attribute.")
            if not validate_mac(msg['mac']):
                raise self.ProtocolException(
                    "Protocol error. REPORT_WORK request contained an invalid mac (%s)." % msg['mac'])

            mac = MacAddress.MacAddress(msg['mac'])

            # Make sure the client belongs to the ones we administrate.
            machine = self.server._app_manager.lookup_by_mac(mac)
            if not self.server._app_manager._manager_disabled and machine is None:
                raise self.ProtocolException("Given mac %s does not match with any machine handled by this manager." % mac)

            # GET_WORK: client is ready to receive a job
            if msg['command'] == "GET_WORK":
                mac, job = self._handle_get_work(msg)
                if job is None:
                    app_log.info("Machine %s has no work to do. Shutting it down." % machine)
                    #machine.get_manager().stop_guest(machine)
                    machine.get_manager().revert_guest(machine)
                    machine.get_manager().stop_guest(machine)

            # REPORT_WORK: client has done its job and wants to send back the report
            elif msg['command'] == "REPORT_WORK":
                work_id, dest, network_conf = self._handle_report_work(msg)
                # If the machine is done and it was a VM, we need to revert it!
                self.server._app_manager.notify_done(mac, work_id, dest, network_conf=network_conf, error=False)

            else:
                # This is a logic error/unexpected message type
                raise self.ProtocolException("Protocol error. Received message %s from host %s" % (msg, client_address))

        except Exception as e:
            app_log.exception("Error occurred.")

        finally:
            # Always release socket resources.
            self.request.close()


class Server(object):
    """
    This class represents the concurrent TCP server. It defines a ThreadPool that serve incoming requests. To increase
    or decrese the number of concurrent threads working, change the numThreads value. Default is 10.
    """
    _tcp_server = None

    class ThreadPoolMixIn(ThreadingMixIn):
        """
            use a thread pool instead of a new thread on every request
        """
        numThreads = 10
        allow_reuse_address = True

        def serve_forever(self):
            """
            Handle one request at a time until doomsday.
            """
            # set up the threadpool
            self.requests = Queue.Queue(self.numThreads)

            for x in range(self.numThreads):
                t = threading.Thread(target=self.process_request_thread)
                t.setDaemon(1)
                t.start()

            # server main loop
            while self._app_manager.should_run():
                self.handle_request()

            self.server_close()

        def process_request_thread(self):
            """
            obtain request from queue instead of directly from server socket
            """
            while self._app_manager.should_run():
                ThreadingMixIn.process_request_thread(self, *self.requests.get())

        def handle_request(self):
            """
            simply collect requests and put them on the queue for the workers.
            """
            try:
                request, client_address = self.get_request()
            except socket.error:
                return
            if self.verify_request(request, client_address):
                self.requests.put((request, client_address))

    class ThreadedTCPServer(ThreadPoolMixIn, TCPServer):
        allow_reuse_address = True
        pass

    def __init__(self, app_manager):
        self._tcp_server = self.ThreadedTCPServer((CFG.bind_host_address, CFG.bind_host_port), Connection)
        # Save a reference to the app manager so we can use it from within each thread. Warning! That class is not
        # thread safe. We must use it with CAUTION!
        self._tcp_server._app_manager = app_manager
        self._server_thread = threading.Thread(target=self._tcp_server.serve_forever)
        self._server_thread.daemon = False

    def start(self):
        self._server_thread.start()
        print("Server loop running in thread %s, listening on %s:%d." % (self._server_thread.name,
                                                                        self._tcp_server.server_address[0],
                                                                        self._tcp_server.server_address[1]))


# Logging: Watchdog
wd_log = Logging.getLogger("app.watchdog")
fname = os.path.join(CFG.logs_directory, "watchdog.log")
hdlr = FileHandler(fname, mode='w')
formatter = Logging.Formatter('%(asctime)s %(levelname)s %(processName)s %(message)s')
hdlr.setFormatter(formatter)
wd_log.setLevel(Logging.getLevelName(CFG.log_level))
wd_log.addHandler(hdlr)


class Watchdog(threading.Thread):
    """
    This class is in charge of overwatching the db. When a worker hits a timeout, we have to stop it and report failure.
    Contextually, we stop/revert the associated VM. Each Host controller will have its own watchdog.
    State information is written on the centralized DB. This means that each watchdog must be careful in handling VMs
    it owns, by filtering those with MAC addresses. By default this thread runs every 5 seconds.
    """
    timeout = CFG.vm_run_timeout
    run_interval = 5
    ctrl = None

    def __init__(self, controller):
        threading.Thread.__init__(self)
        self.ctrl = controller  # type: AppController

    def run(self):
        jmgr = db.jobmanager

        # Deamon!
        while self.ctrl.should_run():
            # Select all the workers from the DB that are tacking more than expected
            # Kill every VM related
            # Report Failure
            # Remove worker records
            # Wait interval
            dead = jmgr.get_pending_workers(self.timeout)
            if len(dead) > 0:
                wd_log.warning("Watchdog found %d workers above the timeout. I am going to terminate those "
                                "VM and report failure for associated experiment." % len(dead))

            for w in dead:
                mac = MacAddress.MacAddress(w.mac)
                try:
                    # Report failure for this job. We try to address any possible strange situation in here.
                    # This method should be as robust as possible
                    exp_id = db.lookup_experiment_id_by_work_id(w.id)
                    if exp_id is None:
                        wd_log.warning("Found a pending worker with null associated experiment_id. "
                                        "Such worker will be terminated.")

                    # Stop associated machine
                    machine = self.ctrl.lookup_by_mac(mac)
                    mm = machine.get_manager()
                    mm.stop_guest(machine)
                    wd_log.info("Watchdog stopped machine with mac %s." % mac)

                    # Now update the db accordingly
                    jmgr.set_work_error(w.id, info="Terminated by watchdog to to timeout.")

                    # Finally revert the machine
                    mm.revert_guest(machine)
                except Exception:
                    wd_log.exception("Watchdog got an exception.")
                    # We do not crash now.

            # Run again later...
            time.sleep(self.run_interval)


class AppController(object):
    """
    This Class represents the main application manager. Being a singleton, this instance is in charge
    of coordinating sub and technology specific machine-managers and is also in charge of network server
    management.
    """

    _lock = threading.RLock()
    _should_run = False

    # Watchdog for the db
    _watchdog = None

    # List of machineManagers registered to this main manager
    _managers = []

    # This dictionary maps to each mac_addres the associated IMachine instance for quick lookups.
    _handled_machines = {}

    # This server runs on a different thread and handles connection from GuestControllers
    _tcp_netowrk_server = None

    # Dictionary containing the agents clients to publish on sniffers
    _agents = {}

    _manager_disabled = None

    _machine_status_handler = None

    def __init__(self, disable_manager=False):
        self._manager_disabled = disable_manager
        self._tcp_netowrk_server = Server(self)
        self._watchdog = Watchdog(self)
        self._machine_status_handler = MachineStatusHandler()

        # Reset the DB status
        app_log.info("Resetting job manager")
        db.jobmanager.run_consistency_checks(CFG.host_controller_id)
        db.jobmanager.reset_workers(CFG.host_controller_id)

        # Load the agents available. Each nested in the path coresponds to a specific information regarding target system of the agent
        for p in os.listdir(CFG.agents_dir):
            # First nesting: platform.
            platform = p

            for v in os.listdir(os.path.join(CFG.agents_dir,platform)):
                # Second nesting: version
                version = v

                for a in os.listdir(os.path.join(CFG.agents_dir,platform,version)):
                    #Third nesting: architecture
                    arch = a

                    agent_path=os.path.join(CFG.agents_dir,platform,version,arch,"agent.zip")
                    if os.path.exists(agent_path):
                        app_log.info("Found AGENT for %s - %s - %s." % (platform, version, arch))
                        self._agents[(platform, version, arch)] = agent_path

    def load_managers(self):
        """
        Load all the managers specified into the configuration file
        :return:
        """
        for m in CFG.managers:
            app_log.info("Loading manager %s..." % m)
            mgr = None
            if m == "vbox":
                from HostController.managers.vbox import VBoxManager
                mgr = VBoxManager()

            elif m == "openstack":
                from HostController.managers.ostack import OpenStackManager
                mgr = OpenStackManager(
                    auth_url=CFG.os_auth_url,
                    project_name=CFG.os_project_name,
                    username=CFG.os_username,
                    password=CFG.os_password,
                    workers=CFG.os_workers,
                    sniffer_instance_name=CFG.os_sniffer_instance_name,
                    sniffer_image_name=CFG.os_sniffer_image_name,
                    sniffer_flavor=CFG.os_sniffer_flavor,
                    sniffer_security_group=CFG.os_sniffer_sg,
                    guest_image_name=CFG.os_guest_image_name,
                    guest_flavor=CFG.os_guest_flavor,
                    guest_security_group=CFG.os_guest_security_group,
                    public_network_name=CFG.os_public_network_name,
                    external_router_name=CFG.os_external_router_name,
                    internal_network_name=CFG.os_internal_network_name,
                    intranet_subnetwork_name=CFG.os_intranet_subnetwork_name,
                    sniffer_port=CFG.os_sniffer_port,
                    external_hc_ip=CFG.os_external_hc_ip,
                    external_hc_port=CFG.os_external_hc_port,
                    internal_network_cidr=CFG.os_internal_network_cidr)

            elif m == "baremetal":
                from HostController.managers.baremetal import BareMetalManager
                mgr = BareMetalManager(
                    diff_vhd_folder=CFG.baremetal_diff_vhd_folder,
                    base_vhd_path=CFG.baremetal_base_vhd_path,
                    sniffer_url=CFG.baremetal_sniffer_url,
                    iscsi_server_ip=CFG.baremetal_iscsi_server_ip,
                    machines_conf=CFG.baremetal_machines_conf,
                    binding_host=CFG.baremetal_websrv_host,
                    binding_port=CFG.baremetal_websrv_port,
                    external_hc_ip=CFG.baremetal_external_hc_ip,
                    external_hc_port=CFG.baremetal_external_hc_port)

            else:
                raise Exception("Invalid or unsupported manager specified: %s" % m)

            mgr.set_machine_status_handler(self._machine_status_handler)
            mgr.prepare()
            mgr.publish_agents(self._agents)
            self.add_manager(mgr)
            app_log.info("Manager %s loaded." % m)

    def should_run(self):
        """
        Returns false if analysis is over or has been requested to stop by the user, otherwise returns true.
        :return:
        """
        with self._lock:
            return self._should_run

    def start_server(self):
        """
        Start the analysis. This action will start the network service and the watchdog.
        :return:
        """
        with self._lock:
            self._should_run = True

        self._tcp_netowrk_server.start()
        self._watchdog.start()

    def stop_everything(self):
        """
        Notifies all the threads to stop and exit. This method will block until all the guest machines are stopped.
        :return:
        """
        with self._lock:
            self._should_run = False

        def stop_single(vm):
            app_log.info("Stopping machine with mac %s" % vm._mac)
            vm.get_manager().stop_guest(vm)

        threads = []
        for mac, machine in self._handled_machines.iteritems():
            t = threading.Thread(target=stop_single, args=(machine,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

    def lookup_by_mac(self, mac):
        # Lookup the given mac address from our dictionary
        if mac is None:
            return None

        m = MacAddress.MacAddress(mac)
        return self._handled_machines.get(m)

    def add_manager(self,
                    m_manager  # type:IGuestManager
                    ):
        """
        Adds a machine amanager (implementing IMachineManager interface) to the list of managers. By doing so, the
        the main manager can perform hybrid analysis, taking advantage of multiple-distinct hypervisor technologies.
        :param mgr:
        :return:
        """
        self._managers.append(m_manager)
        for m in m_manager.list_guests():
            self._handled_machines[MacAddress.MacAddress(m._mac)] = m

    def notify_done(self,
                    mac,  # type:str
                    work_id,  # type:int
                    dest,  # type:str
                    network_conf=None,  # type: dict
                    error=False,  # type:bool
                    info=None  # type:str
                    ):

        netowrk_file_path = None
        netowrk_file_https_path = None

        if not self._manager_disabled:
            # Retrieve the pcap file for that machine
            m = self.lookup_by_mac(mac)

            if m is None:
                # This machine is not handled by us.
                return

            mgr = m.get_manager()
            mgr.stop_guest(m)

            exp_id = db.lookup_experiment_id_by_work_id(worker_id=work_id)
            destpath = _get_output_report_dir(exp_id)
            netowrk_file_path = None
            netowrk_file_https_path = None

            try:
                netowrk_file_path, netowrk_file_https_path = mgr.get_netlog(m, destpath)
            except Exception as ex:
                error = True
                app_log.exception("Error when retrieving netlog / analysis.")
                #TODO: recover?

            # Restart the machine
            mgr.revert_guest(m)
            mgr.start_guest(m)

        # Update the db
        mgr = db.jobmanager
        if error:
            mgr.set_work_error(work_id, info,
                               pcappath=netowrk_file_path,
                               pcappath_https=netowrk_file_https_path,
                               network_conf=network_conf)
        else:
            mgr.set_work_succeeded(work_id, dest,
                                   pcappath=netowrk_file_path,
                                   pcappath_https=netowrk_file_https_path,
                                   info=info,
                                   network_conf=network_conf)

    def run_all_machines(self):
        def run_single(vm):
            app_log.info("Starting machine with mac %s" % vm._mac)
            #vm.get_manager().start_guest(vm)
            mgr = vm.get_manager()
            mgr.stop_guest(vm)
            mgr.revert_guest(vm)
            mgr.start_guest(vm)

        threads = []
        for mac, machine in self._handled_machines.iteritems():
            t = threading.Thread(target=run_single,args=(machine,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disable-managers",
                        action="store_true",
                        help="Do not load any machine manager. Useful for testing webservices.")
    return parser.parse_args()


def main():
    try:
        synthetizer = None
        opts = parse_args()

        CFG.bind_host_port = CFG.bind_host_port
        CFG.bind_host_address = CFG.bind_host_address

        app_log.info("Installer Analyzer Host Starting.")

        # Allocate the main manager and use it as a singleton for the whole project.
        app_log.info("Starting main manager")
        ctrl = AppController(disable_manager=opts.disable_managers)

        # Load the machine managers server
        if not opts.disable_managers:
            ctrl.load_managers()

        # Start the network daemon
        ctrl.start_server()

        # Start all the vms
        if not opts.disable_managers:
            ctrl.run_all_machines()

        # Allocate and start the network synthetizer
        if CFG.enable_analyzer:
            app_log.info("Starting synthetizer client")
            synthetizer = NetworkSynthetizerClient()
            synthetizer.start()

        # Wait for CTRL+C to terminate the program
        try:
            ctrl._tcp_netowrk_server._server_thread.join()
        except KeyboardInterrupt as interrupt:
            app_log.info("Synthetizer client has detected keyboard interruption, exiting...")
            # Stop everything.
            if synthetizer is not None:
                app_log.info("Killing syntetizer...")
                synthetizer.stop()

            app_log.info("Stopping AppController...")
            ctrl.stop_everything()

            app_log.info("Bye bye!")
    except:
        app_log.exception("Uncaught exception detected")
        raise

if __name__ == "__main__":
    main()
