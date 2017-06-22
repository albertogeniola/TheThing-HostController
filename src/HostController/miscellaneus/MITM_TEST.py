import Queue
import SocketServer
import json
import logging
import os
import re
import shutil
import struct
import threading

from logic import db
from managers import vbox

from HostController.settings import CFG


class PendingWorkers(object):
    _lock = None
    _dict = None

    def _format_mac(self,mac):
        return str(mac).lower().replace(':', '').replace('-', '')

    def __init__(self):
        self._lock = threading.RLock()
        self._dict = dict()

    def add(self, mac, exp_id):

        mmac = self._format_mac(mac)

        with self._lock:
            if self._dict.get(mmac) is not None:
                raise Exception('This worker is already working!')

            self._dict[mmac] = exp_id

    def set_done(self, mac):
        mmac = self._format_mac(mac)
        with self._lock:
            if self._dict.get(mmac) is None:
                raise Exception('This worker is not present in our records')

            exp_id = self._dict[mmac]

            del self._dict[mmac]
            return exp_id

    def get(self, mac):
        mmac = self._format_mac(mac)
        with self._lock:
            if self._dict.get(mmac) is None:
                raise Exception('This worker is not present in our records')

            return self._dict[mmac]


def build_mimt_output_dir():
    fname = os.path.join(CFG.output_report_dir, "mitm_attack")
    if not os.path.isdir(fname):
        os.mkdir(fname)
    return fname


def build_output_mitm_report_dir(work_id):
    fname = os.path.join(build_mimt_output_dir(), str(work_id))
    if not os.path.isdir(fname):
        os.mkdir(fname)
    return fname


def build_output_mitm_report_fullpath(work_id):
    fname = os.path.join(build_output_mitm_report_dir(work_id), "mitm.xml")
    return fname


def VALID_MAC(mac):
    return re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())


class CustomHandler(SocketServer.BaseRequestHandler):
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
        bytes = struct.unpack('!I',data)[0]

        data = self.__read_sock(bytes)
        dec_data = data.decode(encoding='UTF-8', errors='strict')
        obj = json.loads(dec_data)
        return obj  # type: dict

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
            while(data):
                self.request.sendall(data)
                data = f.read(BUFFER_SIZE)

    def __write_sock(self,
                     data  # type: bytes
                     ):
        """
        Helper function (blocking) to write all the bytes passed as argument through the socket.
        If error occurs an exception is raised.
        :param data: Data to be written into the socket.
        """
        self.request.sendall(data)

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

    def setup(self):
        print(self.client_address, ' connected.')

    def handle(self):
        try:
            client_address = ":".join([str(x) for x in self.request.getpeername()])
            cur_thread = threading.current_thread().getName()

            # Read the first message
            msg = self._read_message()
            mac = msg['mac']

            # What does the client want? Parse the message.
            if 'command' not in msg:
                raise Exception("The message read from the socket doesn't contain the command parameter.")

            # Handle GET_WORK: provide something to do for the requesting machine
            if msg['command'] == "GET_WORK":
                # Pop a job from our queue
                exp = None
                try:
                    exp = experiments.get(False)

                except Queue.Empty:
                    # Nothing to do at the moment. Shut it down.
                    machine = mgr.get_by_mac(mac)
                    logj.warn("\tRemaining experiments %d\tFailed jobs %d\t%s\t GET_WORK. Experiments are completed, retrieving one failed..." % (experiments.qsize(),failures.qsize(),mac))

                    try:
                        failed_id = failures.get(False)
                        # Retrieve the path for this job
                        exp = get_exp_data_by_id(failed_id)

                    except Queue.Empty:
                        logj.warn("\tRemaining experiments %d\tFailed jobs %d\t%s\t GET_WORK. Machine had nothing more to do. Shut down." % (experiments.qsize(),failures.qsize(),mac))
                        mgr.stop(machine)
                        return

                logj.info("\tRemaining experiments %d\tFailed jobs %d\t%s\t GET_WORK. Assigned job id %d" % (experiments.qsize(),failures.qsize(),mac,exp['id']))

                pending_workers.add(mac, exp['id'])

                def kill_when_stuck(m, e):
                    # Check if the machine is still running the same experiment id. If so it is stuck. Otherwise
                    # it has moved on, and that is fine.
                    try:
                        exp_id = pending_workers.get(m)
                    except:
                        # This means the given worker is not available any longer. Thus it is done.
                        return
                    if exp_id == e:
                        # We are stuck!
                        log.warn('Machine %s is stuck. I will revert it.' % mac)
                        logj.warn("\tRemaining experiments %d\tFailed jobs %d\t%s\t GET_WORK. Machine is stuck with job id %d" % (experiments.qsize(),failures.qsize(),mac,exp_id))
                        machine = mgr.get_by_mac(m)
                        mgr.stop(machine)

                        # Re-add its job id at the bottom of the queue
                        exp_id = pending_workers.set_done(m)
                        failures.put(exp_id)

                        mgr.revert(machine)
                        mgr.start(machine)
                        logj.warn("\tRemaining experiments %d\tFailed jobs %d\t%s\t GET_WORK. Machine reverted." % (experiments.qsize(), failures.qsize(), mac))

                # Now start a timer. If this job isn't executed within a timeout, kill the machine and restart it.
                threading.Timer(1700.0, kill_when_stuck, args=[mac, exp['id']]).start()

                # Convert the obtained path into a locally valid path
                path = db.translate_installer_path(exp['path'])

                file_dim = 0
                file_name = None

                # Given the path, extract the name and the dimension of the file. We assume the file exists.
                file_name = os.path.basename(path)
                file_dim = os.path.getsize(path)

                log.info("%s: Sending work id %d (%s) to client %s" % (cur_thread, exp['id'], file_name, client_address))

                response = {'response': 'GET_WORK_RESP',
                            'work_id': exp['id'],
                            'file_name': file_name,
                            'file_dim': file_dim}

                # Send the get_work_response to client
                self._write_message(response)

                # Wait for GET_WORK_FILE message...
                answer = self._read_message()
                if 'command' not in answer:
                    raise Exception("Message from the client does not contain response command.")
                if answer['command'] != 'GET_WORK_FILE':
                    raise Exception("Unexpected command received by client: %s, expecting GET_WORK_FILE" % answer['command'])

                # Start sending the installer
                self.__send_file(path)

                # Wait for client's ACK
                answer = self._read_message()
                if 'command' not in answer:
                    raise Exception("Message from the client does not contain response command.")
                if answer['command'] != 'GET_WORK_FILE_RECEIVED':
                    raise Exception("Unexpected command received by client: %s, expecting GET_WORK_FILE_RECEIVED" % answer['command'])

            elif msg['command'] == "REPORT_WORK":
                log.info("%s: Handling REPORT_WORK request from %s" % (cur_thread,client_address))

                # Parse all the info within the message from client
                if 'mac' not in msg:
                    raise Exception("Protocol error. The REPORT_WORK request did not contain any mac attribute.")
                if not VALID_MAC(msg['mac']):
                    raise Exception("Protocol error. REPORT_WORK request contained an invalid mac (%s)." % msg['mac'])

                if 'status' not in msg:
                    raise Exception("Protocol error. The REPORT_WORK request did not contain any status attribute.")

                if 'report_bytes_len' not in msg:
                    raise Exception("Protocol error. The REPORT_WORK request did not contain any report_bytes_len attribute.")

                len = 0
                try:
                    len = long(msg['report_bytes_len'])
                except ValueError:
                    raise Exception("Protocol error. REPORT_WORK request contained an invalid report_bytes_len (%s)." % msg['report_bytes_len'])

                if len<0:
                    raise Exception("Protocol error. REPORT_WORK request contained a negative report_bytes_len (%d)." % len)

                work_id = -1
                if 'work_id' not in msg:
                    raise Exception("Protocol error. The REPORT_WORK request did not contain any work_id attribute.")
                try:
                    work_id = long(msg['work_id'])
                except ValueError:
                    raise Exception("Protocol error. REPORT_WORK request contained an invalid work_id (%s)." % msg['work_id'])

                # Now the client expects a sort of ACK to start report transmission
                answer = {'response': 'REPORT_WORK_RESP'}
                self._write_message(answer)

                # Receive the file
                dest = build_output_mitm_report_fullpath(work_id)
                log.info("%s: REPORT_WORK request from %s - Receiving file to %s" % (cur_thread,client_address,dest))
                self.__recv_file(destinationpath=dest, filelen=len)
                log.info("%s: REPORT_WORK request from %s - Received file to %s" % (cur_thread,client_address,dest))

                # Ok, let the client know we are done with file transfer
                answer = {'response': 'REPORT_WORK_REPORT_RECEIVED'}
                self._write_message(answer)

                log.info("%s: REPORT_WORK request from %s HANDLED OK" % (cur_thread, client_address))

                # We are done. Simply revert the machine
                machine = mgr.get_by_mac(mac)
                log.info("Reverting machine %s" % str(mac))
                mgr.stop(machine)

                # Now collect its network log
                netdest = build_output_mitm_report_dir(work_id)

                log.info("Collecting network data for machine %s" % str(mac))

                netowrk_file_path, netowrk_file_https_path = mgr.get_netlog(machine, str(work_id), netdest)
                log.info("Report stored in \nNetwork -> %s\nHttps -> %s" % (netowrk_file_path,netowrk_file_https_path))

                logj.info("\tRemaining experiments %d\tFailed jobs %d\t%s\t REPORT_WORK. Machine completed the job. Reverting." % (experiments.qsize(),failures.qsize(),mac))

                mgr.revert(machine)

                pending_workers.set_done(mac)

                mgr.start(machine)
                return

            else:
                # This is a logic error/unexpected message type
                log.error("Protocol error. Received message %s from host %s" % (msg, client_address))
                raise Exception("Protocol error!")

        except Exception, e:
            log.exception("Protocol error occurred, %s." % e.message)
            logj.exception("\tRemaining experiments %d\tFailed jobs %d\t REPORT_WORK. Unexpected exception." % (experiments.qsize(),failures.qsize()))
            # TODO: in case of exception, should we take any action at this level?

        finally:
            self.request.close()

    def finish(self):
        print self.client_address, ' disconnected.'


def get_exp_data_by_id(exp_id):
    session = db.sessionmaker()
    try:
        # Every process started before that time should be returned
        w = session.query(db.Experiment).filter(db.Experiment.installation_ok==True, db.Experiment.id == exp_id)
        e = w.first()

        if e is not None:
            exp = dict()
            exp['id'] = e.id
            exp['path'] = e.job.path
            return exp
        else:
            raise Exception("Invalid experiment id")
    except:
        session.rollback()
        raise
    finally:
        session.close()



def fill_experiments_to_process(already_processed_ids):
    # Query the DB and get all the experiments ID
    count = 0
    session = db.sessionmaker()
    try:
        # Every process started before that time should be returned
        w = session.query(db.Experiment).filter(db.Experiment.installation_ok==True)
        for e in w.all():
            # Only add it if missing

            if str(e.id) in already_processed_ids:
                # Check whether some mandatory file is missing. If so, clear the content we have and mark
                # the itema as "to be processed".
                curdir = os.path.join(build_mimt_output_dir(), str(e.id))
                files = os.listdir(curdir)
                if ('mitm.xml' not in files) or ('netlog.pcap' not in files) or ('netlog_https.pcap' not in files):
                    log.warn("Experiment %d was already processed, but misses some necessary files. Reverting it." % e.id)
                    shutil.rmtree(curdir)
                else:
                    log.warn("Experiment %d was already processed. Ignoring it." % e.id)
                    continue

            exp = dict()
            exp['id'] = e.id
            exp['path'] = e.job.path
            experiments.put(exp)
            count += 1
    except:
        session.rollback()
        raise
    finally:
        session.close()

    return count


def network_daemon(bind_host_address, bind_host_port):
    # start listening on network
    srv = SocketServer.ThreadingTCPServer((bind_host_address, bind_host_port), CustomHandler, False) # Do not automatically bind
    srv.allow_reuse_address = True # Prevent 'cannot bind to address' errors on restart
    srv.server_bind()     # Manually bind, to support allow_reuse_address
    srv.server_activate() # (see above comment)
    srv.serve_forever()


BUFFER_SIZE = 8192

log = logging.getLogger()
log.setLevel(logging.DEBUG)

logj = logging.getLogger("mitm_jobs")
logj.setLevel(logging.DEBUG)
chj = logging.FileHandler("./mitm_jobs.log")
chj.setLevel(logging.DEBUG)
formatterj = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
chj.setFormatter(formatterj)
logj.addHandler(chj)


experiments = Queue.Queue()
mgr = vbox.VBoxManager()
pending_workers = PendingWorkers()
failures = Queue.Queue()

if __name__ == "__main__":
    bind_host_port = 9000
    bind_host_address = "0.0.0.0"

    log.info("MITM attacker, starting...")

    # Erase previous results
    log.info("Erasing previous results...")
    d = build_mimt_output_dir()

    if (not os.path.isdir(d)):
        os.mkdir(d)

    # Retrieve the list of already processed MITM.
    available_ids = os.listdir(d)

    # Populate the Queue that we will use as job dispenser dispenser
    count = fill_experiments_to_process(available_ids)

    if count == 0:
        log.info("Nothing to do, no experiment to process.")
        exit(0)
    else:
        log.info("Found %d experiments to process." % count)

    # Load the VBoxManager
    log.info("Preparing machine manager...")
    mgr.prepare()

    # Start all the VMs
    machines = mgr.list()
    for m in machines:
        mgr.start(m)

    # block until done.
    network_daemon(bind_host_address, bind_host_port)
