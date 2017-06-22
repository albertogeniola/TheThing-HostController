import logging
import os
import socket
import struct
import time
import json
from sqlalchemy import or_
from multiprocessing import Process
from HostController.logic import db
from HostController.settings import CFG

l = logging.getLogger("synthetizer")
l.setLevel(logging.DEBUG)
h1 = logging.FileHandler(filename="synthetizer.log", mode="w")
h2 = logging.StreamHandler()
l.addHandler(h1)
l.addHandler(h2)

NETWORK_ANALYSIS_LIMIT = 3
RETRY_INTERVAL = 10


class NetworkSynthetizerClient:
    _t = None

    def __init__(self):
        self._t = Process(target=self._run)

    def start(self):
        self._t.start()

    def stop(self):
        self._t.terminate()

    def remote_analyze(self, pcapfile, httpscap_file, target, network_conf):
        BUFFLEN = 1024*1024

        if isinstance(network_conf, dict):
            network_conf = json.dumps(network_conf)

        # Send the pcap file to the server and save the result in target
        log = logging.getLogger("synthetizer")

        #
        # Connect to the remote server. This might go up to infinite time.
        #
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        while True:
            try:
                log.debug("Connecting to synthetizer...")
                sock.connect((CFG.network_analyzer_ip, CFG.network_analyzer_port))
                break
            except socket.error:
                # The remote server seems busy or down. Retry up to infinite times.
                log.error("Cannot connect to remote server. Maybe it is down or too busy. Retrying...")
                time.sleep(RETRY_INTERVAL)
                continue

        try:
            log.debug("Connected to analyzer.")

            # Send both the files to be analyzed
            def send_file(s, fpath):
                # First send the dimension (BigEndian) and the data regarding standard pcap
                size = os.path.getsize(fpath)
                bytes = struct.pack('!L', size)
                sock.sendall(bytes)

                log.debug("Sending file %s of len %d" % (fpath, size))

                # Now we send the actual file's binary
                with open(fpath, "rb") as f:
                    data = f.read(BUFFLEN)
                    #log.debug("Read %d bytes from %s" % (BUFFLEN, fpath))
                    while data:
                        #log.debug("Sending %d bytes to socket" % len(data))
                        s.sendall(data)
                        #log.debug("Data sent. Reading from file again.")
                        data = f.read(BUFFLEN)
                        #log.debug("Read %d bytes from %s" % (len(data), fpath))

                log.debug("File %s of len %d sent." % (fpath, size))

            def send_conf(s, conf):
                # First send the dimension (BigEndian) and the data regarding standard pcap
                size = len(conf)
                bytes = struct.pack('!L', size)
                sock.sendall(bytes)

                log.debug("Sending conf file to synthetizer")
                s.sendall(conf)


            send_file(sock, pcapfile)
            send_file(sock, httpscap_file)

            # Also send the configuration info regarding this analysis. This contains some context information regarding
            # the network environment in which the test was executed, e.g. DEFAULT_GW IP, CLIENT IP.
            log.debug("Sending network conf: %s" % network_conf)
            send_conf(sock, network_conf)

            # Now wait for the analysis result. This may take a looooooong time. So timeout should take this into account.
            log.debug("Capture files sent to analyzer, waiting for report...")

            # We will receive stream of json utf-8 encoded bytes. Write them straight away to the target file.
            # The stream will close when data is over.
            with open(target, 'wb') as f:
                data = sock.recv(BUFFLEN)
                while data:
                    f.write(data)
                    data = sock.recv(BUFFLEN)

            # At this point we received everything.
            log.debug("Remote analysis OK.")

        except Exception:
            log.exception("Error during remote analysis")
            sock.close()
            raise

    def _run(self):
        session = db.sessionmaker()
        # Connect to the db, until there is a job to be done. Forward the job to the VM taking care of it and update
        # the db with its results
        while True:
            nj = None
            try:
                time.sleep(1)
                nj = session.query(db.NetworkJob).filter(db.NetworkJob.assigned == False)\
                    .with_lockmode("update").first()

                if nj is not None:
                    l.info("Found network analysis job to perform. Processing experiment id %d" % nj.experiment.id)
                    nj.assigned = True
                    session.commit()

                    # We got a non None network job to do.
                    # Start sending it to the analyzer and save it on the same folder where the rest of the log info are.
                    if nj.experiment.pcappath is not None:

                        network_cap_path = db.get_full_path_to_report_dir(nj.experiment.pcappath)
                        network_cap_https_path = db.get_full_path_to_report_dir(nj.experiment.pcappath_https)
                        target = os.path.dirname(network_cap_path)
                        target = os.path.join(target, "network_analysis.json")
                        network_conf = nj.experiment.network_conf
                        self.remote_analyze(network_cap_path,network_cap_https_path, target, network_conf)

                        # Now update the db accordingly
                        nj.experiment.network_summary = db.get_relative_path_to_report_dir(target)

                        # Remove the job from the list
                        session.delete(nj)
                        session.commit()
                    else:
                        # Forget about this element
                        session.delete(nj)
                        session.commit()
                else:
                    # If we have no new jobs, try to rescue an old one
                    exp = session.query(db.Experiment)\
                        .filter(db.Experiment.result == "success",
                                db.Experiment.report_processed == False,
                                db.Experiment.retrying == False,
                                db.Experiment.network_summary_attempt < NETWORK_ANALYSIS_LIMIT,
                                or_(db.Experiment.network_summary == None, db.Experiment.network_summary == ""))\
                        .with_lockmode("update")\
                        .order_by(db.Experiment.network_summary_attempt)\
                        .first()

                    if exp is not None:
                        l.info("Found incompleted network analysis job. Processing experiment id %d" % exp.id)
                        network_cap_path = db.get_full_path_to_report_dir(exp.pcappath)
                        network_cap_https_path = db.get_full_path_to_report_dir(exp.pcappath_https)
                        target = os.path.dirname(network_cap_path)
                        target = os.path.join(target, "network_analysis.json")
                        network_conf = exp.network_conf

                        ok = False
                        try:
                            self.remote_analyze(network_cap_path, network_cap_https_path, target, network_conf)
                            ok = True
                        except Exception as e:
                            # If error occurs when analysing network path, skip this
                            exp.network_summary_attempt += 1
                            l.exception("Error during network analysis")
                            exp.info = str(e)

                        if ok:
                            # Analysis was ok, update the target path
                            exp.network_summary = db.get_relative_path_to_report_dir(target)

                        session.commit()

            except KeyboardInterrupt:
                l.info("Synthetizer client has detected keyboard interruption, exiting.")
                session.rollback()
                return
            except Exception as e:
                session.rollback()
                if nj is not None and nj.assigned:
                    # Remove this job and set the result as "failure"
                    nj.experiment.info = "Error when analysing network data: "+str(e)
                    session.delete(nj)
                    session.commit()

                l.exception("Synthetizer got an error.")
                continue


"""
if __name__ == '__main__':
    #def remote_analyze(self, pcapfile, httpscap_file, target, network_conf):
    client = NetworkSynthetizerClient()
    conf = {"hc_port": 9000, "hc_ip": "195.32.86.31", "guest_ip": ["fe80::b033:d593:1f79:8c07%17", "192.168.0.15"], "default_gw": "192.168.0.1"}
    client.remote_analyze("C:\\InstallAnalyzer\\OutputReports\\37\\netlog.pcap", "C:\\InstallAnalyzer\\OutputReports\\37\\netlog_https.pcap", "C:\\InstallAnalyzer\\OutputReports\\37\\test.json", conf)
"""