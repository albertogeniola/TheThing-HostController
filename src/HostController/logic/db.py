import datetime
import hashlib
import json
import logging
import ntpath
import os
from datetime import timedelta
import HostController.fuzzy as Fuzzy
from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime, Text, Float, UniqueConstraint
from sqlalchemy import create_engine, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.orm import sessionmaker
from HostController.logic.WorkerStatus import WorkerStatus, WORKER_STATUS_VALUES
from HostController.utils import MacAddress
from HostController.settings import CFG

__author__ = 'Alberto Geniola'

ATTEMPTS_LIMIT = 3
PATH_SEPARATOR = "{PATH_SEPARATOR}"
DEFAULT_TESTBED_NAME = "DEFAULT"

Base = declarative_base()


class Aggregator(Base):
    __tablename__ = 'aggregators'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    url = Column(String(4096), nullable=False)


class Job(Base):
    __tablename__ = 'jobs'
    id = Column(Integer, primary_key=True, autoincrement=True)
    fname = Column(String(255), nullable=False)
    downlink = Column(String(4096), nullable=True)
    downdate = Column(String(4096), nullable=True)
    path = Column(String(4096), unique=True, nullable=False)
    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=False)
    fuzzy = Column(String(150), nullable=False)
    aggregator = relationship(Aggregator)
    aggregator_id = Column(Integer, ForeignKey("aggregators.id"))
    __table_args__ = (UniqueConstraint('downlink', 'sha1', name='job_uniqueness'),)

    def __str__(self):
        values = {c.name: getattr(self, c.name) for c in self.__class__.__table__.columns}
        return ''.join('  {} = {}\n'.format(key, val) for key, val in values.items())


class TestBed(Base):
    __tablename__ = 'test_beds'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)

# An experiment is mapped to an input JOB, a given testbed and certain outputs.
# It represents the results obtained by the analyzer
class Experiment(Base):
    __tablename__ = 'experiments'
    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_in_progress = Column(Boolean, nullable=False, default=False)
    job = relationship(Job)
    job_id = Column(Integer, ForeignKey("jobs.id"))
    test_bed = relationship(TestBed)
    test_bed_id = Column(Integer, ForeignKey("test_beds.id"))
    startdate = Column(DateTime, nullable=True)
    finishdate = Column(DateTime, nullable=True)
    duration = Column(Integer, nullable=True)  # Duration in seconds
    reportpath = Column(String(4096), nullable=True) #  Path relative to settings.output_report_dir where report is stored
    result = Column(String(255), nullable=True)  # can be success or failed. Depends on the VM: if it crashed or reached timeout, this will be failure.
    attempt = Column(Integer, nullable=False, default=0)
    retrying = Column(Boolean, nullable=False, default=False)
    pcappath = Column(String(4096), nullable=True)
    pcappath_https = Column(String(4096), nullable=True)
    network_summary = Column(String(4096), nullable=True)
    network_summary_attempt = Column(Integer, nullable=False, default=0)
    info = Column(Text, nullable=True)

    # The following values will be populated after reports are processed. So they will be initially blank
    report_processed = Column(Boolean, default=False, nullable=False)  # Specifies if the report has been already processed
    injector_exit_code = Column(Integer, nullable=True)
    injector_stdout = Column(String(4096), nullable=True)
    injector_stderr = Column(String(4096), nullable=True)
    ui_bot_exit_status = Column(String(255), nullable=True)
    ui_bot_log = Column(Text(), nullable=True)
    screens = Column(String(4096), nullable=True)  # Identities the path to the zip file containing screenshots

    # Manual checks, performed by humans
    installation_ok = Column(Boolean, default=None, nullable=True)
    installation_pups_shown = Column(Integer, default=None, nullable=True)
    installation_failure_reason = Column(String, nullable=True)

    # Optional data, such as file version and product name
    product_name = Column(String(1024), nullable=True, default=None)
    description = Column(Text, nullable=True, default=None)
    copyright = Column(Text, nullable=True, default=None)
    file_version = Column(String(1024), nullable=True, default=None)
    company_name = Column(String(1024), nullable=True, default=None)
    original_file_name = Column(String(1024), nullable=True, default=None)
    product_version = Column(String(1024), nullable=True, default=None)
    network_conf = Column(Text(), nullable=True, default=None) # Contains information regarding the network context within the automation was executed.


class UiAnalysis(Base):
    __tablename__ = 'ui_analysis'
    experiment_id = Column(Integer, ForeignKey("experiments.id"), primary_key=True)     # PK
    screen_id = Column(Integer, primary_key=True, nullable=False)                       # PK
    control_id = Column(Integer, primary_key=True, nullable=False)                      # PK
    screen_position_x = Column(Float, nullable=False)
    screen_position_y = Column(Float, nullable=False)
    window_position_x = Column(Float, nullable=False)
    window_position_y = Column(Float, nullable=False)
    control_width = Column(Float, nullable=False)
    control_height = Column(Float, nullable=False)
    control_text = Column(Text, nullable=True, default=None)
    control_is_enabled = Column(Boolean, nullable=True, default=None)
    control_has_focus = Column(Boolean, nullable=True, default=None)
    control_score = Column(Float, nullable=False)
    control_type = Column(Integer, nullable=False)
    experiment = relationship(Experiment)


class File(Base):
    """
    The File table contains all the files that we have seen during the analysis process and is discriminated by its SHA1
    hash. This means that a file is not unique for its PATH on the system, but for its data.
    """
    __tablename__ = 'files'
    # A file is uniquely identified by its SHA1 hash.
    sha1 = Column(String(40), primary_key=True, nullable=False)  # PK
    md5 = Column(String(32), nullable=False)
    fuzzy = Column(String(150), nullable=False)
    size = Column(Integer, nullable=False, default=0)  # File size
    vt_scanned = Column(Boolean, nullable=False, default=False)
    vt_positives = Column(Integer, nullable=True)
    vt_total = Column(Integer, nullable=True)
    vt_scan_details = Column(Text, nullable=True)


class FileAccess(Base):
    """
    FileAccess table contains all the NtOpen() with write permission on files. This table basically
    store information about the PATH of the file on the system and the experiments it refers to.
    Each file access is identified uniquely by its experiment-id, and file-id, path, access sequence.
    """
    __tablename__ = 'file_accesses'
    experiment_id = Column(Integer, ForeignKey("experiments.id"), primary_key=True)     # PK
    file_id = Column(String(40), ForeignKey("files.sha1"), primary_key=True)            # PK
    path = Column(String(2048), primary_key=True)                                        # PK
    sequence = Column(Integer, primary_key=True)        # Defines the access sequence.  # PK
    experiment = relationship(Experiment)
    file = relationship(File)
    directory = Column(String(2048), nullable=False)
    file_name = Column(String(2048), nullable=False)
    file_extension = Column(String(2048), nullable=True)
    is_last = Column(Boolean)                           # States if this is the last access performed by the installer


class FileSystemChanges(Base):
    """
    This table contains all the files that have been changed by the installer on a FS. Also new files are listed.
    In other words, this table contains all the fs changes that have survived the installation process.
    """
    __tablename__ = 'fs_changes'
    experiment_id = Column(Integer, ForeignKey("experiments.id"), primary_key=True)     # PK
    file_id = Column(String(40), ForeignKey("files.sha1"), primary_key=True)            # PK
    path = Column(String(2048), primary_key=True)                                        # PK
    experiment = relationship(Experiment)
    file = relationship(File)
    is_new = Column(Boolean)                                # Was the file present on the FS in first place? If so, that
                                                            # represents a dropped file by the installer.
    is_modified = Column(Boolean)                           # If the file has been modified
    is_deleted = Column(Boolean)                            # If the file has been deleted


class RegistryChanges(Base):
    __tablename__ = 'registry_changes'
    experiment_id = Column(Integer, ForeignKey("experiments.id"), primary_key=True)                               # PK
    full_path = Column(Text, nullable=False, primary_key=True)  # Concatenates both key_path and value name.      # PK
    key_path = Column(Text, nullable=False)   # Indicates the path of the registry key

    # Both the value name and value value can be null in case this record refers to a DELETED KEY.
    key_value_name = Column(Text, nullable=True)  # Indicates the value_name of the registry key
    key_value_value = Column(Text, nullable=True)  # Indicates the value_value of the registry key.

    key_old_value_value = Column(Text,nullable=True)  # In case of edited key, this column contains the previous value.

    is_new = Column(Boolean)  # States if the current element is new
    is_modified = Column(Boolean)  # States if the current element has been modified
    is_deleted = Column(Boolean)  # States if the current element has been deleted


class FileStrings(Base):
    __tablename__ = 'file_strings'
    string = Column(Text, primary_key=True)                                          # PK
    file_ids = Column(Text, nullable=False)


class HttpRequest(Base):
    """
    This table contains the requests performed by an installer to a specific host/website through the
    http protocol.
    """
    __tablename__ = 'http_requests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    host = Column(Text, nullable=False)
    hostname = Column(Text, nullable=True)
    path = Column(Text, nullable=False)
    fullpath = Column(Text,nullable=False)
    number = Column(Integer, nullable=False)
    experiment = relationship(Experiment)


class HttpsRequest(Base):
    """
    This table contains the requests performed by an installer to a specific host/website through the
    https protocol.
    """
    __tablename__ = 'https_requests'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    host = Column(String(256), nullable=False)
    hostname = Column(Text, nullable=True)
    port = Column(Integer, nullable=False)
    path = Column(Text, nullable=False)
    fullpath = Column(Text, nullable=False)
    scheme = Column(String(32), nullable=False)
    method = Column(String(32), nullable=False)
    content = Column(Text, nullable=True)
    first_line_format = Column(String(255), nullable=False)
    http_version = Column(String(32), nullable=False)
    timestamp_start = Column(Float, nullable=False)
    timestamp_end = Column(Float, nullable=False)
    experiment = relationship(Experiment)


class HttpDownload(Base):
    """
    This table contains info about the HTTP downloads of an installer. To detect where a file has been dropped, we can
    join FileSystemChanges on sha1 = file_id. This will tell us where a downloaded file has been left on the system.
    """
    __tablename__ = 'http_downloads'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    sha1 = Column(String(40), nullable=False)
    md5 = Column(String(32), nullable=False)
    fuzzy = Column(String(150), nullable=False)
    size = Column(Integer, nullable=False)
    source_ip = Column(String(15), nullable=False)
    source_port = Column(Integer, nullable=False)
    source_host = Column(String(255), nullable=True)
    mime = Column(String(255), nullable=False)
    parent_archive = Column(String(40), nullable=True)
    nested_level = Column(Integer, nullable=False, default=0)
    experiment = relationship(Experiment)


class HttpsDownload(Base):
    """
    This table contains info about the HTTPS downloads of an installer. To detect where a file has been dropped, we can
    join FileSystemChanges on sha1 = file_id. This will tell us where a downloaded file has been left on the system.
    """
    __tablename__ = 'https_downloads'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    sha1 = Column(String(40), nullable=False)
    md5 = Column(String(32), nullable=False)
    fuzzy = Column(String(150), nullable=False)
    size = Column(Integer, nullable=False)
    status_code = Column(Integer, nullable=False)
    method = Column(String(32), nullable=False)
    parent_archive = Column(String(40),nullable=True)
    nested_level = Column(Integer, nullable=False, default=0)
    hostname = Column(String(256), nullable=True)
    host = Column(String(256), nullable=False)
    port = Column(Integer, nullable=False)
    path = Column(Text, nullable=False)
    fullpath = Column(Text, nullable=False)
    scheme = Column(String(32), nullable=False)
    mime = Column(String(255), nullable=False)
    experiment = relationship(Experiment)


class NetworkConversation(Base):
    """
    This table contains data about the network conversations happened for each installer.
    """
    __tablename__ = 'network_conversations'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    transport_protocol = Column(String(255), nullable=False)
    src_addr = Column(String(15), nullable=False)
    src_port = Column(Integer, nullable=True)  # Can be null for protocol levels < transport
    dst_addr = Column(String(15), nullable=False)
    dst_port = Column(Integer, nullable=True)  # Can be null for protocol levels < transport
    tx_frames = Column(Integer, nullable=False)
    rx_frames = Column(Integer, nullable=False)
    tx_bytes = Column(Integer, nullable=False)
    rx_bytes = Column(Integer, nullable=False)
    duration = Column(Float, nullable=False)
    total_frames = Column(Integer, nullable=False)
    dst_host = Column(String(255), nullable=True)
    experiment = relationship(Experiment)


class NetworkProtocol(Base):
    __tablename__ = 'network_protocols'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    protocol_l4 = Column(String(255), nullable=False)
    protocol_l7 = Column(String(255), nullable=True)
    bytes = Column(Integer, nullable=False)
    experiment = relationship(Experiment)


class ControlPanelNewApp(Base):
    __tablename__ = 'cp_new_apps'
    experiment_id = Column(Integer, ForeignKey("experiments.id"), primary_key=True)         # PK
    name = Column(String(255), primary_key=True)                                            # PK
    experiment = relationship(Experiment)


class Worker(Base):
    __tablename__ = 'workers'
    id = Column(Integer, primary_key=True, autoincrement=True)
    hc_id = Column(Integer, nullable=False)
    mac = Column(String(17), unique=True, nullable=False)
    startdate = Column(DateTime)
    status = Column(String(255), nullable=False)
    status_date = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    experiment = relationship(Experiment, uselist=False, backref="analyzing_worker")
    experiment_id = Column(Integer, ForeignKey("experiments.id"))


# This table contains the list of jobs finished but currently waiting for network analysis
class NetworkJob(Base):
    __tablename__ = 'pending_network_analysis'
    id = Column(Integer, primary_key=True, autoincrement=True)
    experiment = relationship(Experiment)
    experiment_id = Column(Integer, ForeignKey("experiments.id"), nullable=False)
    assigned = Column(Boolean, nullable=False)


class JobManager(object):

    def _erase(self):
        # WARNING USE ONLY FOR TESTING!!!!
        """
        with _engine.connect() as conn:
            with conn.begin() as transaction:
                conn.execute("DROP table IF EXISTS aggregators CASCADE")
                conn.execute("DROP table IF EXISTS cp_new_apps CASCADE")
                conn.execute("DROP table IF EXISTS file_accesses CASCADE")
                conn.execute("DROP table IF EXISTS file_strings CASCADE")
                conn.execute("DROP table IF EXISTS files CASCADE")
                conn.execute("DROP table IF EXISTS fs_changes CASCADE")
                conn.execute("DROP table IF EXISTS http_downloads CASCADE")
                conn.execute("DROP table IF EXISTS http_requests CASCADE")
                conn.execute("DROP table IF EXISTS jobs CASCADE")
                conn.execute("DROP table IF EXISTS network_conversations CASCADE")
                conn.execute("DROP table IF EXISTS network_protocols CASCADE")
                conn.execute("DROP table IF EXISTS pending_network_analysis CASCADE")
                conn.execute("DROP table IF EXISTS registry_changes CASCADE")
                conn.execute("DROP table IF EXISTS test_beds CASCADE")
                conn.execute("DROP table IF EXISTS workers CASCADE")
        """
        Base.metadata.drop_all(_engine)
        Base.metadata.create_all(_engine)

    def get_or_create_aggregator(self, name, url):
        name = name.lower()
        url = url.lower()

        session = sessionmaker()
        try:
            agg = session.query(Aggregator).filter(Aggregator.name == name, Aggregator.url == url).first()
            if agg is None:
                agg = Aggregator(name=name, url=url)
                session.add(agg)
                session.commit()

            # Lookup it again
            agg = session.query(Aggregator).filter(Aggregator.name == name, Aggregator.url == url).first()
            return agg
        except:
            session.rollback()
            raise
        finally:
            session.expunge_all()
            session.close()

    def exists(self, aggregator, sha1):
        session = sessionmaker()
        try:
            j = session.query(Job).filter(Job.sha1 == sha1.lower(), Job.aggregator == aggregator).first()
            return j is not None
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def print_list_filter_jobs(self,
                  id_is=None,
                  fname_like=None,
                  downlink_like=None,
                  downdate_greater_than=None,
                  downdate_less_than=None,
                  assigned_is=None,
                  assigned_to=None,
                  path_like=None,
                  md5_is=None,
                  sha1_is=None,
                  fuzzy_like=None,
                  aggregator_name_like=None,
                  **kwargs):

        print("Printing jobs by selected filters:")

        session = sessionmaker()
        try:
            query = session.query(Job)

            if id_is is not None:
                query = query.filter(Job.id==int(id_is))

            if fname_like is not None:
                query = query.filter(Job.fname.like(str(fname_like)))

            if downlink_like is not None:
                query = query.filter(Job.downlink.like(str(downlink_like)))

            if downdate_greater_than is not None:
                query = query.filter(Job.downdate > str(downdate_greater_than))

            if downdate_less_than is not None:
                query = query.filter(Job.downdate < str(downdate_less_than))

            if assigned_is is not None:
                if assigned_is:
                    query = query.filter(Job.worker != None)
                else:
                    query = query.filter(Job.worker == None)

            if assigned_to is not None:
                query = query.filter(Job.worker == int(assigned_to))

            if path_like is not None:
                query = query.filter(Job.path.like(str(path_like)))

            if md5_is is not None:
                query = query.filter(Job.md5 == str(md5_is))

            if sha1_is is not None:
                query = query.filter(Job.sha1 == str(sha1_is))

            if fuzzy_like is not None:
                query = query.filter(Job.fuzzy.like(str(fuzzy_like)))

            if aggregator_name_like is not None:
                # Lookup the aggregator name
                query = query.filter(Job.aggregator.name.like(str(aggregator_name_like)))

            for r in query.all():
                print("---------------")
                print(r)


        finally:
            session.close()

    def create_job(self, path, aggregator_id, downlink, downdate, md5=None, sha1=None, fuzzy=None, **kwargs):
        if not ntpath.isfile(path):
            raise Exception("File %s does not exist or it is not a file." % path)

        # Calculate more info about the given installer.
        size = ntpath.getsize(path)
        if md5 is None or sha1 is None or fuzzy is None:
            # Calculate the hash function and ssdeep values
            m = hashlib.md5()
            s = hashlib.sha1()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    m.update(chunk)
                    s.update(chunk)
            md5 = m.hexdigest().lower()
            sha1 = s.hexdigest().lower()
            fuzzy = Fuzzy._fuzzy_hash_from_file(path).lower()

        fname = ntpath.basename(path)

        # Now add the data into the DB
        session = sessionmaker()

        try:
            new_job = Job(fname=fname,
                          aggregator_id=aggregator_id,
                          downlink=downlink,
                          downdate=downdate,
                          path=path,
                          md5=md5.lower(),
                          sha1=sha1.lower(),
                          fuzzy=fuzzy.lower())

            session.add(new_job)
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def get_default_testbed_id(self):
        return self._get_or_create_testbed(DEFAULT_TESTBED_NAME)

    def create_experiment(self, job_id, test_bed_id=None, **kwargs):
        session = sessionmaker()
        try:
            # Check if job_id and test_bed_id exist
            if session.query(Job).filter(Job.id==job_id).first() is None:
                raise ValueError("Specified job_id is not present in the database.")

            if test_bed_id is None:
                test_bed_id = self.get_default_testbed_id()

            if session.query(TestBed).filter(TestBed.id==test_bed_id).first() is None:
                raise ValueError("Specified test_bed_id is not present in the database.")

            # Do not add the job if we already have a mactch
            collision = session.query(Experiment).filter(Experiment.job_id==job_id,Experiment.test_bed_id==test_bed_id).first()
            if collision is not None:
                raise ValueError("There already is an experiment (experiment id %d) with job_id %d and test_bed_id %d." % (collision.id, job_id, test_bed_id))

            exp = Experiment(job_id=job_id,
                             test_bed_id=test_bed_id)

            session.add(exp)
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def run_consistency_checks(self, hc_id):
        session = sessionmaker()
        try:
            # First check: all the experiments that are under analysis but there is no associated worker in table
            exps = session.query(Experiment).with_lockmode("update").filter(Experiment.analysis_in_progress == True).all()
            for e in exps:  # type: Experiment
                w = session.query(Worker).filter(Worker.experiment_id==e.id).first()
                if w is None:
                    logging.error("Experiment-Id %d resulted to be under analysis but no associated worker has been found in the DB. reverting its status."  % e.id)
                    e.analysis_in_progress = False

            session.commit()

        except:
            session.rollback()
            raise
        finally:
            session.close()

    def reset_workers(self, hc_id):
        """
        Cleans up the state of the db in case the app is started again after a crash
        :return:
        """
        session = sessionmaker()
        try:
            # Get all the pending workers associated to myself. Those are "Zombies". Purge them.
            workers = session.query(Worker).with_lockmode("update").filter(Worker.hc_id==hc_id)
            for w in workers:
                if w.experiment is not None:
                    w.experiment.analysis_in_progress = False
                logging.error("Found a Worker in pending status. Worker's mac is %s.")
                session.delete(w)
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def register_worker(self,
                        host_controller_id,
                        mac_address,
                        experiment_id=None,
                        worker_status=WorkerStatus.IDLE):

        session = sessionmaker()
        try:
            w = Worker()
            w.hc_id = host_controller_id,
            w.mac = str(MacAddress.MacAddress(mac_address)),
            w.status = worker_status,
            w.experiment_id = experiment_id

            session.add(w)
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def update_worker_status(self,
                             worker_mac,
                             hc_id,
                             status,  # type:str
                             status_date=None  # type datetime.datetime
                             ):

        if status_date is None:
            status_date = datetime.datetime.utcnow()

        mac = MacAddress.MacAddress(worker_mac)

        session = sessionmaker()
        try:
            worker = session.query(Worker)\
                .filter(Worker.hc_id==hc_id, Worker.mac==str(mac))\
                .with_lockmode("update")\
                .filter(Worker.hc_id == hc_id)\
                .first()

            if worker is None:
                logging.error("Cannot find any worker with mac %s. "
                              "This usually happens when the machine is being prepared for the first "
                              "time and shutdown is invoked on it." % mac)
                return

            worker.status = status
            worker.status_date = status_date
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def get_pending_workers(self, timeout):
        """
        Look into the DB and return all the workers with status != IDLE.
        there should be a VM running for each worker line. If timeout is specified, this method returns
        all the workers started before than <timeout> milliseconds. Default value is 0, which means
        that all the workers started in the past will be returned.
        :param timeout:
        :return:
        """

        session = sessionmaker()
        try:
            # Calculate the time-threshold from now()-timeout.
            d = timedelta(milliseconds=-timeout)
            #d = timedelta(milliseconds=-60000)
            threshold = datetime.datetime.utcnow() + d

            # Every process started before that time should be returned
            w = session.query(Worker).filter(Worker.startdate < threshold, Worker.status!=WorkerStatus.IDLE, Worker.hc_id == CFG.host_controller_id)

            return w.all()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def get_work(self, mac):
        """
        Returns the work id and the installer path to be sent as work for the client.
        In case there is no job for the client, None/None is returned.
        :param mac: mac address of the machine in charge of this worker
        :return:
        """

        # Relying on the DB locking mechanism instead of using my private lock
        session = sessionmaker()
        attempt = 0
        try:
            # Check if there is any worker conflict. This might happen for a number of reasons.
            # A conflict is detected when a Worker is requesting a job but its status is different from BOOTING.
            # This means that something during the Worker's lifecycle went wrong.
            worker = session.query(Worker).filter(Worker.mac == str(MacAddress.MacAddress(mac))).first()
            if worker is None:
                # This worker does not belong to us.
                logging.error("Received a get_work from Worker %s. This worker is not configured in the Databse."
                              " Sending a NO-WORK response." % mac)
                return None, None

            if worker.status != WorkerStatus.BOOTING:
                # In order to recover, report failure for the job assigned previously to this worker (if any) and reset the worker status
                if worker.experiment is not None:
                    logging.error("Detected worker conflicts. Reporting failure for experiment id %d." % worker.experiment.id)
                    self.set_work_error(worker_id=worker.id,
                                        info="Detected worker conflicts. Reporting failure for experiment id %d." % worker.experiment.id)

            # Look for a job that has not completed yet and is not assigned to any worker
            # Get only jobs not currently assigned to workers
            experiment = session.query(Experiment)\
                .with_lockmode('update')\
                .filter(Experiment.attempt < ATTEMPTS_LIMIT,
                        Experiment.analysis_in_progress == False,
                        or_(Experiment.result != 'success', Experiment.result == None))\
                .order_by(Experiment.attempt).first()

            # If no experiment is found, return immediately.
            if experiment is None:
                return None, None

            # Otherwise assign the job to this worker
            worker.status = WorkerStatus.WAITING_JOB
            worker.status_date = datetime.datetime.utcnow()
            worker.startdate = datetime.datetime.utcnow()
            worker.experiment_id = experiment.id
            experiment.analysis_in_progress = True

            session.commit()
            return worker.id, experiment.job.path
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def set_work_error(self, worker_id, info, pcappath=None, pcappath_https=None, network_conf=None):
        """
        Register an ongoing work has finished with failure.
        :param worker_id:
        :param report_path: path where the full report is available
        :param info: additional info about the failure
        :return: void
        """

        # Lock is not necessary here, because handled by the DB itself with the SelectForUpdate
        #with self._lock:
        session=sessionmaker()
        try:
            worker = session.query(Worker).filter(Worker.id == worker_id).with_lockmode("update").first()
            if worker is None:
                raise Exception("Requested id doesn't exist on the DB. "
                                "Make sure you obtained the worker_id by calling get_work() method.")

            finishdate = None
            duration = None
            if worker.startdate is not None:
                finishdate = datetime.datetime.utcnow()
                delta = finishdate-worker.startdate
                duration = delta.total_seconds()

            # Check if the current worker refers to a previous experiment attempt. If so, update that row. Otherwise
            # add another
            experiment = worker.experiment

            # Update the experiment
            experiment.startdate=worker.startdate
            experiment.finishdate=finishdate
            experiment.duration=duration
            experiment.reportpath=None
            experiment.result='failure'
            experiment.pcappath=get_relative_path_to_report_dir(pcappath)
            experiment.pcappath_https=get_relative_path_to_report_dir(pcappath_https)
            experiment.attempt=experiment.attempt + 1
            experiment.network_summary=None
            experiment.info=info
            experiment.retrying=False
            experiment.analysis_in_progress=False

            if network_conf is not None:
                experiment.network_conf=json.dumps(network_conf)
            else:
                experiment.network_conf=None

            # Reset the startdate
            worker.startdate = None

            # Commit the transaction
            session.commit()
        except Exception as e:
            logging.exception("Error when handling call to work_error")
            session.rollback()
            raise e
        finally:
            session.close()

    def set_work_succeeded(self, worker_id, report_path, pcappath=None, pcappath_https=None, info=None, network_conf=None):
        """
        Register an ongoing work has finished and succeeded.
        :param worker_id:
        :param result: string/enum representing the result of the analysis
        :param report_path: path where the full report is available
        :return: void
        """

        # Lock is not necessary here, because handled by the DB itself with the SelectForUpdate
        #with self._lock:
        session = sessionmaker()
        try:
            worker = session.query(Worker).filter(Worker.id == worker_id).with_lockmode("update").first()
            if worker is None:
                raise Exception("Requested id doesn't exist on the DB. "
                                "Make sure you obtained the worker_id by calling get_work() method.")

            finishdate = datetime.datetime.utcnow()
            delta = finishdate-worker.startdate
            duration = delta.total_seconds()

            experiment = worker.experiment

            # Update the experiment
            # Result specific
            experiment.reportpath=get_relative_path_to_report_dir(report_path)
            experiment.startdate=worker.startdate
            experiment.finishdate=finishdate
            experiment.duration=duration
            experiment.result='success'
            experiment.pcappath=get_relative_path_to_report_dir(pcappath)
            experiment.pcappath_https=get_relative_path_to_report_dir(pcappath_https)
            experiment.network_summary=None
            experiment.attempt = experiment.attempt+1
            experiment.info=info
            experiment.retrying = False
            experiment.analysis_in_progress = False
            experiment.network_conf = json.dumps(network_conf)

            # Reset the startdate
            worker.startdate = None

            # Commit the transaction
            session.commit()
        except:
            session.rollback()
            raise
        finally:
            session.close()

    def _get_or_create_testbed(self, name):
        session = sessionmaker()
        try:
            test_bed = session.query(TestBed).filter(TestBed.name == name).first()

            # If not present, add a new record
            if test_bed is None:
                test_bed = TestBed(name=name)
                session.add(test_bed)

            # Commit the transaction
            session.commit()
            return test_bed.id
        except:
            session.rollback()
            raise
        finally:
            session.close()


def lookup_experiment_id_by_work_id(
        worker_id  # type: int
):
    """
    Given the id of a worker, this function looksup the db and return the associated experiment id, or NONE if 
    the worker does not exist or has no experiment assigned.
    :param worker_id: 
    :return: 
    """
    session = sessionmaker()
    try:
        worker = session.query(Worker).get(worker_id)
        return worker.experiment_id
    except:
        session.rollback()
        return None
    finally:
        session.close()


def get_relative_path_to_report_dir(fullpath):
    """
    Given a full path to the local file system, this method returns the relative path to the file. Useful to
    workaround Unix/Windows FS problems
    :param fullpath:
    :return:
    """

    if fullpath is None:
        return None

    # Split the full path into the directory and the relative path
    repodir = CFG.output_report_dir
    relative = os.path.relpath(fullpath,start=repodir)

    if relative is None:
        raise Exception("Unsupported fullpath provided")

    # Instead of using dedault path separator, let's use a custom maker.
    return relative.replace(os.sep,PATH_SEPARATOR)


def get_full_path_to_report_dir(relativepath):
    """
    Given a relative path, returns the full path, on the current system, pointing to the
    reports dir.
    :param relativepath:
    :return:
    """
    # Split the full path into the directory and the relative path
    repodir = CFG.output_report_dir
    relative = relativepath.replace(PATH_SEPARATOR,os.sep)

    return os.path.join(repodir,relative)


def translate_to_installer_path(abspath):
    """
    Given a os dependent path, returns an independent path to be used with the DB.
    :param abspath:
    :return:
    """
    if abspath is None:
        return None

    # Split the full path into the directory and the relative path
    install_base_dir = CFG.installers_base_dir
    relative = os.path.relpath(abspath,start=install_base_dir)

    if relative is None:
        raise Exception("Unsupported fullpath provided")

    # Instead of using dedault path separator, let's use a custom maker.
    return relative.replace(os.sep ,PATH_SEPARATOR)


def translate_installer_path(relpath):
    """
    Given a relative path in an independent representation (non OS-dependent), gives the OS dependent
    representation on this HostController
    :param relpath:
    :return:
    """
    # We basically have to concatenate the installer_path configuration available in the settings,
    # then we append the relative path and finally we translate the path separators to machine dependent.
    install_base_dir = CFG.installers_base_dir
    relative = relpath.replace(PATH_SEPARATOR,os.sep)

    return os.path.join(install_base_dir,relative)


_engine = create_engine(
            CFG.db_connection_string
        )
Base.metadata.create_all(_engine)
Base.metadata.bind = _engine

sessionmaker = sessionmaker(_engine)

# Initialize the jobmanager. Note that Python only runs the module code if the module has not been imported
# yet into the process. This means that this line runs Once per process. It's a sort of singleton pattern.
jobmanager = JobManager()
