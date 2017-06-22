"""
This is the executable in charge of inserting report result data into a DB format for further analysis
"""
import base64
import io
import json
import logging
import ntpath
import os
import re
import shutil
import xml.etree.ElementTree as ET
import zipfile
from multiprocessing import Process, Queue, current_process

import ipaddress
from logic.db import *
from lxml import etree as ET2
from sqlalchemy import *
from xmljson import parker as pk

from HostController.settings import CFG

PROC_GRADE=1

engine = create_engine(CFG.db_connection_string, isolation_level="AUTOCOMMIT")


def expand_report(experiment_id):
    """
    This function will parse the report data about the experiment_id provided and will expand its results into the db.
    :param experiment_id:
    :return: boolean: True if the expansion was ok, False otherwise.
    """

    session = sessionmaker()
    try:
        # Retrieve basic info about the work we want to expand
        experiment = session.query(Experiment).filter(Experiment.id == experiment_id).with_for_update().first()
        if experiment is None:
            logging.error("Experiment id %d is invalid." % experiment_id)
            return False

        # Only process non-processed reports
        if experiment.processed:
            logging.error("Experiment id %d has been already processed." % experiment_id)
            return False

        # Only proceed if the experiment has succeeded
        if experiment.result != "success":
            logging.error("Experiment id %d did not succeed." % experiment_id)
            return False

        # Check the report path is available
        reppath = get_full_path_to_report_dir(experiment.reportpath)
        if not os.path.exists(reppath):
            logging.error("Cannot find report file (%s) for experiment id %d." % (reppath, experiment_id))
            return False

        # Check the network summary is available
        if experiment.network_summary is None:
            # This is incomplete.
            logging.error("Experiment id %d is missing network analysis file." % experiment_id)
            return False

        netsummarypath = get_full_path_to_report_dir(experiment.network_summary)
        if not os.path.exists(netsummarypath):
            logging.error("Cannot find network summary file (%s) for experiment id %d." % (netsummarypath, experiment_id))
            return False

        logging.info("Processing file %s" % reppath)
        logging.info("Processing net report %s" % netsummarypath)

        # Process the XML report file
        process_report(experiment, session)

        # Process the network logging file
        process_net_summary(experiment, session)

        # Set the experiment as PROCESSED
        experiment.processed = True

        logging.info("Data import finished for experiment id %d" % experiment_id)

        # Clean the pcap file? Clean the report?
        session.commit()

        """
        # load the whole table in memory for fast lookup
        elements = session.query(FileStrings).all()

        db_strings = dict()
        for e in elements:
            db_strings[e.string] = e

        for k, v in strings.iteritems():
            for s in v:
                e = db_strings.get(s)
                if e is None:
                    e = FileStrings()
                    e.string=s
                    db_strings[s]=e

                if e.file_ids is None:
                    e.file_ids=json.dumps([k])
                else:
                    tmp = json.loads(e.file_ids)
                    tmp.append(k)
                    e.file_ids = json.dumps(tmp)

        # Save back to db
        session.bulk_save_objects(
            db_strings.values()
        )
        session.commit()
        """

        return True
    except Exception as e:
        logging.exception("Error when processing experiment id %d " % experiment_id)
        session.rollback()
        return False

    finally:
        session.close()


def process_net_summary(experiment, session):
    logging.info("Processing network summary for experiment id %d" % experiment.id)
    # Open the network summary file
    data = None
    netsumpath = get_full_path_to_report_dir(experiment.network_summary)
    with open(netsumpath) as fp:
        data = json.load(fp)

    # Save into a temp dictionary the hosts<->IP bindings. Those are useful to lookup the ip into the following
    # analysis
    ip_hosts, hosts_ip = process_hosts(data)

    # Process each part of the report step by step
    process_network_protocols(data, experiment, session)

    process_network_conversations(data, experiment, session, ip_hosts, hosts_ip)

    process_http_downlaods(data, experiment, session, ip_hosts, hosts_ip)

    process_http_requests(data, experiment, session, ip_hosts, hosts_ip)

    process_https_requests(data, experiment, session)

    process_https_downlaods(data, experiment, session)


def process_report(experiment, session):
    parser = ET2.XMLParser(recover=True, huge_tree=True) #recovers from bad characters.
    reppath = get_full_path_to_report_dir(experiment.reportpath)

    tree = ET.parse(reppath,parser=parser)
    #tree = ET.parse(reppath)
    root = tree.getroot()

    # Process the experiment row
    process_experiment(experiment, root, session)

    # Add the new applications detected into the control panel
    process_new_apps(experiment, root, session)

    # Handle the registry changes
    process_registry(experiment, root, session)

    # Handle file system changes.
    process_fs(experiment, root, session)

    # Handle UI Information
    process_ui(experiment, root, session)


def process_experiment(experiment, xml_root, session):
    """
    Fill experiment row according to the report data
    :param experiment:
    :param session:
    :return:
    """

    # Installer details
    installer = xml_root.find("Experiment/InstallerDetails")
    experiment.product_name = installer.find("ProductName").text.strip()
    experiment.description = installer.find("FileDescription").text.strip()
    experiment.copyright = installer.find("LegalCopyright").text.strip()
    experiment.file_version = installer.find("FileVersion").text.strip()
    experiment.company_name = installer.find("CompanyName").text.strip()
    experiment.original_file_name = installer.find("OriginalFilename").text.strip()
    experiment.product_version = installer.find("ProductVersion").text.strip()

    # Injector details
    injector = xml_root.find("Result/Injector")
    experiment.injector_exit_code = int(injector.find("RetCode").text.strip())
    experiment.injector_stdout = injector.find("StdOut").text.strip()
    experiment.injector_stderr = injector.find("StdErr").text.strip()

    # UIBot status & log
    uibot = xml_root.find("Result/UiBot")
    experiment.ui_bot_exit_status = uibot.find("Description").text.strip()
    experiment.ui_bot_log = xml_root.find("AppLog").text.strip()

    # Screenshots?


def _process_ui_xml(path, screen_id, experiment, session):
    with open(path) as ui_repo:
        parser = ET2.XMLParser(recover=True, huge_tree=True) #recovers from bad characters.
        tree = ET.parse(path,parser=parser)
        #tree = ET.parse(path)
        root = tree.getroot()

        control_id = 0
        # Look for records
        for uielement in root.findall("UIControlCandidate"):

            try:
                screen_position_x = uielement.find("PositionScreenRelative/Location/X").text
                screen_position_y = uielement.find("PositionScreenRelative/Location/Y").text
                window_position_x = uielement.find("PositionWindowRelative/Location/X").text
                window_position_y = uielement.find("PositionWindowRelative/Location/Y").text
                control_width = uielement.find("PositionWindowRelative/Size/Width").text
                control_height = uielement.find("PositionWindowRelative/Size/Height").text
                control_text = uielement.find("Text").text
                control_is_enabled = None
                if uielement.find("IsEnabled").text is not None:
                    control_is_enabled = uielement.find("IsEnabled").text.lower() == "true"
                control_has_focus = None
                if uielement.find("HasFocus").get("xsi:nil") is not None:
                    control_is_enabled = uielement.find("HasFocus").get("xsi:nil").text.lower() == "true"

                control_score = float(uielement.find("Score").text)
                control_type = int(uielement.find("ControlTypeId").text)

                obj = UiAnalysis(
                        experiment_id=experiment.id,
                        screen_id=screen_id,
                        control_id=control_id,
                        screen_position_x=screen_position_x,
                        screen_position_y=screen_position_y,
                        window_position_x=window_position_x,
                        window_position_y=window_position_y,
                        control_width=control_width,
                        control_height=control_height,
                        control_text=control_text,
                        control_is_enabled=control_is_enabled,
                        control_has_focus=control_has_focus,
                        control_score=control_score,
                        control_type=control_type)
                session.add(obj)

                control_id += 1
            except Exception as e:
                pass


def process_ui(experiment, root, session):
    logging.info("Processing UI interactions for experiment id %d" % experiment.id)

    # Prepare the destination directory
    dir_path = os.path.join(os.path.curdir, "ui_zips")
    if not os.path.isdir(dir_path):
        os.mkdir(dir_path)

    dir_path = os.path.join(dir_path, str(experiment.id))

    if os.path.exists(dir_path) and os.path.isdir(dir_path):
        # Erase it
        shutil.rmtree(dir_path)
    else:
        os.mkdir(dir_path)

    # Retrieve binary data included into the report
    b64_zipfile = root.find("InteractionScreenshots")

    # Extract that zipfile directly from memory to created dir
    data = base64.b64decode(b64_zipfile.text)
    with io.BytesIO(data) as zip_data:
        with zipfile.ZipFile(zip_data) as zip:
            zip.extractall(dir_path)

    logging.info("Zip archive for experiment id %d has been extracted to %s" % (experiment.id, dir_path))

    # Now read all the xml files
    reg_compile = re.compile("^[0-9]+\.(xml|XML)$")
    results = []
    for p in os.listdir(dir_path):
        if os.path.isfile(os.path.join(dir_path, p)) and reg_compile.match(p):
            results.append(p)

    def comparator(x, y):
        x_str = re.search('^([0-9]+)\.(xml|XML)$', x, re.IGNORECASE).group(1)
        y_str = re.search('^([0-9]+)\.(xml|XML)$', y, re.IGNORECASE).group(1)
        x_int = int(x_str)
        y_int = int(y_str)

        return x_int - y_int

    # Order the list so we first process correct files
    results = sorted(results, cmp=comparator)

    # Process every XML file
    i = 0
    for f in results:
        _process_ui_xml(os.path.join(dir_path, f), i, experiment, session)
        i += 1

    # Now extract some other info about the experiment. User Parker convention, which ignores Attributes
    xml_applog = root.find("AppLog")
    xml_experiment = root.find("Experiment")
    xml_guest = root.find("GuestConfiguration")
    xml_new_apps = root.find("Result/NewApplications")
    xml_ui_bot = root.find("Result/UiBot")
    xml_injector = root.find("Result/Injector")

    # Convert to dictionaries
    applog = pk.data(xml_applog)
    exp = pk.data(xml_experiment)
    guest = pk.data(xml_guest)
    new_apps = pk.data(xml_new_apps)
    ui_bot = pk.data(xml_ui_bot)
    injector = pk.data(xml_injector)

    # Put everything together
    result = {}
    result['AppLog'] = applog
    result['Experiment'] = exp
    result['Guest'] = guest
    result['NewApps'] = new_apps
    result['UiBot'] = ui_bot
    result['Injector'] = injector

    # Convert everything to a json file
    with open(os.path.join(dir_path, "report.json"),'w') as rep:
        json.dump(result,rep)

    logging.info("Processed %d UI mini ui reports" % len(results))


def process_fs(experiment, root, session):
    logging.info("Processing FS for experiment id %d" % experiment.id)
    result = root.find("Result")

    """
    # We need a dictionary that will contain file<->strings to be added later on
    file_strings = dict()
    """

    # File accesses
    files = result.findall("FileAccess//File")
    for f in files:
        # For each new file we might have a sequence of events. That means we need to process each element into the
        # AccessHistory tag.
        f_accs = f.findall("AccessHistory/FileStatus")
        last_seq = len(f_accs)-1
        for fa in f_accs:
            try:
                path = fa.find("Path").text.strip()
                md5 = fa.find("Md5Hash").text.strip().lower()
                sha1 = fa.find("Sha1Hash").text.strip().lower()
                fuzzy_hash = fa.find("FuzzyHash").text.strip().lower()
                size = int(fa.find("Size").text.strip())
                sequence = int(fa.get("Sequence").strip())

                db_file = File()
                db_file.sha1=sha1
                db_file.md5=md5
                db_file.fuzzy=fuzzy_hash
                db_file.size=size
                session.merge(db_file)

                # Add a matching file access (if not previously existing)

                db_fa = FileAccess()
                # PKEY cols
                db_fa.experiment_id = experiment.id
                db_fa.file_id=db_file.sha1
                db_fa.path=path
                db_fa.sequence=sequence

                # Other cols
                db_fa.directory=ntpath.dirname(path)
                db_fa.file_extension=ntpath.splitext(path)[-1]
                db_fa.file_name=ntpath.basename(path)
                db_fa.is_last = False
                session.merge(db_fa)

                # When dealing with the last accessed file we have information about the last change performed on the FS.
                # So we can fill the FileSystemChanges table with that info.
                if last_seq == sequence:
                    db_fa.is_last = True
                    last_file_change = FileSystemChanges()
                    last_file_change.file_id = db_file.sha1
                    last_file_change.experiment_id = experiment.id
                    last_file_change.path = path

                    last_file_change.is_deleted = f.get("Deleted")=="True"
                    last_file_change.is_modified = f.get("Modified")=="True"
                    last_file_change.is_new = f.get("New")=="True"

                    # Only update/merge if New/deleted/modified
                    if last_file_change.is_deleted or last_file_change.is_modified or last_file_change.is_new:
                        session.merge(last_file_change)
            except:
                logging.exception("Unhandled exception occurred")
                import pdb;pdb.set_trace()
                continue

                """
                # Populate the dictionary containing the strings associated to this file
                strings = f.findall("Strings/String")
                if len(strings)>0:
                    clean_strs = set()
                    for s in strings:
                        if s.text is not None:
                            clean_strs.add(s.text.strip())

                    file_strings[db_file.sha1] = clean_strs
                    #logging.info("Processed %d strings for file %s" % (len(strings),db_fa.path))

    return file_strings
                """


def process_new_apps(experiment, root, session):
    logging.info("Processing New Apps for experiment id %d" % experiment.id)

    result = root.find("Result")

    # Control panel / New apps
    new_apps = result.findall("NewApplications/Application")
    k = set()
    for app in new_apps:
        k.add(app.text)
    for app in k:
        tmp = ControlPanelNewApp(name=app, experiment_id=experiment.id)
        logging.debug("Adding Application %s " % app)
        session.add(tmp)


def process_hosts(data):
    ip_hosts = dict()
    hosts_ip = dict()
    for entry in data['hosts']:
        ip = format_ip(entry['ip'])

        ip_hosts[str(ip)] = str(entry['host'])
        hosts_ip[str(entry['host'])] = str(ip)

    return ip_hosts, hosts_ip


def process_network_protocols(data, experiment, session):
    for entry in data['protocols']:
        prot = NetworkProtocol()
        prot.experiment_id = experiment.id
        prot.bytes = int(entry['bytes'])
        prot.frames = int(entry['frames'])
        prot.protocol = entry['protocol']
        session.add(prot)


def process_network_conversations(data, experiment, session, ip_hosts, hosts_ip):
    # Import first udp conversations
    for entry in data['udp_conversations']:
        nc = NetworkConversation()
        nc.experiment_id = experiment.id
        nc.transport_protocol = 'udp'
        nc.src_addr = str(entry['src_addr'])
        nc.src_port = int(entry['src_port'])
        nc.dst_addr = str(entry['dst_ip'])
        nc.dst_host = ip_hosts.get(format_ip(str(entry['dst_ip'])))
        nc.dst_port = int(entry['dst_port'])
        nc.rx_bytes = int(entry['rx_bytes'])
        nc.tx_bytes = int(entry['tx_bytes'])
        nc.rx_frames = int(entry['rx_frames'])
        nc.tx_frames = int(entry['tx_frames'])
        nc.total_frames = int(entry['total_frames'])
        nc.duration = float(entry['duration'])
        session.add(nc)

    # TCP Conversation now
    for entry in data['tcp_conversations']:
        nc = NetworkConversation()
        nc.experiment_id = experiment.id
        nc.transport_protocol = 'tcp'
        nc.src_addr = str(entry['src_addr'])
        nc.src_port = int(entry['src_port'])
        nc.dst_addr = str(format_ip(entry['dst_ip']))
        nc.dst_host = ip_hosts.get(format_ip(str(entry['dst_ip'])))
        nc.dst_port = int(entry['dst_port'])
        nc.rx_bytes = int(entry['rx_bytes'])
        nc.tx_bytes = int(entry['tx_bytes'])
        nc.rx_frames = int(entry['rx_frames'])
        nc.tx_frames = int(entry['tx_frames'])
        nc.total_frames = int(entry['total_frames'])
        nc.duration = float(entry['duration'])
        session.add(nc)


def process_http_requests(data, experiment, session, ip_hosts, hosts_ip):
    for key in data['http_requests']:
        for entry in data['http_requests'][key]['paths']:
            req = HttpRequest()
            req.experiment_id = experiment.id
            req.host = str(key)
            req.path = str(entry['path'])
            req.fullpath=str(key)+"/"+str(entry['path'])
            req.number = int(entry['rate'])
            session.add(req)


def process_https_requests(data, experiment, session):
    for r in data['https_requests']:
        req = HttpsRequest()
        req.experiment_id = experiment.id
        req.host = r['host']
        req.hostname = r['hostname']
        req.port = r['port']
        req.path = r['path']
        req.fullpath = r['fullpath']
        req.scheme = r['scheme']
        req.method = r['method']
        req.content = r['content']
        req.first_line_format = r['first_line_format']
        req.http_version = r['http_version']
        req.timestamp_start = r['timestamp_start']
        req.timestamp_end = r['timestamp_end']
        session.add(req)


def process_http_downlaods(data, experiment, session, ip_hosts, hosts_ip):
    # There is a tool in the tcp reassembly process that otuputs IPs with leading zeroes. So we need to
    # be careful when performing the lookup in the ip_hosts table, because the key may be formatted differently.
    for entry in data['downloads']:
        dw = HttpDownload()
        dw.experiment_id = experiment.id
        dw.sha1 = str(entry['sha1']).lower()
        dw.md5 = str(entry['md5']).lower()
        dw.fuzzy = str(entry['fuzzy']).lower()
        dw.size = int(entry['size'])
        dw.mime = str(entry['mime_type'])
        dw.parent_archive = str(entry['parent_hash'])
        dw.nested_level = int(entry['nseting_level'])  # Note this is a Typo, but we also need to update the synthetizer to be consistent with this.

        # Format the ip so we avoid trailing zeroes
        src_ip = format_ip(entry['source_ip'])
        dw.source_ip = src_ip
        dw.source_port = int(entry['source_port'])
        dw.source_host = ip_hosts.get(src_ip)
        session.add(dw)


def process_https_downlaods(data, experiment, session):
    for e in data['https_downloads']:
        dw = HttpsDownload()
        dw.experiment_id = experiment.id
        dw.sha1 = e['sha1']
        dw.md5 = e['md5']
        dw.fuzzy = e['fuzzy']
        dw.size = e['size']
        dw.status_code = e['status_code']
        dw.method = e['method']
        dw.parent_archive = e['parent_archive']
        dw.nested_level = e['nest_level']
        dw.host = e['host']
        dw.hostname = e['hostname']
        dw.port = e['port']
        dw.path = e['path']
        dw.fullpath = e['fullpath']
        dw.scheme = e['scheme']
        dw.mime = e['mime']
        session.add(dw)


def process_registry(experiment, root, session):
    logging.info("Processing Registry modifications for experiment id %d" % experiment.id)

    result = root.find("Result")

    new_keys = result.findall("RegistryAccess/NewKeys/Key")
    for key in new_keys:
        # Add the key item itself: it is a row containing info about only the key
        fullpath = key.get("Path")

        tmp = RegistryChanges()
        # The following 2 columns compose the PK
        tmp.experiment_id = experiment.id
        tmp.full_path = fullpath

        # Populate only the key path and leave the other values to NULL
        tmp.key_path = key.get("Path")
        tmp.key_value_name = None
        tmp.key_value_value = None
        tmp.key_old_value_value = None
        tmp.is_new = True
        tmp.is_modified = False
        tmp.is_deleted = False

        session.merge(tmp)

        logging.debug("Detected new key %s " % key.get("Path"))

        # Now each new key might have a key-value pair, plus possible sub-keys
        key_val = key.findall("Values/KeyValue")
        for kv in key_val:
            name = kv.find("Name").text
            value = kv.find("Value").text

            fullpath=key.get("Path")+"\\"+name

            tmp = RegistryChanges()
            # The following 2 columns compose the PK
            tmp.experiment_id = experiment.id
            tmp.full_path = fullpath

            # Populate only the key path and leave the other values to NULL
            tmp.key_path = key.get("Path")
            tmp.key_value_name = name
            tmp.key_value_value = value
            tmp.key_old_value_value = None
            tmp.is_new = True
            tmp.is_modified = False
            tmp.is_deleted = False

            session.merge(tmp)
        #TODO: subkeys!

    # Modified keys...
    edited_keys = result.findall("RegistryAccess/EditedKeys/Key")
    for key in edited_keys:
        # Some if a new key is added to an existing key, the existing key will be marked as edited but will
        # contain no name-values.


        tmp = RegistryChanges()
        # The following 2 columns compose the PK
        tmp.experiment_id = experiment.id
        tmp.full_path = key.get("Path")
        tmp.is_new = False
        tmp.is_modified = True
        tmp.is_deleted = False

        # Populate only the key path and leave the other values to NULL
        tmp.key_path = key.get("Path")
        tmp.key_value_name = None
        tmp.key_value_value = None
        tmp.key_old_value_value = None
        tmp.is_modified = True

        session.merge(tmp)
        logging.debug("Detected edited key %s " % key.get("Path"))

        # Now handle the edited values
        e_kvs = key.findall("EditedValues/KeyValue")
        for kv in e_kvs:
            name = kv.find("Name").text
            old_value = kv.find("OriginalValue").text
            new_value = kv.find("NewValue").text

            fullpath = key.get("Path")+"\\"+name

            tmp = RegistryChanges()

            # The following 2 columns compose the PK
            tmp.experiment_id = experiment.id
            tmp.full_path = key.get("Path")+"\\"+name
            tmp.is_new = False
            tmp.is_modified = True
            tmp.is_deleted = False

            # Populate only the key path and leave the other values to NULL
            tmp.key_path = key.get("Path")
            tmp.key_value_name = name
            tmp.key_value_value = new_value
            tmp.key_old_value_value = old_value
            tmp.is_modified = True

            session.merge(tmp)

    # Deleted keys
    deleted_keys = result.findall("RegistryAccess/DeletedKeys/Key")
    for key in deleted_keys:
        # A deleted key contains the path of the key itself and all the previous value-names contained.

        tmp = RegistryChanges()
        # The following 2 columns compose the PK
        tmp.experiment_id = experiment.id
        tmp.full_path = key.get("Path")
        tmp.is_new = False
        tmp.is_modified = True
        tmp.is_deleted = True

        # Populate only the key path and leave the other values to NULL
        tmp.key_path = key.get("Path")
        tmp.key_value_name = None
        tmp.key_value_value = None
        tmp.key_old_value_value = None
        tmp.is_deleted = True
        tmp.is_modified = True

        session.merge(tmp)

        logging.debug("Detected deleted key %s " % key.get("Path"))

        # Now handle the deleted sub values
        d_kvs = key.findall("PreviousValues/KeyValue")
        for kv in d_kvs:
            name = kv.find("Name").text
            old_value = kv.find("Value").text

            fullpath = key.get("Path")+"\\"+name

            tmp = RegistryChanges()

            # The following 2 columns compose the PK
            tmp.experiment_id = experiment.id
            tmp.full_path = fullpath
            tmp.is_new = False
            tmp.is_modified = True
            tmp.is_deleted = True

            # Populate only the key path and leave the other values to NULL
            tmp.key_path = key.get("Path")
            tmp.key_value_name = name
            tmp.key_value_value = None  # The new value is none because the key has been deleted.
            tmp.key_old_value_value = old_value
            tmp.is_modified = True
            tmp.is_deleted = True

            session.merge(tmp)


def format_ip(ip_str):
    if ip_str is None:
        raise Exception("Invalid ip provided: %s" % ip_str)

    # Purge ipv4
    # IPv4: divide the ip string into octets
    parts = str(ip_str).split('.')
    if len(parts) == 4:
        octests = []
        for part in parts:
            octests.append(int(part.strip()))

        return "%d.%d.%d.%d" % (octests[0],octests[1],octests[2],octests[3])

    # Purge ipv6
    if ':' in str(ip_str):
        return str(ipaddress.ip_address(unicode(ip_str)))

    # Otherwise we do not recognize this object
    raise Exception("Invalid ip address %s" % ip_str)


def expander_process(q):
    #FORMAT = "%(asctime)s %(levelname)s %(processName)s %(message)s"
    #logging.basicConfig(format=FORMAT)

    #for job in iter(q.get, None): # Replace `None` as you need.
    #    logging.info("JOB: %d" % job)

    exp_id = q.get()
    while exp_id != "STOP":
        try:
            procname = current_process().name
            logging.info("%s: Expanding experiment id %d." % (procname, exp_id))
            expand_report(exp_id)
        except Exception as e:
            logging.exception("Error when extracting experiment id %d" % exp_id)

        exp_id = q.get()

    exit(0)


if __name__ == "__main__":
    # Create a queue for dispatching tasks to processes
    q = Queue()

    exp_ids = []
    # Get all the work that we can process right now without locking the db
    session=sessionmaker()
    exps = session.query(Experiment).filter(Experiment.processed==False, Experiment.result=='success').all()
    for e in exps:
        exp_ids.append(e.id)
    session.close()

    # Start filling the queue
    for e in exp_ids:
        q.put(e)
        #logging.info("Expanding experiment id %d." % e)
        #expand_report(e)

    logging.info("There are %d experiments ready to be expanded." % len(exp_ids))

    #TODO: add a queue end marker and join processes.
    for i in range(0,PROC_GRADE):
        q.put("STOP")

    # Allocate consumer processes & start them
    processes = []
    for i in range(0,PROC_GRADE):
        p = Process(target=expander_process, name="EXPANDER_PROC_%d"%i, args=(q,))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()
