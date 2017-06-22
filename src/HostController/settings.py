__author__ = 'Alberto Geniola'
from os.path import isdir, exists, isfile
import logging
import os
import ConfigParser
from urlparse import urlparse
import json
import re
from logging import FileHandler

CONF_FILE = os.path.join(os.path.dirname(__file__), "controller.conf")
config = None
CFG = None

DEFAULTS={'vbox_url':None,'vbox_user':None,'vbox_password':None}


if CFG is None:

    class Configuration(object):
        pass

    if not exists(CONF_FILE):
        raise Exception("Configuration file %s not found in path." % CONF_FILE)

    logging.info("Loading settings from %s." % CONF_FILE)
    config = ConfigParser.SafeConfigParser(DEFAULTS)  # If no value is found, null is used.
    config.read(CONF_FILE)

    CFG = Configuration()

    # Parsing general section. This is mandatory
    CFG.logs_directory = str(config.get("general", "logs_directory"))
    if not isdir(CFG.logs_directory):
        os.makedirs(CFG.logs_directory)

    CFG.log_level = str(config.get("general", "log_level"))
    CFG.db_connection_string = str(config.get("general", "db_connection_string"))
    CFG.bind_host_address = str(config.get("general", "bind_host_address"))
    CFG.bind_host_port = config.getint("general", "bind_host_port")
    CFG.network_analyzer_ip = str(config.get("general", "network_analyzer_ip"))
    CFG.network_analyzer_port = config.getint("general", "network_analyzer_port")
    CFG.output_report_dir = config.get("general", "output_report_dir")
    CFG.host_controller_id = config.getint("general", "host_controller_id")
    if not isdir(CFG.output_report_dir):
        os.makedirs(CFG.output_report_dir)

    CFG.vm_run_timeout = config.getint("general", "vm_run_timeout")
    CFG.enable_analyzer = config.getboolean("general", "enable_analyzer")
    CFG.installers_base_dir = config.get("general","installers_base_dir")
    CFG.agents_dir = config.get("general", "agents_dir")
    if not isdir(CFG.agents_dir):
        os.makedirs(CFG.agents_dir)

    CFG.managers = []
    managers = str(config.get("general","managers"))
    managers = managers.split(",")
    for mgr in managers:
        m = mgr.lower()
        if m.lower() in ('vbox', 'baremetal', 'openstack'):
            CFG.managers.append(m)
        else:
            raise ValueError("Invalid manager specified <%s>." % m)

    if "vbox" in CFG.managers:
        if not config.has_section("vbox"):
            raise ValueError("VBOX manager has been specified as manager into the configuration file, but its "
                             "configuration section is missing. Please add the [vbox] section into the settings file.")

        # Parsing VBox Section
        CFG.vbox_workers = config.getint("vbox", "vbox_workers")
        if CFG.vbox_workers < 0:
            raise ValueError("vbox_workers paramenter must be a positive integer.")

        CFG.vbox_base_disk_path = config.get("vbox", "vbox_base_disk_path")
        if not exists(CFG.vbox_base_disk_path):
            raise ValueError("Path %s does not exist on this machine." % CFG.vbox_base_disk_path)

        CFG.vbox_diff_disk_dir = config.get("vbox", "vbox_diff_disk_dir")
        if not exists(CFG.vbox_diff_disk_dir):
            os.makedirs(CFG.vbox_diff_disk_dir)

        vm_conf = config.get("vbox", "vbox_default_vm_cfg")
        try:
            CFG.vbox_default_vm_cfg = json.loads(vm_conf)
        except ValueError:
            raise ValueError("VBox default VM configuration must be in json format.")

        CFG.vbox_default_group = str(config.get("vbox", "vbox_default_group"))
        CFG.vbox_url = config.get("vbox", "vbox_url")
        CFG.vbox_user = config.get("vbox", "vbox_user")
        CFG.vbox_password = config.get("vbox", "vbox_password")

        CFG.vbox_sniffer_name = config.get("vbox", "vbox_sniffer_name")
        CFG.sniffer_base_disk = str(config.get("vbox", "sniffer_base_disk"))
        try:
            CFG.vbox_sniffer_cfg = json.loads(config.get("vbox", "vbox_sniffer_cfg"))
        except ValueError:
            raise ValueError("VBox sniffer VM configuration must be in json format.")

        CFG.vbox_host_only_interface_name=config.get("vbox", "vbox_host_only_interface_name")
        CFG.vbox_host_only_interface_ip=config.get("vbox", "vbox_host_only_interface_ip")
        CFG.vbox_host_only_interface_mask=config.get("vbox", "vbox_host_only_interface_mask")
        CFG.vbox_wan_nat_name=config.get("vbox","vbox_wan_nat_name")
        CFG.vbox_sandboxes_internal_nat_name=config.get("vbox","vbox_sandboxes_internal_nat_name")
        CFG.vbox_wan_nat_cidr=config.get("vbox","vbox_wan_nat_cidr")
        CFG.vbox_sniffer_ip=config.get("vbox","vbox_sniffer_ip")
        CFG.vbox_sniffer_port=config.getint("vbox","vbox_sniffer_port")
        CFG.vbox_intranet_network_name=config.get("vbox","vbox_intranet_network_name")

    if config.has_section("openstack"):
        CFG.os_workers = config.getint("openstack","os_workers")
        CFG.os_auth_url = str(config.get("openstack","os_auth_url"))
        CFG.os_project_name = str(config.get("openstack","os_project_name"))
        CFG.os_username = str(config.get("openstack","os_username"))
        CFG.os_password = str(config.get("openstack","os_password"))
        CFG.os_sniffer_image_name = str(config.get("openstack","os_sniffer_image_name"))
        CFG.os_sniffer_instance_name = str(config.get("openstack", "os_sniffer_instance_name"))
        CFG.os_guest_image_name = str(config.get("openstack","os_guest_image_name"))
        CFG.os_public_network_name = str(config.get("openstack","os_public_network_name"))
        CFG.os_sniffer_port = config.getint("openstack", "os_sniffer_port")
        CFG.os_sniffer_sg = str(config.get("openstack","os_sniffer_sg"))
        CFG.os_sniffer_flavor = str(config.get("openstack", "os_sniffer_flavor"))
        CFG.os_guest_flavor = str(config.get("openstack", "os_guest_flavor"))
        CFG.os_guest_security_group = str(config.get("openstack","os_guest_security_group"))
        CFG.os_internal_network_name = str(config.get("openstack","os_internal_network_name"))
        CFG.os_intranet_subnetwork_name = str(config.get("openstack","os_intranet_subnetwork_name"))
        CFG.os_external_hc_ip = str(config.get("openstack","os_external_hc_ip"))
        CFG.os_external_hc_port = config.getint("openstack","os_external_hc_port")
        CFG.os_internal_network_cidr = str(config.get("openstack","os_internal_network_cidr"))
        CFG.os_external_router_name = str(config.get("openstack","os_external_router_name"))

    if config.has_section("baremetal"):
        CFG.baremetal_diff_vhd_folder = str(config.get("baremetal","baremetal_diff_vhd_folder"))
        CFG.baremetal_base_vhd_path = str(config.get("baremetal","baremetal_base_vhd_path"))
        CFG.baremetal_sniffer_url = str(config.get("baremetal", "baremetal_sniffer_url"))
        CFG.baremetal_iscsi_server_ip = str(config.get("baremetal", "baremetal_iscsi_server_ip"))
        CFG.baremetal_machines_conf = str(config.get("baremetal", "baremetal_machines_conf"))
        CFG.baremetal_websrv_host = str(config.get("baremetal", "baremetal_websrv_host"))
        CFG.baremetal_websrv_port = config.getint("baremetal", "baremetal_websrv_port")
        CFG.baremetal_external_hc_ip = str(config.get("baremetal", "baremetal_external_hc_ip"))
        CFG.baremetal_external_hc_port = config.getint("baremetal", "baremetal_external_hc_port")

    # Configure main logger
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.info("Configuration loaded.")
