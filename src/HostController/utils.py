import os
import re
import socket
from HostController.miscellaneus import MacAddress
from HostController.settings import CFG
import logging
from logging import FileHandler


def validate_network_conf(
        conf  # type:dict
):
    """
    Checks if the networkconf dictionary passed as argument is formally correct
    :param conf:
    :return:
    """

    if 'guest_ip' not in conf:
        return False

    if 'default_gw' not in conf:
        return False

    if 'hc_ip' not in conf:
        return False

    if 'hc_port' not in conf:
        return False

    return True


def _get_output_report_dir(
        experiment_id  # type:int
):
    """
    Given a experiment_id, constructs the report destination folder path so that we can ensure consistency when
    dealing with paths.The path is built using path info provided into the configuration file.
    :param experiment_id:
    :return:
    """
    # Just concatenate output report path with experiment_id being its directory
    root = CFG.output_report_dir
    path = os.path.join(root,str(experiment_id))
    if not os.path.isdir(path):
        os.mkdir(path)
    return path


def build_output_report_fullpath(
        experiment_id  # type: int
):
    """
    Constructs the full report path given a experiment_id. The path is built using path info provided into the configuration
    file.
    :param experiment_id:
    :return:
    """
    return os.path.join(_get_output_report_dir(experiment_id), "report.xml")


def validate_mac(mac):
    """
    Simply checks if a given input string is a valid mac address
    :param mac:
    :return:
    """
    if mac is None:
        return False

    try:
        m = MacAddress.MacAddress(mac)
        return True
    except:
        return False


def find_route_to_host(addr):
    """
    This is a trick used to retrieve the source IP address to be used when connecting to a specific host.
    :param host:
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sq = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sq.connect(addr)
    return sq.getsockname()[0]
