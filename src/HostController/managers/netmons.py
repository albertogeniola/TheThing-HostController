__author__ = 'Alberto Geniola'
import json
from abc import ABCMeta, abstractmethod
from urlparse import urljoin

import requests

from HostController.settings import CFG
from HostController.miscellaneus import MacAddress

class SnifferAlreadyRunningException(Exception):
    pass


class NetMon:
    __metaclass__ = ABCMeta

    @abstractmethod
    def start(self, mac):
        """
        Starts the network capture to catch all the traffic from/for the given mac address
        specified.
        :param mac: string formatted as XX:XX:XX:XX:XX:XX
        :return: void
        """
        pass

    @abstractmethod
    def stop(self, mac):
        """
        Stops the network capture to catch all the traffic from/for the given mac address
        specified.
        :param mac: string formatted as XX:XX:XX:XX:XX:XX
        :return: void
        """
        pass

    @abstractmethod
    def collect(self, mac, dest_file):
        """
        Downloads the network pcap file collected.
        :param mac: string formatted as XX:XX:XX:XX:XX:XX
        :param dest_file: optional, if set the log will be downloaded to this path
        :return: path of the downloaded pcap file
        """
        pass

    @abstractmethod
    def query_status(self, mac):
        """
        Returns information about the status of the logger
        :param mac: string formatted as XX:XX:XX:XX:XX:XX
        :return: status of the logger
        """
        pass

    @abstractmethod
    def post_agent(self, platform, version, arch, agent_path):
        """
        Publishes agent binaries for a specific OS version.
        :param platform: OS platfomr (Linux, Windows, etc)
        :param version: (Version of OS)
        :param arch: (System architecture: 32/64 bit)
        :param agent_path: Path where to locate the binary to be published
        :return: 
        """
        pass

    @abstractmethod
    def post_hc(self, hc_ext_addr, hc_ext_port):
        """
        Tells to the sniffer how to connect to the HC. Be careful: hc_ext_addr and hc_ext_port must depend on the specific
        network configuration/topology in use. For instance, if there is a NAT in between HC and SNIFFER, the user must
        specify IP/PORT external to the NAT. In some topologies (such the Single Tier), the address and port might collide
        with the ones used by the HC itself.
        :param hc_ext_addr: IP address that will be used by the sniffer to contact the HostController
        :param hc_ext_port: Port that will be used by the sniffer to contact the HostController
        :return: 
        """
        pass


def get_local_ip_routing_to_addr(addr):
    # This is a trick to retrieve the IP address of the interface that will route to ADDR.
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((addr, 80))
        return s.getsockname()[0]
    finally:
        s.close()


class BareNetMon(NetMon):
    # Represents the URI for the webservice
    GET_SNIFFER = "/sniffers/{0}"
    POST_SNIFFER = "/sniffers"
    START_SNIFFER = "/manager/{0}/start"
    STOP_SNIFFER = "/manager/{0}/stop"
    COLLECT_LOG = "/manager/{0}/collect"
    COLLECT_LOG_HTTPS = "/manager/{0}/collect_https"
    COLLECT_ANALYSIS = "/manager/{0}/analyse"
    PUBLISH_AGENT = "/agents/{0}/{1}/{2}"
    PUBLISH_HC_ADDR = "/hc_address"

    _url = None

    def __init__(self, url):
        self._url = url

    def _prepare(self, mac):
        mac = MacAddress.MacAddress(mac)
        data = {"mac": str(mac)
                # The following are not necessary since the HostController will register itself with the sniffer at boot.
                #,"hc_ip": get_local_ip_routing_to_addr(CFG.network_analyzer_ip)
                #,"hc_port": CFG.bind_host_port
                }

        response = requests.post(urljoin(self._url, self.POST_SNIFFER),
                                 data=json.dumps(data))
        if response.status_code != 201:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

        # Ok, sniffer prepared.

    def start(self, mac):
        mac = MacAddress.MacAddress(mac)
        # Check if there already is a sniffer working for this mac
        response = requests.get(urljoin(self._url,
                                        self.GET_SNIFFER.format(mac)))

        # Is there already a sniffer for this traffic?
        if response.status_code == 404:
            # Need to prepare the sniffer
            self._prepare(mac)

        elif response.status_code == 200:
            # Is the sniffer busy?
            data = response.json()
            if data['status'] == 'running':
                # The sniffer is busy now. We can't proceed
                raise SnifferAlreadyRunningException("Sniffer status isn't either prepared nor finished.")
        else:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

        # Let's start the sniffer
        response = requests.get(urljoin(self._url,
                                        self.START_SNIFFER.format(mac)))

        if response.status_code != 200:
            raise Exception("Unexpected result code %d. Check server log for error details." % response.status_code)

        # At this point we can assume the logger is running, hopefully :S

    def stop(self, mac):
        mac = MacAddress.MacAddress(mac)
        response = requests.get(urljoin(self._url, self.STOP_SNIFFER.format(mac)))
        if response.status_code != 200:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

    def collect(self, mac, dest_file):
        mac = MacAddress.MacAddress(mac)
        response = requests.get(urljoin(self._url,self.COLLECT_LOG.format(mac)))
        if response.status_code != 200:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

        # The expected data is in binary format, representing the log catch by the sniffer in pcap format.
        with open(dest_file, 'wb') as f:
            f.write(response.content)

        return dest_file

    def collect_https(self, mac, dest_file):
        mac = MacAddress.MacAddress(mac)
        response = requests.get(urljoin(self._url,self.COLLECT_LOG_HTTPS.format(mac)))
        if response.status_code != 200:
            raise Exception("Unexpected return code %d. Check server log https for error details." % response.status_code)

        # The expected data is in binary format, representing the log catch by the sniffer in pcap format.
        with open(dest_file, 'wb') as f:
            f.write(response.content)

        return dest_file

    def analyse(self, mac, dest_file):
        mac = MacAddress.MacAddress(mac)
        response = requests.get(urljoin(self._url,self.COLLECT_ANALYSIS.format(mac)))
        if response.status_code != 200:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

        # The expected data is in binary format, representing the log catch by the sniffer in pcap format.
        with open(dest_file, 'wb') as f:
            f.write(response.content)

        return dest_file

    def query_status(self, mac):
        """
        Returns the status of the current sniffer. If no sniffer is found None is returned.
        :param mac:
        :return:
        """
        mac = MacAddress.MacAddress(mac)
        response = requests.get(urljoin(self._url,
                                        self.GET_SNIFFER.format(mac)))
        if response.status_code == 404:
            return None
        if response.status_code != 200:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

        return response.json()['status']

    def post_agent(self, platform, version, arch, agent_path):
        """
        Posts the latest version of sandbox agent available for platform osver, located at agent_path.
        :param osver: 
        :param agent_path: 
        :return: 
        """
        url = urljoin(self._url, self.PUBLISH_AGENT.format(platform, version, arch))
        files={'agent_file': open(agent_path, 'rb')}
        response = requests.post(url, files=files)
        if response.status_code != 201:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)

    def post_hc(self, hc_ext_addr, hc_ext_port):
        """
        Posts the network information needed to the sniffer to reach the HOST CONTROLLER. 
        :param hc_ext_addr: 
        :param hc_ext_port: 
        :return: 
        """
        url = urljoin(self._url, self.PUBLISH_HC_ADDR)
        data = {"address": hc_ext_addr, "port": hc_ext_port}
        response = requests.post(url, json=data)
        if response.status_code != 200:
            raise Exception("Unexpected return code %d. Check server log for error details." % response.status_code)