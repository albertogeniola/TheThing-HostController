from abc import ABCMeta, abstractmethod
import re
from enum import Enum

__author__ = 'Alberto Geniola'

NETLOG_NAME = 'netlog.pcap'
HTTPS_NETLOG_NAME = 'netlog_https.pcap'


class MachineState(Enum):
    # We have no clue.
    unknown = 0

    # Machine is not running and can be started.
    stopped = 1

    # Machine is online, running.
    running = 2

    # Some error has happened on the machine.
    error = 10

    # Machine seems is busy at the moment (snapshotting, restoring, etc).
    busy = 11


class IGuest:
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_manager(self):
        """
        Gets the manager in charge of this machine
        :return: the IMachineManager administrating this machine
        """
        pass
        return  # type: IGuest

    @abstractmethod
    def get_mac(self):
        """
        Gets the mac of this machine
        :return: the mac address of this machine
        """
        pass
        return  # type: MacAddress.MacAddress

    def __str__(self):
        return "Machine %s, manager %s" % (self.get_mac(), self.get_manager().get_name())  # type: str


class IGuestManager:
    """
    This class represents a generic GuestManager. A guest manager is in charge of
    handling machine life-cycle. Generic operations like Reboot/Boot/Shutdown must be
    supported as well as Network sniffing.
    """
    __metaclass__ = ABCMeta

    @classmethod
    def __init__(cls):
        pass

    @abstractmethod
    def set_machine_status_handler(self, handler):
        """
        Registers a status handler which should be notified by the manager every time a machine managed by this handler
        changes its status.
        :return:
        """
        pass

    @abstractmethod
    def publish_agents(self, agents_dict):
        """
        Used to publish client agents on the sniffer, so that clients can automatically retrieve them at startup
        :return:
        """
        pass

    @abstractmethod
    def prepare(self):
        """
        Used for initialization of manager, if needed. In some cases, it is used to clone/create VMs if there is no
        VM to be used.
        :return:
        """
        pass

    @abstractmethod
    def get_guest_by_mac(self,
                   mac  # type: MacAddress
                   ):
        pass
        return  # type: IGuest

    @abstractmethod
    def create_guest(self):
        """
        Clones the base machine and register the new clone as new_machine_name, adding it to the
        queue of machines handled by this manager.
        :return: the created machine
        """
        pass
        return  # type: IGuest

    @abstractmethod
    def delete_guest(self,
                     guest  # type: IGuest
                    ):
        """
        Removes the machines from the manager and deallocates its resources.
        :return:
        """
        pass

    def get_netlog(self,
                   machine,  # type: IGuest
                   directory  # type:str
                   ):
        """
        Given a machine, will retrieve the associated network log, assuming there is a valid sniffer instance for 
        that machine. 
        :param machine:  
        :param directory: 
        :return: 
        """
        pass

    @abstractmethod
    def start_network_sniffing(self,
                               guest  # type: IGuest
                               ):
        """
        This method takes care of starting the network monitoring.
        :param guest:
        :return:
        """
        pass

    @abstractmethod
    def stop_network_sniffing(self,
                              guest  # type: IGuest
                              ):
        """
        This method takes care of stopping the network monitoring for the given guest.
        :param guest:
        :return:
        """
        pass

    @abstractmethod
    def start_guest(self,
                    guest  # type: IGuest
                    ):
        """
        Given the machine id or reference, starts it if it is stopped/not running
        :param guest:
        :return:
        """
        pass

    @abstractmethod
    def get_machine_state(self,
                          guest  # type: IGuest
                          ):
        """
        Returns the state of the machine. This can either be RUNNING/STOPPED. Check :type: MachineState
        :param guest:
        :return:
        """
        pass
        return  # type: MachineState

    @abstractmethod
    def stop_guest(self,
                   guest  # type: IGuest
                   ):
        """
        Given the guest, stops it if it is running
        :param guest:
        :return:
        """
        pass

    @abstractmethod
    def revert_guest(self,
                     guest  # type: IGuest
                     ):
        """
        Given the machine id, reverts it, even if it is running.
        :param guest:
        :return:
        """
        pass

    @abstractmethod
    def get_name(self):
        """
        Returns the name of this manager
        :return:
        """
        pass
        return  # type: str

    @abstractmethod
    def list_guests(self):
        """
        Returns the list of all guests handled by this manager
        :return:
        """
        pass
        return  # type: [IGuest]
