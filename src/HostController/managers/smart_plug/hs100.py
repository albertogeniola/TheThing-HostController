import time
import socket
import json


TIMEOUT = 0.25
RECV_BUFFER = 2048


class SwitchException(Exception):
    pass


class HS1XX:
    ip = None
    port = 9999
    socket = None
    
    def __init__(self, ip):
        self.ip = ip
        self.connected = False
        
        # status
        self.enable = False
        self.error = False

    def send_cmd(self, cmd):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.ip, self.port))
            sock.send(self.encrypt(cmd))
            data = sock.recv(RECV_BUFFER)
            sock.close()
            data = self.decrypt(data[4:])
            return json.loads(data)
        except socket.error:
            return None

    def _switch(self, on_or_off):
        cmd = '{"system":{"set_relay_state":{"state":%i}}}' % int(on_or_off)
        data = self.send_cmd(cmd)
        if data is None:
            raise SwitchException("Could not send data to the smart plug")
        result = data['system']['set_relay_state']
        err_code = result['err_code']
        return err_code

    def switch_off(self):
        ret_code = self._switch(0)
        if ret_code != 0:
            # We failed. This is a hard error. Caller should take us into account
            raise SwitchException("Cannot operate the remote switch.")
            
    def switch_on(self):
        ret_code = self._switch(1)
        if ret_code != 0:
            # We failed. This is a hard error. Caller should take us into account
            raise SwitchException("Cannot operate the remote switch.")

    def get_status(self):
        cmd = '{"system": {"get_sysinfo": null}}'
        data = self.send_cmd(cmd)
        if data is None:
            raise SwitchException("Remote plug did not provide any data.")
        result = data['system']['get_sysinfo']
        status = result['relay_state']
        return status

    # source: https://github.com/softScheck/tplink-smartplug
    # Encryption and Decryption of TP-Link Smart Home Protocol
    # XOR Autokey Cipher with starting key = 171
    def encrypt(self, string):
        key = 171
        result = "\0\0\0\0"
        for i in string:
            a = key ^ ord(i)
            key = a
            result += chr(a)
        return result

    def decrypt(self, string):
        key = 171
        result = ""
        for i in string:
            a = key ^ ord(i)
            key = ord(i)
            result += chr(a)
        return result
