import re

class MacAddress:
    """
    Wrapper for handling MacAddress. It taks a parameter in the constructor which may be an instance of MacAddress or
    a string. The class will parse the string/mac and will store it in a fixed format. Using this class everywhere in 
    the code will ensure consistency in the MACAddress representation.
    """

    _mac = None

    def __init__(self,
                 mac
                 ):
        # The user is expected to call this method and specify a mac address in a supported syntax.
        # We will try to "sanitize" those here and provide an uniform string representing that mac.
        if mac is None:
            raise Exception("Invalid or unsupported mac address specified.")

        m = mac
        if isinstance(mac, str):
            m = mac
        elif isinstance(mac, MacAddress):
            m = str(mac)
        elif isinstance(mac, unicode):
            m = str(mac)
        else:
            raise ValueError("Invalid mac address specified. Mac address must be either a string or an instance of MACAddress class.")

        m = m.lower()

        if re.match('^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$', m):
            # This mac is ok. Store it with colons
            self._mac = m.replace("-","").replace(":","")
        elif re.match('^[0-9a-f]{12}$', m):
            # This is a mac address with no separators
            self._mac = m
        else:
            raise Exception("Invalid mac address provided: %s" % m)

    def __hash__(self):
        return hash(self._mac)

    def __eq__(self, other):
        if isinstance(other, MacAddress):
            return self._mac == other._mac
        else:
            return self._mac == MacAddress(other)._mac

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self, separator=':'):
        return separator.join(map(''.join, zip(*[iter(self._mac)]*2)))