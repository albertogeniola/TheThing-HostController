import threading
import logging
import os
# For debugging purposes, configure the locking log.
DEBUG=False
locklog = logging.getLogger("locking")
dirname = os.getcwd()
logDest = os.path.join(dirname, "locking.log")
hdlr = logging.FileHandler(logDest)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
locklog.addHandler(hdlr)
locklog.setLevel(logging.DEBUG)


class LogLock(object):
    def __init__(self, name):
        self.name = str(name)
        self.lock = threading.RLock()

    def acquire(self, blocking=True):
        if DEBUG:
            locklog.debug("{0:x} Trying to acquire {1} lock".format(id(self), self.name))
        ret = self.lock.acquire(blocking)
        if DEBUG:
            if ret == True:
                locklog.debug("{0:x} Acquired {1} lock".format(id(self), self.name))
            else:
                locklog.debug("{0:x} Non-blocking aquire of {1} lock failed".format(id(self), self.name))

        return ret

    def release(self):
        if DEBUG:
            locklog.debug("{0:x} Releasing {1} lock".format(id(self), self.name))
        self.lock.release()
        if DEBUG:
            locklog.debug("{0:x} Released {1} lock".format(id(self), self.name))

    def __enter__(self):
        self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()
        return False    # Do not swallow exceptions