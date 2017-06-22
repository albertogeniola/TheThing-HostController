from threading import Condition
import pefile
import os
import time


def is_win32(path):
    ok = False
    pe = None
    try:
        pe = pefile.PE(path)
        ok = pe.OPTIONAL_HEADER.Magic == 0x10b and pe.FILE_HEADER.IMAGE_FILE_EXECUTABLE_IMAGE
    except:
        ok = False
    finally:
        if pe is not None:
            pe.close()
            pe.__data__.close()

    return ok


def remove_retry(fname):
    tries = 0
    MAX_TRIES = 10

    while tries < MAX_TRIES:
        try:
            os.remove(fname)
            return True
        except Exception as e:
            tries += 1
            time.sleep(2)
    return False


def is_msi(path):
    try:
        return path.lower().endswith(".msi")
    except:
        return False


class DoneException(Exception):
    pass


class PageProvider(object):
    _cond = Condition()
    _page_count = 1
    _limit = 0
    _done = 0
    _target = 0

    def __init__(self, limit):
        self._limit = limit
        self._target = limit
        self._page_count = 1
        self._done = 0

    def pop_download(self):
        with self._cond:
            # Check if we are finished. If so, return False so the caller understands we are done.
            if self._done == self._target:
                return False

            # Otherwise reserve one download from the list, if available
            while self._limit == 0 and self._done < self._target:
                self._cond.wait()

            if self._done == self._target:
                return False
            else:
                self._limit -= 1
                return True

    def set_done(self):
        with self._cond:
            self._done += 1
            self._cond.notify_all()

    def push_download(self):
        with self._cond:
            self._limit += 1
            self._cond.notify()

    def pop_page(self):
        with self._cond:
            # If we are done, return -1 so the caller can exit
            if self._done == self._target:
                return -1

            # Otherwise increment the page counter and return the new page
            page = self._page_count
            self._page_count += 1

            return page