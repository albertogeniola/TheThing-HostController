import subprocess
import os

EXECFILE = "ssdeep.exe"

path = os.path.dirname(os.path.realpath(__file__))
executable = os.path.join(path, EXECFILE)


def _fuzzy_hash_from_file(fullpath):
    # Use subprocess in order to calculate the fuzzy hashing
    p = subprocess.Popen([executable, '-s', fullpath], stdout=subprocess.PIPE)
    out, err = p.communicate()
    if out is None:
        return ''
    lines = out.split('\r\n')
    if len(lines) > 2:
        l = lines[1]
        l.strip()
        return l.split(',')[0]
    else:
        return ''
