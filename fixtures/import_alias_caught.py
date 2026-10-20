"""`from os import system` used to slip past a sink-name check. The
reviewer now resolves imports statically, so this is caught (REJECT).
Found by red-teaming the detector against its own thesis."""
from os import system


def ping(host):
    system("ping -c 1 " + host)   # resolved back to os.system, flagged CWE-78
