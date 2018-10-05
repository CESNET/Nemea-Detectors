#!/usr/bin/env python3

# Aggregation of alerts from all blacklist detectors (IP, URL, DNS).
# Output of IP detector is pre-aggregated with standard UniRec aggregator,
# output of URL and DNS detectors is roughly the same
# Records are being aggregated 1-N in time window, where 1 is the blacklisted entry.

from threading import Timer
from threading import Lock
import sys, os
import signal
import json
import pytrap

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option("-t", "--time", dest="time", type="float",
                  help="Length of time interval in which alerts are aggregated.", metavar="MINUTES", default=5)

lock = Lock()

# All ports higher than MINSRCPORT are considered as dynamic/private;
# therefore, let's put lower ports into IDEA messages.
MINSRCPORT=30000

# Maximum number of dest. IPs in an event record (if there are more, they are trimmed)
MAX_DST_IPS_PER_EVENT = 1000


def signal_h(signal, f):
    global trap
    trap.terminate()


class RepeatedTimer:
    def __init__(self, interval, function):
        self._timer = None
        self.function = function
        self.interval = interval
        self.is_running = False
        self.start()

    def _run(self):
        global lock
        lock.acquire()
        self.is_running = False
        self.start()
        self.function()
        lock.release()

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


# Parse remaining command-line arguments
options, args = parser.parse_args()


# Initialize module
trap = pytrap.TrapCtx()
trap.init(sys.argv, 3, 3)

signal.signal(signal.SIGINT, signal_h)

# exact output match of pre-aggregated ipblacklistfilter
ip_urfmt = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST," + \
           "time TIME_FIRST,time TIME_LAST,uint32 COUNT,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL"

