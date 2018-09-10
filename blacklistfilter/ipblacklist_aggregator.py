#!/usr/bin/env python3

# Aggregation of alerts from ipblacklist detector.
# It receives UniRec and aggregates addresses 1-N in time window.

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


class RepeatedTimer(object):
    def __init__(self, interval, function):
        self._timer     = None
        self.function   = function
        self.interval   = interval
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
(options, args) = parser.parse_args()

def signal_h(signal, f):
    global trap
    trap.terminate()

# Initialize module
trap = pytrap.TrapCtx()
trap.init(sys.argv, 1, 1)

signal.signal(signal.SIGINT, signal_h)


# exact output match of ipblacklistfilter
urfmt = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST," + \
        "time TIME_FIRST,time TIME_LAST,uint32 COUNT,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL"

UR_Input = pytrap.UnirecTemplate(urfmt)

# Set the template as required format
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, urfmt)

# Set output format and disable output buffering
trap.setDataFmt(0, pytrap.FMT_JSON, "aggregated_ipblacklist")
trap.ifcctl(0, False, pytrap.CTL_BUFFERSWITCH, 0)


# Send aggregated alerts by RepeatedTimer
def sendEvents():
    global eventList
    for key in eventList:
        event = eventList[key]
        try:
            # Send data to output interface
            trap.send(bytearray(json.dumps(event), "utf-8"))
        except pytrap.Terminated:
            print("Terminated TRAP.")
            break

    eventList = {}


def storeEvent():
    global UR_Input

    # Set key (blacklisted address and protocol)
    if UR_Input.SRC_BLACKLIST:
        key = (UR_Input.SRC_IP, UR_Input.PROTOCOL)
    else:
        key = (UR_Input.DST_IP, UR_Input.PROTOCOL)

    if key in eventList:
        # Update the event
        event = eventList[key]

        # Update ports of the source (of trouble) and target IPs
        source_ports = set(event["source_ports"])
        targets = set(event["targets"])
        if UR_Input.SRC_BLACKLIST:
            source_ports.add(UR_Input.SRC_PORT)
            targets.add(str(UR_Input.DST_IP))
        else:
            source_ports.add(UR_Input.DST_PORT)
            targets.add(str(UR_Input.SRC_IP))
        event["source_ports"] = list(source_ports)
        event["targets"] = list(targets)

        event["ts_first"] = min(event["ts_first"], float(UR_Input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(UR_Input.TIME_LAST))

        if UR_Input.SRC_BLACKLIST:
            event["src_sent_bytes"] += UR_Input.BYTES
            event["src_sent_flows"] += UR_Input.COUNT
            event["src_sent_packets"] += UR_Input.PACKETS
        else:
            event["tgt_sent_bytes"] += UR_Input.BYTES
            event["tgt_sent_flows"] += UR_Input.COUNT
            event["tgt_sent_packets"] += UR_Input.PACKETS

    else:
        # Insert new event
        event = {
            # Every source/src means source of trouble (the blacklisted address)
            "source": str(UR_Input.SRC_IP) if UR_Input.SRC_BLACKLIST > 0  else str(UR_Input.DST_IP),
            "targets": [str(UR_Input.SRC_IP)] if UR_Input.SRC_BLACKLIST == 0 else [str(UR_Input.DST_IP)],
            "source_ports" : [UR_Input.SRC_PORT] if UR_Input.SRC_BLACKLIST > 0 else [UR_Input.DST_PORT],
            "ts_first": float(UR_Input.TIME_FIRST),
            "ts_last": float(UR_Input.TIME_LAST),
            "protocol": UR_Input.PROTOCOL,
            "src_sent_bytes" : UR_Input.BYTES if UR_Input.SRC_BLACKLIST else 0,
            "src_sent_flows" : UR_Input.COUNT if UR_Input.SRC_BLACKLIST else 0,
            "src_sent_packets" : UR_Input.PACKETS if UR_Input.SRC_BLACKLIST else 0,
            "tgt_sent_bytes" : UR_Input.BYTES if UR_Input.DST_BLACKLIST else 0,
            "tgt_sent_flows" : UR_Input.COUNT if UR_Input.DST_BLACKLIST else 0,
            "tgt_sent_packets" : UR_Input.PACKETS if UR_Input.DST_BLACKLIST else 0,
            "blacklist_bmp": UR_Input.SRC_BLACKLIST if UR_Input.SRC_BLACKLIST else UR_Input.DST_BLACKLIST
        }

        eventList[key] = event


print("starting timer for sending...")
rt = RepeatedTimer(int(options.time * 60), sendEvents)

# Global list of events
eventList = {}

while True:
    # Read data from input interface
    try:
        data = trap.recv()
    except pytrap.FormatMismatch:
        print("Error: output and input interfaces data format or data specifier mismatch")
        break
    except pytrap.FormatChanged as e:
        # Get data format from negotiation and set it for output IFC
        (fmttype, fmtspec) = trap.getDataFmt(0)
        # Update UniRec template
        UR_Input = pytrap.UnirecTemplate(fmtspec)

        # Store data from the exception
        data = e.data
    except pytrap.Terminated:
        print("Terminated TRAP.")
        break
    except pytrap.TrapError:
        break

    # Check for "end-of-stream" record
    if len(data) <= 1:
        break

    lock.acquire()

    # Set data for access using attributes
    UR_Input.setData(data)

    storeEvent()

    lock.release()


rt.stop()
sendEvents()
trap.sendFlush()
