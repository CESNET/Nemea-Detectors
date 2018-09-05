#!/usr/bin/env python3

# Aggregation of alerts from ipblacklist detector.
# It receives alerts and aggregates them into time window.
# The purpose is to group addresses 1-N (C&C server and its botnet).
# Aggregation is done either by SRC_IP or DST_IP (the blacklisted address is the key)

from threading import Timer
from threading import Lock
import sys, os
import signal
import json
import pytrap

MAX_IPS_PER_EVENT = 1000

from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option("-t", "--time", dest="time", type="float",
                  help="Length of time interval in which alerts are aggregated.", metavar="MINUTES", default=5)

lock = Lock()


# Timer
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
urfmt = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST, " + \
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
            # To avoid too long messages, split the event if there are more than 1000 IPs
            if len(event["targets"]) > MAX_IPS_PER_EVENT:
                all_ip_port_pairs = list(event["targets"].items())
                all_ip_port_pairs.sort()
                while all_ip_port_pairs:
                    event_copy = event.copy()
                    event_copy["targets"] = dict(all_ip_port_pairs[:MAX_IPS_PER_EVENT])
                    all_ip_port_pairs = all_ip_port_pairs[MAX_IPS_PER_EVENT:]
                    trap.send(bytearray(json.dumps(event_copy), "utf-8"))

            else:
                # Send data to output interface
                trap.send(bytearray(json.dumps(event), "utf-8"))
        except pytrap.Terminated:
            print("Terminated TRAP.")
            break

    eventList = {}


def storeEvent():
    global UR_Input

    # Set bi-flow key ("lower" address first)
    if str(UR_Input.SRC_IP) < str(UR_Input.DST_IP):
        key = (UR_Input.SRC_IP, UR_Input.DST_IP, UR_Input.PROTOCOL)
    else:
        key = (UR_Input.DST_IP, UR_Input.SRC_IP, UR_Input.PROTOCOL)

    if key in eventList:
        # Update the event
        event = eventList[key]

        if UR_Input.SRC_BLACKLIST:
            event["target"][str(UR_Input.DST_IP)] = UR_Input.DST_PORT
        else:
            event["target"][str(UR_Input.SRC_IP)] = UR_Input.SRC_PORT

        event["ts_first"] = min(event["ts_first"], float(UR_Input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(UR_Input.TIME_LAST))
        event["byte_count"] += UR_Input.BYTES
        event["packet_count"] += UR_Input.PACKETS
        event["event_scale"] = max(event["event_scale"], int(UR_Input.EVENT_SCALE))     # TODO: max?

    else:
        # Insert new event
        event = {
            # Every source/src means source of trouble (the blacklisted address)
            "source": str(UR_Input.SRC_IP) if UR_Input.SRC_BLACKLIST > 0  else str(UR_Input.DST_IP),
            "target": str(UR_Input.SRC_IP) if UR_Input.SRC_BLACKLIST == 0 else str(UR_Input.DST_IP),
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
# format: dict ((srcip/dstip,proto,blacklist_index) -> event_record), where event_record looks like:
# {"event_scale": 68, "dst_blacklist": 0, "ts_first": 1503065770.126,
# "targets": {"195.113.170.21": 59802, "147.231.249.2": 51101, "147.251.4.46": 34272, "194.29.128.37": 51627,
# "195.113.231.2": 54326, "147.229.37.100": 22208, "195.113.139.95": 38053, "195.113.192.82": 24099},
# "packet_count": 99, "ts_last": 1503065808.908, "protocol": 6, "source": {"185.140.110.3": 25},
# "byte_count": 4596, "src_blacklist": 8}
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
        # TODO: set JSON output??
        trap.setDataFmt(0, fmttype, fmtspec)

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
