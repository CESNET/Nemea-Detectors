#!/usr/bin/env python3

# Aggregation of alerts from urlblacklist detector.
# It receives UniRec and aggregates addresses 1-N in time window.

from threading import Timer
from threading import Lock
import sys, os
import signal
import json
import pytrap

from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option("-t", "--time", dest="time", type="float",
                  help="Length of time interval in which alerts are aggregated.", metavar="MINUTES", default=5)

lock = Lock()

# Maximum number of dest. IPs in an event record (if there are more, they are trimmed)
MAX_DST_IPS_PER_EVENT = 1000


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


# exact output match of urlblacklistfilter
urfmt = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BLACKLIST,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS," + \
        "uint16 DST_PORT,uint16 SRC_PORT,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL"

UR_Input = pytrap.UnirecTemplate(urfmt)

# Set the template as required format
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, urfmt)

# Set output format and disable output buffering
trap.setDataFmt(0, pytrap.FMT_JSON, "aggregated_urlblacklist")
trap.ifcctl(0, False, pytrap.CTL_BUFFERSWITCH, 0)


# Send aggregated alerts by RepeatedTimer
def sendEvents():
    global eventList
    for key in eventList:
        event = eventList[key]
        try:
            if len(event['targets']) > MAX_DST_IPS_PER_EVENT:
                event['targets'] = event['targets'][:MAX_DST_IPS_PER_EVENT]
            # Send data to output interface
            trap.send(bytearray(json.dumps(event), "utf-8"))
        except pytrap.Terminated:
            print("Terminated TRAP.")
            break

    eventList = {}


def storeEvent():
    global UR_Input

    # Set key (Host+URL, destination and L4 protocol)
    key = (UR_Input.HTTP_REQUEST_HOST, UR_Input.HTTP_REQUEST_URL, UR_Input.DST_IP, UR_Input.PROTOCOL)

    if key in eventList:
        # Update the event
        event = eventList[key]

        # Update ports of the source (of trouble) and target IPs
        if UR_Input.DST_PORT not in event["source_ports"]:
            event["source_ports"].append(UR_Input.DST_PORT)

        if str(UR_Input.SRC_IP) not in event["targets"]:
            event["targets"].append(str(UR_Input.SRC_IP))

        event["ts_first"] = min(event["ts_first"], float(UR_Input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(UR_Input.TIME_LAST))

        event["blacklist_bmp"] |= UR_Input.BLACKLIST

        event["tgt_sent_bytes"] += UR_Input.BYTES
        event["tgt_sent_flows"] += 1
        event["tgt_sent_packets"] += UR_Input.PACKETS

    else:
        # Insert new event

        url = str(UR_Input.HTTP_REQUEST_HOST)
        only_fqdn = True

        if len(str(UR_Input.HTTP_REQUEST_URL)) > 1:
            url += str(UR_Input.HTTP_REQUEST_URL)
            only_fqdn = False

        event = {
            # Every source/src means source of trouble (the blacklisted address)
            "source_ip": str(UR_Input.DST_IP),
            "source_url": url,
            "referer": str(UR_Input.HTTP_REQUEST_REFERER),
            "targets": [str(UR_Input.SRC_IP)],
            "source_ports": [UR_Input.DST_PORT],
            "ts_first": float(UR_Input.TIME_FIRST),
            "ts_last": float(UR_Input.TIME_LAST),
            "protocol": UR_Input.PROTOCOL,
            # The detected flow is a HTTP request to blacklisted URL, so the communication we can observe is from the client
            "tgt_sent_bytes" : UR_Input.BYTES,
            "tgt_sent_flows" : 1,
            "tgt_sent_packets" : UR_Input.PACKETS,
            "blacklist_bmp": UR_Input.BLACKLIST,
            "agg_win_minutes": options.time,
            "is_only_fqdn": only_fqdn
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
