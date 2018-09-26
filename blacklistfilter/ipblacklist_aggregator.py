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

# All ports higher than MINSRCPORT are considered as dynamic/private;
# therefore, let's put lower ports into IDEA messages.
MINSRCPORT=30000

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
            # To avoid too long messages, split the event if there are more 1000 IPs
            if len(event["targets"]) > MAX_DST_IPS_PER_EVENT:
                targets = event["targets"]
                while targets:
                    event_copy = event.copy()
                    event_copy["targets"] = targets[:MAX_DST_IPS_PER_EVENT]
                    targets = targets[MAX_DST_IPS_PER_EVENT:]
                    trap.send(bytearray(json.dumps(event_copy), "utf-8"))

            else:
                # Send data to output interface
                trap.send(bytearray(json.dumps(event), "utf-8"))
        except pytrap.Terminated:
            print("Terminated TRAP.")
            break

    eventList = {}


def storeEvent():
    """
    There are following cases for aggregation:
    1) both SRC_IP and DST_IP are on some blacklist:
        put every flow together and both IPs are Sources,
        remember which IP was on which blacklist
    2) SRC_IP is on some blacklist and DST_IP is not:
        we can aggregate by SRC_IP and protocol,
        SRC_IP is Source and DST_IP is Target
    3) DST_IP is on some blacklist and SRC_IP is not:
        we can aggregate by DST_IP and protocol,
        DST_IP is Source and SRC_IP is Target
    """

    global UR_Input

    src = UR_Input.SRC_IP
    dst = UR_Input.DST_IP
    srclist = UR_Input.SRC_BLACKLIST
    dstlist = UR_Input.DST_BLACKLIST
    oneway = True
    swapips = False

    # Set key (blacklisted address and protocol)
    if srclist and dstlist:
        oneway = False
        if src < dst:
            key = (src, dst, UR_Input.PROTOCOL)
        else:
            key = (dst, src, UR_Input.PROTOCOL)
            swapips = True
    elif srclist:
        key = (src, UR_Input.PROTOCOL)
    elif dstlist:
        key = (dst, UR_Input.PROTOCOL)
    else:
        # no IP is on blacklist - strange, non-working blacklistfilter
        return

    if key in eventList:
        # Update the event
        event = eventList[key]

        # Update ports of the source (of trouble) and target IPs
        source_ports = set(event.get("source_ports", []))
        targets = set(event.get("targets", []))
        sources = set(event.get("sources", []))

        # update IPs
        if srclist and dstlist:
            if swapips:
                event["ipa_bl"] |= dstlist
                event["ipb_bl"] |= srclist
                event["ipb_sent_bytes"] += UR_Input.BYTES
                event["ipb_sent_flows"] += UR_Input.COUNT
                event["ipb_sent_packets"] += UR_Input.PACKETS
            else:
                event["ipa_bl"] |= srclist
                event["ipb_bl"] |= dstlist
                event["ipa_sent_bytes"] += UR_Input.BYTES
                event["ipa_sent_flows"] += UR_Input.COUNT
                event["ipa_sent_packets"] += UR_Input.PACKETS
        elif srclist:
            #source_ports.add(UR_Input.SRC_PORT)
            targets.add(str(dst))
            event["src_sent_bytes"] += UR_Input.BYTES
            event["src_sent_flows"] += UR_Input.COUNT
            event["src_sent_packets"] += UR_Input.PACKETS
            event["blacklist_bmp"] |= UR_Input.SRC_BLACKLIST | UR_Input.DST_BLACKLIST
        elif dstlist:
            source_ports.add(UR_Input.DST_PORT)
            targets.add(str(src))
            event["tgt_sent_bytes"] += UR_Input.BYTES
            event["tgt_sent_flows"] += UR_Input.COUNT
            event["tgt_sent_packets"] += UR_Input.PACKETS
            event["blacklist_bmp"] |= UR_Input.SRC_BLACKLIST | UR_Input.DST_BLACKLIST

        event["source_ports"] = list(source_ports)
        event["targets"] = list(targets)
        event["sources"] = list(sources)

        event["ts_first"] = min(event["ts_first"], float(UR_Input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(UR_Input.TIME_LAST))
    else:
        # Insert new event
        event = {
            # Every source/src means source of trouble (the blacklisted address)
            "ts_first": float(UR_Input.TIME_FIRST),
            "ts_last": float(UR_Input.TIME_LAST),
            "protocol": UR_Input.PROTOCOL,
            "source_ports": [],
            "src_sent_bytes": UR_Input.BYTES if UR_Input.SRC_BLACKLIST else 0,
            "src_sent_flows": UR_Input.COUNT if UR_Input.SRC_BLACKLIST else 0,
            "src_sent_packets": UR_Input.PACKETS if UR_Input.SRC_BLACKLIST else 0,
            "tgt_sent_bytes": UR_Input.BYTES if UR_Input.DST_BLACKLIST else 0,
            "tgt_sent_flows": UR_Input.COUNT if UR_Input.DST_BLACKLIST else 0,
            "tgt_sent_packets": UR_Input.PACKETS if UR_Input.DST_BLACKLIST else 0,
        }
        if oneway:
            event["blacklist_bmp"] = UR_Input.SRC_BLACKLIST | UR_Input.DST_BLACKLIST
            if srclist:
                event["sources"] = [str(src)]
                event["targets"] = [str(dst)]
                #if UR_Input.SRC_PORT <= MINSRCPORT:
                #    event["source_ports"].add(UR_Input.SRC_PORT)
            elif dstlist:
                event["sources"] = [str(dst)]
                event["targets"] = [str(src)]
                if UR_Input.DST_PORT <= MINSRCPORT:
                    event["source_ports"].append(UR_Input.DST_PORT)
        else:
            event["sources"] = list(set([str(src), str(dst)]))
            sp = set()
            #if UR_Input.SRC_PORT <= MINSRCPORT:
            #    event["source_ports"].add(UR_Input.SRC_PORT)
            if UR_Input.DST_PORT <= MINSRCPORT:
                event["source_ports"].append(UR_Input.DST_PORT)
            event["source_ports"] = list(sp)
            if swapips:
                event["ipa_bl"] = dstlist
                event["ipb_bl"] = srclist
                event["ipa_sent_bytes"] = 0
                event["ipa_sent_flows"] = 0
                event["ipa_sent_packets"] = 0
                event["ipb_sent_bytes"] = UR_Input.BYTES
                event["ipb_sent_flows"] = UR_Input.COUNT
                event["ipb_sent_packets"] = UR_Input.PACKETS
            else:
                event["ipa_bl"] = srclist
                event["ipb_bl"] = dstlist
                event["ipa_sent_bytes"] = UR_Input.BYTES
                event["ipa_sent_flows"] = UR_Input.COUNT
                event["ipa_sent_packets"] = UR_Input.PACKETS
                event["ipb_sent_bytes"] = 0
                event["ipb_sent_flows"] = 0
                event["ipb_sent_packets"] = 0

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
