#!/usr/bin/python3
#
# Aggregation of alert from vportscan_detector.
# It receives alerts and aggregates them into time window.
# As a result, it decreases number of alerts about the same scanners.
# Aggregation is done by SRC_IP (or SRC_IP,DST_IP pair if --noblockscan is set).
#
# Author: Tomas Cejka <cejkat@cesnet.cz>
#         Vaclav Bartos <bartos@cesnet.cz>
#
# Copyright (C) 2017 CESNET
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL) version 2 or later, in which case the provisions
# of the GPL apply INSTEAD OF those given above.
#
# This software is provided ``as is'', and any express or implied
# warranties, INCluding, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, INCidental, special, exemplary, or consequential
# damages (INCluding, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (INCluding negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.
#

from time import sleep
from threading import Timer
from threading import Lock
from collections import defaultdict
import sys, os
import signal
import json
import pytrap

# Maximum number of dest. IPs in an event record (if there are more, the event
# is split into several records)
MAX_DST_IPS_PER_EVENT = 1000

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
      help="See https://nemea.liberouter.org/trap-ifcspec/", metavar="IFCSPEC")
parser.add_option("-t", "--time", dest="time", type="float",
      help="Length of time interval in which alerts are aggregated.", metavar="MINUTES", default=5)
parser.add_option("--noblockscans", dest="blockscans", action="store_false", default=True,
      help="Don't aggregate scans of multiple destination IPs to block scans, i.e. use (src_ip,dst_ip)-pair as aggregation key rather than src_ip only.")

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

# Specifier of UniRec format expected on input
urfmt = "ipaddr DST_IP,ipaddr SRC_IP,uint32 PORT_CNT,time TIME_FIRST," + \
        "time TIME_LAST,uint16 DST_PORT,uint16 SRC_PORT,uint8 EVENT_TYPE," + \
        "uint8 PROTOCOL"

UR_Input = pytrap.UnirecTemplate(urfmt)

# Set the template as required format
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, urfmt)

# Set output format and disable output buffering
trap.setDataFmt(0, pytrap.FMT_JSON, "aggregated_portscan")
trap.ifcctl(0, False, pytrap.CTL_BUFFERSWITCH, 0)


# Send aggregated alerts by RepeatedTimer
def sendEvents():
    global eventList
    for key in eventList:
        event = eventList[key]
        try:
            # To avoid too long messages, split the event if there are more 1000 IPs
            if len(event["dst_ips"]) > MAX_DST_IPS_PER_EVENT:
                all_ip_cnt_pairs = list(event["dst_ips"].items())
                all_ip_cnt_pairs.sort()
                while all_ip_cnt_pairs:
                    event_copy = event.copy()
                    event_copy["dst_ips"] = dict(all_ip_cnt_pairs[:MAX_DST_IPS_PER_EVENT])
                    all_ip_cnt_pairs = all_ip_cnt_pairs[MAX_DST_IPS_PER_EVENT:]
                    trap.send(json.dumps(event_copy))
            else:
                # Send data to output interface
                trap.send(json.dumps(event))
        except pytrap.Terminated:
            print("Terminated TRAP.")
            break

    eventList = {}

print("starting timer for sending...")
rt = RepeatedTimer(int(options.time * 60), sendEvents)

# Global list of events
# format: dict (srcip[,dstip] -> event_record), where event_record looks like:
# {"src_ip": "1.8.9.39", "dst_ips": {"88.5.17.23": 400, "69.7.18.27": 2100},
#  "ts_first": 1455131428.0, "ts_last": 1455131910.327, "protocol": 6}
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
      (fmttype, fmtspec) = trap.get_data_fmt(trap.IFC_INPUT, 0)
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

   # Update the list of events
   if options.blockscans:
      key = (UR_Input.SRC_IP, UR_Input.PROTOCOL)
   else:
      key = (UR_Input.SRC_IP, UR_Input.DST_IP, UR_Input.PROTOCOL)
   if key in eventList:
      # Update the event
      event = eventList[key]
      event["dst_ips"][str(UR_Input.DST_IP)] += UR_Input.PORT_CNT
      event["ts_first"] = min(event["ts_first"], float(UR_Input.TIME_FIRST))
      event["ts_last"] = max(event["ts_last"], float(UR_Input.TIME_LAST))
   else:
      # Insert new event
      event = {
         "src_ip": str(UR_Input.SRC_IP),
         "dst_ips": defaultdict(int, {str(UR_Input.DST_IP): UR_Input.PORT_CNT}),
         "ts_first": float(UR_Input.TIME_FIRST),
         "ts_last": float(UR_Input.TIME_LAST),
         "protocol": UR_Input.PROTOCOL,
      }
      eventList[key] = event

   lock.release()


rt.stop()
sendEvents()
trap.sendFlush()
