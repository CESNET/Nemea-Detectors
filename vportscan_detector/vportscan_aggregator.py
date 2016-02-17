#!/usr/bin/python
#
# Aggregation of alert from vportscan_detector.
# It receives alerts and aggregates them into time window.
# As a result, it decreases number of alerts about the same scanners.
#
# Author: Tomas Cejka <cejkat@cesnet.cz>
#
# Copyright (C) 2015 CESNET
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
import sys, os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "python"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "nemea-frame-work", "python"))
import trap
import unirec

# how many minutes to wait?
minutes = 5

# Global list of events
eventList = []

from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-t", "--time", dest="time",
      help="wait MINUTES before sending aggregated alerts", metavar="MINUTES", default=5)
parser.add_option("-m", "--maxportlist", dest="maxportlist", metavar="CHARS", default=300,
      help="list of scanned ports will be shorter then CHARS including commas")

import pdb


module_info = trap.CreateModuleInfo(
   "Vertical port scan aggregator", # Module name
   "Receives UniRec messages containing alerts and aggregates them. The resulting alerts are sent every 5 minutes.", # Description
   1, # Number of input interfaces
   1,  # Number of output interfaces
   parser
)

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

# Initialize module
ifc_spec = trap.parseParams(sys.argv, module_info)

trap.init(module_info, ifc_spec)

trap.registerDefaultSignalHandler() # This is needed to allow module termination using s SIGINT or SIGTERM signal

# Parse remaining command-line arguments
(options, args) = parser.parse_args()

# Specifier of UniRec records will be received during libtrap negotiation
alertURFormat = "ipaddr DST_IP,ipaddr SRC_IP,uint32 PORT_CNT,time TIME_FIRST," + \
                "time TIME_LAST,uint16 DST_PORT,uint16 SRC_PORT,uint8 EVENT_TYPE," + \
                "uint8 PROTOCOL"

UR_Input = unirec.CreateTemplate("UR_Input", alertURFormat)

# this module accepts all UniRec fieds -> set required format:
trap.set_required_fmt(0, trap.TRAP_FMT_UNIREC, alertURFormat)
trap.set_data_fmt(0, trap.TRAP_FMT_UNIREC, alertURFormat)

trap.ifcctl(trap.IFC_OUTPUT, 0, trap.CTL_BUFFERSWITCH, 0)

UR_Output = None
#UR_Output = unirec.CreateTemplate("UR_Output", alertURFormat)
#
#trap.set_data_fmt(0, trap.TRAP_FMT_UNIREC, alertURFormat)


# Send aggregated alerts by RepeatedTimer
def sendEvents():
    global eventList
    if not eventList:
        return
    # Send data to output interface
    for event in eventList:
        try:
            trap.send(0, event.serialize())
        except trap.ETerminated:
            break

    eventList = []

print "starting timer for sending..."
rt = RepeatedTimer(int(options.time) * 60, sendEvents)

while not trap.stop:
   # Read data from input interface
   try:
      data = trap.recv(0)
   except trap.EFMTMismatch:
      print("Error: output and input interfaces data format or data specifier mismatch")
      break
   except trap.EFMTChanged as e:
      # Get data format from negotiation
      (fmttype, fmtspec) = trap.get_data_fmt(trap.IFC_INPUT, 0)
      UR_Input = unirec.CreateTemplate("UR_Input", fmtspec)
      print("mismatch", fmttype, fmtspec)
      
      trap.set_data_fmt(0, fmttype, fmtspec)
      data = e.data
   except trap.ETerminated:
      break

   # Check for "end-of-stream" record
   if len(data) <= 1:
      break

   # Convert data to UniRec
   rec = UR_Input(data)
   lock.acquire()
   # update list of events
   added = False
   for i in eventList:
       if rec.EVENT_TYPE == i.EVENT_TYPE and rec.SRC_IP == i.SRC_IP and rec.DST_IP == i.DST_IP:
           if i.TIME_FIRST > rec.TIME_FIRST:
               i.TIME_FIRST = rec.TIME_FIRST
           if i.TIME_LAST < rec.TIME_LAST:
               i.TIME_LAST = rec.TIME_LAST
           i.PORT_CNT += rec.PORT_CNT
           added = True
           break

   if not added:
       eventList.append(rec)

   lock.release()

rt.stop()
sendEvents()


