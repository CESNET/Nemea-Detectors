#!/usr/bin/python
#
# Aggregation of alert from haddrscan_detector.
# It receives alerts and aggregates them into time window.
# As a result, it decreases number of alerts about the same scanners.
#
# Author: Marek Svepes <svepemar@fit.cvut.cz>
# Author: Tomas Cejka <cejkat@cesnet.cz>
#
# Copyright (C) 2016 CESNET
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
import pytrap

# how many minutes to wait?
minutes = 5

# Global list of events
eventList = {}

from optparse import OptionParser
parser = OptionParser(add_help_option=False)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
      help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option("-t", "--time", dest="time",
      help="wait MINUTES before sending aggregated alerts", metavar="MINUTES", default=5)

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

# Initialize module
trap = pytrap.TrapCtx()
trap.init(sys.argv, 1, 1)

# Specifier of UniRec records will be received during libtrap negotiation
alertURFormat = "ipaddr SRC_IP,uint32 ADDR_CNT,time TIME_FIRST," + \
                "time TIME_LAST,uint8 EVENT_TYPE,uint8 PROTOCOL"

UR_Input = pytrap.UnirecTemplate(alertURFormat)

# this module accepts all UniRec fieds -> set required format:
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, alertURFormat)

trap.ifcctl(0,  False, pytrap.CTL_BUFFERSWITCH, 0)
trap.setDataFmt(0, pytrap.FMT_UNIREC, alertURFormat)

UR_Output = pytrap.UnirecTemplate(alertURFormat)
URtmp = UR_Input.copy()

# Send aggregated alerts by RepeatedTimer
def sendEvents():
    global eventList
    if not eventList:
        return
    # Send data to output interface
    for event in eventList:
        try:
            trap.send(eventList[event])
        except pytrap.Terminated:
            print("Terminated TRAP.")
            break

    eventList = {}

print("starting timer for sending...")
rt = RepeatedTimer(int(options.time) * 60, sendEvents)

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
      URtmp = UR_Input.copy()

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
   key = str(UR_Input.SRC_IP)
   if key in eventList:
      # Updating the value
      URtmp.setData(eventList[key])
      if URtmp.TIME_FIRST > UR_Input.TIME_FIRST:
         URtmp.TIME_FIRST = UR_Input.TIME_FIRST
      if URtmp.TIME_LAST < UR_Input.TIME_LAST:
         URtmp.TIME_LAST = UR_Input.TIME_LAST
      URtmp.ADDR_CNT += UR_Input.ADDR_CNT
   else:
      # Inserting new key
      eventList[key] = data

   lock.release()


rt.stop()
sendEvents()
trap.sendFlush()
