"""
Copyright (C) 2016-2018 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.
3. Neither the name of the Company nor the names of its contributors
   may be used to endorse or promote products derived from this
   software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this
product may be distributed under the terms of the GNU General Public
License (GPL) version 2 or later, in which case the provisions
of the GPL apply INSTEAD OF those given above.

This software is provided ``as is'', and any express or implied
warranties, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose are disclaimed.
In no event shall the company or contributors be liable for any
direct, indirect, incidental, special, exemplary, or consequential
damages (including, but not limited to, procurement of substitute
goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even
if advised of the possibility of such damage.
"""

#!/usr/bin/env python
# Full imports
import pytrap
import sys
from global_def import *
from threading import Thread, Semaphore
from flow import Flow, SMTP_Flow
from smtp_entity import SMTP_ENTITY
from detection import SpamDetection
try:
    from queue import Queue
except:
    from Queue import Queue
import time
# Interfaces definition
BASIC_IF = 0
SMTP_IF = 1

def fetch_data(trap, interface, queue):
    """
    Fetches data from trap context and puts them to
    queue as a Flow or SMTP_Flow based on interface input

    Arguments:
    trap        pytrap.trapCtx
    interface   int BASIC_IF/SMTP_IF
    queue       Queue
    """
    while (True):
        try:
            data = trap.recv(interface)
        except pytrap.FormatChanged as e:
            fmttype, inputspec = trap.getDataFmt(interface)
            rec = pytrap.UnirecTemplate(inputspec)
            data = e.data
        if len(data) <= 1:
            break
        rec.setData(data)
        if interface is BASIC_IF:
            if rec.DST_PORT in email_protocols.values():
                flow = Flow(rec)
                queue.put(flow)
        else:
            flow = SMTP_Flow(rec)
            flow.filter()
            queue.put(flow)
    return True

def data_handling(detector, q):
    """
    Handles data from queue which are fetched from trap context to detector.

    Arguments:
    detector    SpamDetector
    q           queue
    """
    processed = 0
    ts = time.time()
    while (True):
        try:
            flow = q.get()
            if flow is None:
                sys.stderr.write("data_handling: Processed {0} flows.\n".format(processed))
                break
            detector.add_entity(flow, flow.SRC_IP)
            processed = processed + 1
            if processed % 10000 is 0:
                print("Fetched {0} flow.s".format(processed))
            q.task_done()
        except IndexError:
            sys.stderr.write("No data in queue.\n")
    return True

if __name__ == '__main__':

    # Datapool used to store information about smtp entities
    data = {}

    # Create a new trap context
    trap = pytrap.TrapCtx()

    """
    Trap initialization for two input interfaces, and no output interface
    """

    trap.init(["-i", "u:flow_data_source,u:smtp_data_source"], 2, 0)
    #trap.init(sys.argv, 2, 0)

    # Set up required format to accept any unirec format.
    trap.setRequiredFmt(BASIC_IF)   # Refers to flows without SMTP headers
    trap.setRequiredFmt(SMTP_IF)    # Refers to flows with SMTP headers
    trap.setVerboseLevel(0)
    detector = SpamDetection(trap)

    # Data synchronized queues
    flow_queue = Queue()    # Synchronize input flows
    reports = Queue()       # Synchronize output reports

    # Create workers for each receiver
    basic_rcv = Thread(target=fetch_data, args=(trap, BASIC_IF, flow_queue))
    smtp_rcv = Thread(target=fetch_data, args=(trap, SMTP_IF, flow_queue))

    # Handle the received data from receivers
    data_handler = Thread(target=data_handling, args=(detector, flow_queue))

    # Run multireciver
    basic_rcv.start()
    smtp_rcv.start()
    data_handler.start()

    # Start detector
    detector.start()

    # Join the threads
    basic_rcv.join()
    smtp_rcv.join()

    # Stop data_handler
    flow_queue.put(None)
    data_handler.join()

    # Free allocated memory
    trap.finalize()

