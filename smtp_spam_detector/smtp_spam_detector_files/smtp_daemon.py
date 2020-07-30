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

Authors:
    Ladislav Macoun <ladislavmacoun@gmail.com>

"""

#!/usr/bin/env python3
import pytrap
import sys
import signal
import logging
import argparse
from threading import Thread, Semaphore, Lock
from .flow import Flow, SMTP_Flow, FlowConversionException
from .smtp_entity import SMTP_ENTITY
from .detection import SpamDetection
try:
    from queue import Queue
except:
    from queue import Queue

"""
Parse input parameters
"""
parser = argparse.ArgumentParser()
parser.add_argument('-i', help="trap interface see libtrap manual for more information")
parser.add_argument('-L', '--log', default="/var/log/smtp_spam_detector.log",
                    help="--log [path] Specifies path for logger. Default path is set to /var/log/smtp_spam_detector.log")
parser.add_argument('--debug', default=False, help="--debug [True/False] Set debug level to show debug output.")
parser.add_argument('-t', '--interval', default=300, help="--interval [integer] Set probing interval to evaluate parameters for each entity in database. Default value = 300")
parser.add_argument('-c', '--clean', default=0, help="--clean [integer] Set different time for cleaning instead of cleaning at the end of probing cycle.")


try:
    args = parser.parse_args()
except:
    parser.print_help()
    exit(0)

# Interfaces definition
BASIC_IF = 0
SMTP_IF = 1
"""
Initialize logging mechanism
"""
from . import g
g.PATH_DEBUG_LOG = args.log
g.debug_level = args.debug
g.PROBE_INTERVAL = int(args.interval)
g.CLEAN_INTERVAL = int(args.clean)
LOGFORMAT = "%(asctime)-15s,%(threadName)s,%(name)s,[%(levelname)s] %(message)s"
LOGDATEFORMAT = "%Y-%m-%dT%H:%M:%S"
logging.basicConfig(level=logging.INFO, format=LOGFORMAT, datefmt=LOGDATEFORMAT)
log = logging.getLogger('smtp_spam')

if (g.debug_level == "True"):
    log.setLevel('DEBUG')

"""
Initialize file handler for log

Arguments:
DEBUG_LOG_PATH : path to debug log file from config file (g_def.py)
"""
fh = logging.FileHandler(g.PATH_DEBUG_LOG)
fh.setFormatter(logging.Formatter(LOGFORMAT))
log.addHandler(fh)
log.info("***SMTP SPAM DETECTION Started***")

# Create signal handler for stopping this module
g.stop_lock = Lock()
g.stop_lock.acquire()
g.is_running = True

# Signal handler releasing the lock on SIGINT or SIGTERM
def sigint_handler(signum, frame):
    log.debug("Signal {} received, stopping daemon".format({signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}.get(signum, signum)))
    g.stop_lock.release()

signal.signal(signal.SIGINT, sigint_handler)
signal.signal(signal.SIGTERM, sigint_handler)
signal.signal(signal.SIGABRT, sigint_handler)

def fetch_data(trap, rec, interface, queue):
    """
    Fetches data from trap context and puts them to
    queue as a Flow or SMTP_Flow based on interface input

    Arguments:
    trap        pytrap.trapCtx
    interface   int BASIC_IF/SMTP_IF
    queue       Queue
    """
    while (g.is_running):
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
            if rec.DST_PORT in list(g.email_protocols.values()):
                flow = Flow(rec)
                queue.put(flow)
        else:
            try: #TODO Flow are discarded at the moment
                flow = SMTP_Flow(rec)
                if (flow == None):
                    pass
                else:
                    queue.put(flow)
            except FlowConversionException as e:
                log.error("{0} Flow discarded.".format(e))

    log.info("Receiver finished! Closing on interface {0}".format(interface))
    return True

def data_handling(detector, q):
    """
    Handles data from queue which are fetched from trap context to detector.

    Arguments:
    detector    SpamDetector
    q           queue
    """
    while (g.is_running == True):
        try:
            flow = q.get()
            if flow is None:
                sys.stderr.write("data_handling: Receiving flows failed.\n")
                break
            detector.add_entity(flow)
            q.task_done()
        except IndexError:
            sys.stderr.write("data_handling: No data in queue.\n")
    log.info("Data handler finished! Exiting now.")
    return True

def main():
    # Select input spec for basic and smtp interface
    basic_spec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL"
    smtp_spec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 SMTP_2XX_STAT_CODE_COUNT,uint32 SMTP_3XX_STAT_CODE_COUNT,uint32 SMTP_4XX_STAT_CODE_COUNT,uint32 SMTP_5XX_STAT_CODE_COUNT,uint32 SMTP_COMMAND_FLAGS,uint32 SMTP_MAIL_CMD_COUNT,uint32 SMTP_RCPT_CMD_COUNT,uint32 SMTP_STAT_CODE_FLAGS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL,string SMTP_DOMAIN,string SMTP_FIRST_RECIPIENT,string SMTP_FIRST_SENDER"
    # Create a new trap context
    trap = pytrap.TrapCtx()
    """
    Trap initialization for two input interfaces, and no output interface
    """
    trap.init(sys.argv, 2, 1)
    # Set up required format to accept any unirec format.
    trap.setRequiredFmt(BASIC_IF, pytrap.FMT_UNIREC, basic_spec)    # Refers to flows without SMTP headers
    trap.setRequiredFmt(SMTP_IF, pytrap.FMT_UNIREC, smtp_spec)      # Refers to flows with SMTP headers
    basic_rec = pytrap.UnirecTemplate(basic_spec)
    smtp_rec = pytrap.UnirecTemplate(smtp_spec)
    trap.setDataFmt(0, pytrap.FMT_JSON, "smtp_alert")
    log.info("Daemon: Trap initialized.")
    detector = SpamDetection(trap)
    # Data synchronized queues
    flow_queue = Queue()    # Synchronize input flows
    # Create workers for each receiver
    basic_rcv = Thread(name="basic_receiver", target=fetch_data, args=(trap, basic_rec, BASIC_IF, flow_queue))
    smtp_rcv = Thread(name="smtp_receiver", target=fetch_data, args=(trap, smtp_rec, SMTP_IF, flow_queue))
    # Handle the received data from receivers
    data_handler = Thread(name="data_handler", target=data_handling, args=(detector, flow_queue))
    # Run multi-receiver
    basic_rcv.start()
    smtp_rcv.start()
    data_handler.start()
    log.info("Daemon: Multi-receiver started.")
    # Start detector
    detector.start()
    # Wait until the daemon is requested to stop by releasing the lock (by signal handler)
    g.stop_lock.acquire()
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGABRT, signal.SIG_DFL)
    log.info("Stopping running components ...")
    g.is_running = False
    detector.stop()
    # Join the threads
    basic_rcv.join()
    smtp_rcv.join()
    # Stop data_handler
    flow_queue.put(None)
    data_handler.join()
    detector.join()
    # Free allocated memory
    trap.finalize()
    log.info("***** Finished, main thread exiting. *****")
    logging.shutdown()
    sys.exit(0)

if __name__ == "__main__":
    main()

