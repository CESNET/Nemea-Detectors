#!/usr/bin/env python
# Full imports
import pytrap
import sys
from threading import Thread, Semaphore
from queue import Queue
# Import project parts
from flow import *
from smtp_entity import *
import time
# Print current version of python
print (sys.version)

# Interfaces definition
BASIC_IF = 0
SMTP_IF = 1

semaphore = Semaphore(0)

# Class for basic flow without SMTP Headers
def get_ctx_data(trap, interface, queue):
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
            flow = Flow(rec)
        else:
            flow = SMTP_Flow(rec)
        queue.put(flow)
    return True

def data_handling(data, q):
    # Load flow from queue
    qs = q.qsize()
    while (True):
        try:
            #print("Getting flows from queue.")
            flow = q.get()
            if flow is 0:
                sys.stderr.write("data_handlig: Processed {0} flows.".format(qs))
                break
            # Add it to the history flow datapool
            if flow.SRC_IP in data.keys():
                if flow.DST_IP in data.keys():
                    data[flow.DST_IP].incoming += 1
                else:
                    data[flow.DST_IP] = SMTP_ENTITY(flow.DST_IP, flow.TIME_LAST)
                data[flow.SRC_IP].add_new_flow(flow)
                data[flow.SRC_IP].update_time(flow)
            else:
                data[flow.SRC_IP] = SMTP_ENTITY(flow)
            q.task_done()
        except IndexError:
            sys.stderr.write("No data in queue.\n")
    semaphore.release()
    return True

def data_print(data):
    semaphore.acquire()
    for entity in data:
        print(data[entity].sent_history)
        print()
    return None


if __name__ == '__main__':
    # Datapool used to store information about smtp entites
    data = {}
    # Create a new trap context
    trap = pytrap.TrapCtx()
    """
        Trap initialization for two input interfaces, and no output interface
    """
    #trap.init(["-i", "u:flow_data_source,u:smtp_data_source"], 2, 0)
    trap.init(["-i", "f:~/data/test_multireciver/basic_flow.trapcap,f:~/data/test_multireciver/smtp_flow.trapcap"], 2, 0)
    # Set up requried format to accept any unirec format.
    trap.setRequiredFmt(BASIC_IF)   # Refers to flows without SMTP headers
    trap.setRequiredFmt(SMTP_IF)    # Refers to flows with SMTP headers
    trap.setVerboseLevel(0)
    """
        *** Multireciever Implementation ***
        Splits unirec input from libtrap into multiple interfaces
        this enables recieving unirec flows with different format.
    """
    # Data queue
    flow_queue = Queue()
    # Create workers for each reciever
    basic_rcv = Thread(target=get_ctx_data, args=(trap, BASIC_IF, flow_queue))
    smtp_rcv = Thread(target=get_ctx_data, args=(trap, SMTP_IF, flow_queue))
    # Handle the recieved data from recivers
    data_handler = Thread(target=data_handling, args=(data, flow_queue))

    basic_rcv.start()
    smtp_rcv.start()
    data_handler.start()

    # Finilize multireciver
    flow_queue.put(0)

    basic_rcv.join()
    smtp_rcv.join()
    data_handler.join()

    data_print(data)

    # Free allocated memory
    trap.finalize()
