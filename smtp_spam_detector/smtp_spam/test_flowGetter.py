#!/usr/bin/env python

# Full imports
import pytrap
import sys
import threading
import Queue

# Import project parts
from smtp_flow import flow
from smtp_flow import smtp_flow
from smtp_flow import entity
from smtp_flow import detection
 
# Print current version of python
print (sys.version)

# Interfaces definition
BASIC_IF    =   0
SMTP_IF     =   1

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
        queue.put(rec)
    return True

def data_handling(data, q):
    # Load flow from queue
    while (True):
        try:
            rec = q.get()
            flow = Flow(rec)
            if flow.SRC_IP in data.keys():
                data[flow.SRC_IP].history.append(flow)
            else:
                data[flow.SRC_IP] = SMTP_ENTITY(flow.SRC_IP)
            print("DEBUG: Flow recieved from queue.\n")
            print(flow)
        except:
            sys.stderr.write("No data in queue.\n")
    return True


if __name__ == '__main__':
    # Datapool
    data = {}
    detector = SpamDetection(data)    

    # Create a new trap context
    trap = pytrap.TrapCtx()
    """
        Trap initialization for two input interfaces, and no output interface
    """
    trap.init(["-i", "u:flow_data_source,u:smtp_data_source"], 2, 0)
    # Set up requried format to accept any unirec format.
    trap.setRequiredFmt(BASIC_IF)   # Refers to flows without SMTP headers
    trap.setRequiredFmt(SMTP_IF)    # Refers to flows with SMTP headers
    """
        *** Multireciever Implementation ***
        Splits unirec input from libtrap into multiple interfaces
        this enables recieving unirec flows with different format.
    """
    # Data queue
    flow_queue = Queue.Queue()
    # Create workers for each reciever
    basic_rcv = threading.Thread(target=get_ctx_data,
                                 args=(trap, BASIC_IF, flow_queue))
    smtp_rcv = threading.Thread(target=get_ctx_data,
                                args=(trap, SMTP_IF, flow_queue))
    # Handle the recieved data from recivers
    data_handler = threading.Thread(target=data_handling,
                                    args=(data, flow_queue))
    basic_rcv.start()
    smtp_rcv.start()
    data_handler.start()

    # Finilize multireciver
    flow_queue.put(0)
    basic_rcv.join()
    smtp_rcv.join()
    data_handler.join()

    # Free allocated memory
    trap.finalize()
