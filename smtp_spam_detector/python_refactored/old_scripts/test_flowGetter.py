#!/usr/bin/env python

# Full imports
import pytrap
import sys
import threading
import Queue

BASIC_IF    =   0
SMTP_IF     =   1

# Class for basic flow without SMTP Headers
class Flow(object):
    def __init__(self, rec):
        # Basic flow
        self.DST_IP = rec.DST_IP
        self.SRC_IP = rec.SRC_IP
        self.BYTES = rec.BYTES
        self.TIME_FIRST = rec.TIME_FIRST
        self.TIME_LAST = rec.TIME_LAST
        self.PACKETS = rec.PACKETS
        self.DST_PORT = rec.DST_PORT
        self.SRC_PORT = rec.SRC_PORT

    def __repr__(self):
        return "SRC_IP:" + self.SRC_IP + ",DST_IP:" + self.DST_IP + ",BYTES:" \
                 + self.BYTES + ",TIME_FIRST;" + self.TIME_FIRST + ",TIME_LAST:" \
                 + self.TIME_LAST + ",PACKETS:" + self.PACKETS

class SMTP_ENTITY(object):
    def __init__(self, id):
        self.id = id
        self.history = []

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
        #print(rec.strRecord())
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
    # Create a new trap context
    trap = pytrap.TrapCtx()

    """
        Trap initialization for two input interfaces, and no output interface
    """
    trap.init(["-i", "u:flow_data_source,u:smtp_data_source"], 2, 0)

    # set up requried format to accept anything
    trap.setRequiredFmt(BASIC_IF)
    trap.setRequiredFmt(SMTP_IF)

    """
        *** Multireciever Implementation ***
        Splits unirec input from libtrap into multiple interfaces
        this enables recieving unirec flows with different format.
    """
    # Data queue
    flow_queue = Queue.Queue()

    # Create two reciever workers
    basic_rcv = threading.Thread(target=get_ctx_data, args=(trap, BASIC_IF, flow_queue))
    smtp_rcv = threading.Thread(target=get_ctx_data, args=(trap, SMTP_IF, flow_queue))
    data_handler = threading.Thread(target=data_handling, args=(data, flow_queue))

    print("basic started")
    basic_rcv.start()
    print("smtp started")
    smtp_rcv.start()
    print("data handler started")
    data_handler.start()


    # Finilize multireciver
    flow_queue.put(0)
    basic_rcv.join()
    smtp_rcv.join()
    data_handler.join()
    print("Multirecieving done")

    # Free allocated memory
    trap.finalize()
