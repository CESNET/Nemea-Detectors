import pytrap
import sys
from queue import Queue

IP_IF = 0
URL_IF = 1

def fetch_data():
    pass




if __name__ == '__main__':
    # Create a new trap context
    trap = pytrap.TrapCtx()
    """
    Trap initialization for two input interfaces, and no output interface
    """
    trap.init(sys.argv, 2, 0)
    # Set up required format to accept any unirec format.
    trap.setRequiredFmt(IP_IF)     # Refers to basic (IP) flows from ipdetect
    trap.setRequiredFmt(URL_IF)    # Refers to flows with HTTP headers from urldetec
    trap.setVerboseLevel(0)

    # Data queue
    flow_queue = Queue()
    # Create workers for each receiver
    basic_rcv = Thread(target=fetch_data, args=(trap, BASIC_IF, flow_queue))
    smtp_rcv = Thread(target=fetch_data, args=(trap, SMTP_IF, flow_queue))
    # Handle the received data from receivers
    data_handler = Thread(target=data_handling, args=(detector, flow_queue))
    # Run multireciver
    basic_rcv.start()
    smtp_rcv.start()
    data_handler.start()
    # Join the threads
    basic_rcv.join()
    smtp_rcv.join()
    # Stop data_handler
    flow_queue.put(None)
    data_handler.join()
    # Free allocated memory
    trap.finalize()