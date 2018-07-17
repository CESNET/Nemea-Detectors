#!/usr/bin/env python3

import pytrap
import sys
from threading import Thread
from queue import Queue

IP_IF = 0
URL_IF = 1


class Receiver:
    def __init__(self, input_ifcs, output_ifcs):
        """
        Trap initialization for input and output interfaces
        """
        self.trap = pytrap.TrapCtx()
        self.trap.init(sys.argv, input_ifcs, output_ifcs)

        # Set up required format to accept any unirec format.
        self.trap.setRequiredFmt(IP_IF)     # Refers to basic (IP) flows from ipdetect
        self.trap.setRequiredFmt(URL_IF)    # Refers to flows with HTTP headers from urldetec
        self.trap.setVerboseLevel(0)

        # Queue for received flows
        self.queue = Queue()

    def __create_threads__(self):
        # Create workers for each receiver
        self.ip_rcv = Thread(target=self.__fetch_data__, args=[IP_IF])
        self.url_rcv = Thread(target=self.__fetch_data__, args=[URL_IF])

    def run(self):
        self.__create_threads__()

        # Run multireciver
        self.ip_rcv.start()
        self.url_rcv.start()

    def join_and_quit(self):
        # Join the threads
        self.ip_rcv.join()
        self.url_rcv.join()
        self.queue.put(None)

        # Free allocated memory
        self.trap.finalize()

    def __fetch_data__(self, interface):
        """
        Fetches data from trap context and puts them to
        queue as a IP/URL/DNS flow based on interface input (detector)
        Arguments:
        trap        pytrap.trapCtx
        interface   int IP_IF/URL_IF
        queue       Queue
        """
        while True:
            try:
                data = self.trap.recv(interface)
            except pytrap.FormatChanged as e:
                print('koko')
                fmttype, inputspec = self.trap.getDataFmt(interface)
                rec = pytrap.UnirecTemplate(inputspec)
                data = e.data
            if len(data) <= 1:
                break

            rec.setData(data)

            print(rec.SRC_IP)
            print(interface)
            exit(3)

            if interface is IP_IF:
                pass
            else:
                pass




if __name__ == '__main__':
    # Create a new trap context

    receiver = Receiver(2, 0)
    receiver.run()
    receiver.join_and_quit()

    # Handle the received data from receivers
    # data_handler = Thread(target=data_handling, args=(detector, flow_queue))
    # data_handler.start()
