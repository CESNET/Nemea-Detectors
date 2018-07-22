#!/usr/bin/env python3

import pytrap
import sys
from time import time, sleep
from threading import Thread
from queue import Queue
from adaptive_filter_scenarios import Scenario, ScenarioDoesNotFit
from contextlib import suppress

IP_IF = 0
URL_IF = 1


# Sorting comparator, splits the IP in format "A.B.C.D(/X),Y,Z"
# into tuple of IP (A, B, C, D), which is comparable by python (numerically)
def split_ip(ip):
    # Extract only IP, without the prefix and indexes
    ip = ip.split('/')[0] if '/' in ip else ip.split(',')[0]
    tuple_ip = tuple(int(part) for part in ip.split('.'))

    """Split a IP address given as string into a 4-tuple of integers."""
    return tuple_ip


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

    def _create_threads(self):
        # Create workers for each receiver
        self.ip_rcv = Thread(target=self._fetch_data, args=[IP_IF])
        self.url_rcv = Thread(target=self._fetch_data, args=[URL_IF])

    def run(self):
        self._create_threads()

        # Run multireceiver
        self.ip_rcv.start()
        self.url_rcv.start()

    def join_and_quit(self):
        # Join the threads
        self.ip_rcv.join()
        self.url_rcv.join()
        self.queue.put(None)

        # Free allocated memory
        self.trap.finalize()

    def _fetch_data(self, interface):
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
                fmttype, inputspec = self.trap.getDataFmt(interface)
                rec = pytrap.UnirecTemplate(inputspec)
                data = e.data
            if len(data) <= 1:
                break

            # There has to be a copy, otherwise only reference is stored in the queue and rec is rewritten
            rec_copy = rec.copy()
            rec_copy.setData(data)

            self.queue.put((interface, rec_copy))


class Controller:
    def __init__(self):
        self.receiver = Receiver(2, 0)
        self.detected_scenarios = {}
        self.receiver.run()

    def create_detector_file(self):
        all_entities = []

        for detected_scenario in self.detected_scenarios.values():
            all_entities.extend(detected_scenario.adaptive_entities)

        # Create sorted list of entities and their cumulative indexes
        all_entities = sorted(all_entities, key=split_ip)

        with open('/tmp/blacklistfilter/adaptive.blist', 'w') as f:
            f.write('\n'.join(all_entities))

    def run(self):
        while True:
            detection_tuple = self.receiver.queue.get()
            detection_iface = detection_tuple[0]
            detection_flow = detection_tuple[1]

            detected_scenario = None
            for scenario_class in Scenario.__subclasses__():
                with suppress(ScenarioDoesNotFit):
                    detected_scenario = scenario_class(detection_iface, detection_flow)

            if detected_scenario:
                try:
                    scenario_event = self.detected_scenarios[detected_scenario.key]
                    scenario_event.detection_cnt += 1
                    scenario_event.last_ts = time()

                except KeyError:
                    # New scenario event
                    detected_scenario.set_id()
                    detected_scenario.generate_entities()

                    self.detected_scenarios[detected_scenario.key] = detected_scenario

                    self.create_detector_file()


if __name__ == '__main__':
    controller = Controller()
    controller.run()

    # Handle the received data from receivers
    # data_handler = Thread(target=data_handling, args=(detector, flow_queue))
    # data_handler.start()
