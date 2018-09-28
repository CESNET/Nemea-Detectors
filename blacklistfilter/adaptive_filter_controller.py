#!/usr/bin/env python3

import pytrap
import sys
import logging
from time import time, sleep
from threading import Thread
from queue import Queue
from adaptive_filter_scenarios import Scenario, ScenarioDoesNotFit
from contextlib import suppress

blfilter_interfaces = {'IP': 0,
                       'URL': 1,
                       'DNS': 2}

cs = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
cs.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(cs)


# Sorting comparator, splits the IP in format "A.B.C.D(/X),Y,Z"
# into tuple of IP (A, B, C, D), which is comparable by python (numerically)
def split_ip(ip):
    """Split a IP address given as string into a 4-tuple of integers."""
    # Extract only IP, without the prefix and indexes
    ip = ip.split('/')[0] if '/' in ip else ip.split(',')[0]
    tuple_ip = tuple(int(part) for part in ip.split('.'))

    return tuple_ip


class Receiver:
    def __init__(self, input_ifcs, output_ifcs):
        """
        Trap initialization for input and output interfaces
        """
        self.trap = pytrap.TrapCtx()
        self.trap.init(sys.argv, input_ifcs, output_ifcs)

        # Set up required format to accept any unirec format.
        self.trap.setRequiredFmt(blfilter_interfaces['IP'])     # Refers to basic (IP) flows from ipdetect
        self.trap.setRequiredFmt(blfilter_interfaces['URL'])    # Refers to flows with HTTP headers from urldetect
        self.trap.setRequiredFmt(blfilter_interfaces['DNS'])    # Refers to flows with DNS headers from dnsdetect
        self.trap.setVerboseLevel(0)

        # Queue for received flows
        self.queue = Queue()

    def _create_threads(self):
        # Create workers for each receiver
        self.ip_rcv = Thread(target=self._fetch_data, args=[blfilter_interfaces['IP']])
        self.url_rcv = Thread(target=self._fetch_data, args=[blfilter_interfaces['URL']])
        self.dns_rcv = Thread(target=self._fetch_data, args=[blfilter_interfaces['DNS']])

    def run(self):
        self._create_threads()

        # Run multireceiver
        self.ip_rcv.start()
        self.url_rcv.start()
        self.dns_rcv.start()

    def join_and_quit(self):
        # Join the threads
        self.ip_rcv.join()
        self.url_rcv.join()
        self.dns_rcv.join()
        self.queue.put(None)

        # Free allocated memory
        self.trap.finalize()

    def _fetch_data(self, interface):
        """
        Fetches data from trap context and puts them to
        queue as a IP/URL/DNS flow based on interface input (detector)
        Arguments:
        trap        pytrap.trapCtx
        interface   int IP/URL/DNS
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

            # No locking needed, the queue object does it internally
            self.queue.put((interface, rec_copy))


class Controller:
    def __init__(self):
        self.receiver = Receiver(3, 0)

        # A dict of detected scenarios, e.g. those which fit some Scenario class
        # The dict key can be different for each scenario
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
            # Wait until there is a detection event
            detection = self.receiver.queue.get()

            detection_iface, detection_flow = detection
            logger.debug('Received detection event from {}'
                         .format([key for key, val in blfilter_interfaces.items() if val == detection_iface]))

            detected_scenario = None

            # Try to fit the detection event to some scenario
            for scenario_class in Scenario.__subclasses__():
                with suppress(ScenarioDoesNotFit):
                    detected_scenario = scenario_class(detection_iface, detection_flow)

            if detected_scenario:
                logger.info('Detected scenario: {}'.format(type(detected_scenario).__name__))
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
