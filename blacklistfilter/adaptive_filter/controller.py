#!/usr/bin/env python3

import pytrap
import sys
import logging
import json
from time import time
from threading import Thread
from queue import Queue
from contextlib import suppress

import scenarios

#
# from optparse import OptionParser
# parser = OptionParser(add_help_option=True)
# parser.add_option("-i", "--ifcspec", dest="ifcspec",
#                   help="TRAP IFC specifier", metavar="IFCSPEC")


cs = logging.StreamHandler()
formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
cs.setFormatter(formatter)
logger = logging.getLogger('Adaptive-filter')
logger.addHandler(cs)
logger.setLevel(logging.DEBUG)


# Sorting comparator, splits the IP in format "A.B.C.D(/X),Y,Z"
# into tuple of IP (A, B, C, D), which is comparable by python (numerically)
def split_ip(ip):
    """Split a IP address given as string into a 4-tuple of integers."""
    # Extract only IP, without the prefix and indexes
    ip = ip.split('/')[0] if '/' in ip else ip.split(',')[0]
    tuple_ip = tuple(int(part) for part in ip.split('.'))

    return tuple_ip


class IP_URL:
    iface_num = 0

    template_type = pytrap.FMT_JSON
    template_in = "aggregated_blacklist"

    def __init__(self):
        # Set output format and disable output buffering
        trap.ifcctl(self.iface_num, False, pytrap.CTL_BUFFERSWITCH, 0)


class DNS:
    iface_num = 1

    template_type = pytrap.FMT_UNIREC
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint8 PROTOCOL," \
                  "uint16 DST_PORT,uint16 SRC_PORT,uint16 DNS_ID,uint16 DNS_ANSWERS,string DNS_NAME,uint16 DNS_QTYPE," \
                  "uint16 DNS_RLENGTH,uint8 DNS_RCODE,bytes DNS_RDATA,uint8 DNS_DO,uint16 DNS_CLASS," \
                  "uint16 DNS_PSIZE,uint32 DNS_RR_TTL,uint64 BLACKLIST"

    def __init__(self):
        self.ur_input = pytrap.UnirecTemplate(self.template_in)
        # Set output format and disable output buffering
        trap.ifcctl(self.iface_num, False, pytrap.CTL_BUFFERSWITCH, 0)


class Receiver:
    def __init__(self):
        """
        Trap initialization for input and output interfaces
        """

        # Set up required format to accept any unirec format.
        trap.setRequiredFmt(IP_URL.iface_num, IP_URL.template_type, IP_URL.template_in)
        trap.setRequiredFmt(DNS.iface_num, DNS.template_type, DNS.template_in)

        # Queue for received flows
        self.queue = Queue()

    def _create_threads(self):
        # Create workers for each receiver
        self.ip_url_rcv = Thread(target=self._fetch_data, args=[IP_URL()])
        self.dns_rcv = Thread(target=self._fetch_data, args=[DNS()])

    def run(self):
        self._create_threads()

        # Run multireceiver
        self.ip_url_rcv.start()
        self.dns_rcv.start()

    def join_and_quit(self):
        # Join the threads
        self.ip_url_rcv.join()
        self.dns_rcv.join()
        self.queue.put(None)

    def _fetch_data(self, input_class):
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
                data = trap.recv(input_class.iface_num)
            except pytrap.FormatMismatch:
                print("Error: output and input interfaces data format or data specifier mismatch")
                break
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(input_class.iface_num)
                input_class.ur_input = pytrap.UnirecTemplate(inputspec)
                data = e.data
            except pytrap.Terminated:
                print("Terminated TRAP.")
                break
            except pytrap.TrapError:
                break
            if len(data) <= 1:
                break

            if isinstance(input_class, DNS):
                # DNS has Unirec format
                # There has to be a copy, otherwise only reference is stored in the queue and rec is rewritten
                rec = input_class.ur_input.copy()
                rec.setData(data)

            else:
                # IP and URL events are sent in JSON (from aggregator)
                rec = json.loads(data.decode())

            # No locking needed, the queue object does it internally
            self.queue.put((input_class.iface_num, rec))


class Controller:
    def __init__(self):
        self.receiver = Receiver()

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

        logger.info('Created new ADAPTIVE detector file')

    def run(self):
        while True:
            # Wait until there is a detection event
            detection = self.receiver.queue.get()

            detection_iface, detection_event = detection
            logger.debug('Received detection event from iface {}'.format(detection_iface))

            print("{} : {}".format(detection_iface, detection_event))

            detected_scenario = None

            # Try to fit the detection event to some scenario
            for scenario_class in scenarios.Scenario.__subclasses__():
                with suppress(scenarios.ScenarioDoesNotFit):
                    detected_scenario = scenario_class(detection_iface, detection_event)

            if detected_scenario:
                # Scenario fits
                logger.info('Detected scenario: {}'.format(type(detected_scenario).__name__))
                try:
                    # Do we know about this specific case of the scenario?
                    scenario_event = self.detected_scenarios[detected_scenario.key]

                    scenario_event.detection_events.append(detection_event)
                    scenario_event.detection_cnt += 1
                    scenario_event.last_ts = time()

                except KeyError:
                    # New scenario event
                    detected_scenario.set_random_id()
                    self.detected_scenarios[detected_scenario.key] = detected_scenario

                adaptive_entitites = detected_scenario.get_entities()
                if adaptive_entitites != detected_scenario.adaptive_entities:
                    detected_scenario.adaptive_entities = adaptive_entitites
                    self.create_detector_file()

            for key, val in self.detected_scenarios.items():
                print(key)
                print(val)
                # if key == 'zstresser.com':
                #     print(val.detection_event.SRC_IP)


if __name__ == '__main__':
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 2, 1)

    # TODO: set proper output template
    trap.setDataFmt(0, pytrap.FMT_JSON, "TODO")

    controller = Controller()
    controller.run()

    # Free allocated memory
    trap.finalize()
