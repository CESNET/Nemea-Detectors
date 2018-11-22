#!/usr/bin/env python3

import pytrap
import sys
import logging
import json
import os
from time import time
from threading import Thread
from queue import Queue
from contextlib import suppress

import scenarios
import utils
import g

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option('--blacklist-config', help="Set path to config file of blacklist downloader. Default: /etc/nemea/blacklistfilter/bl_downloader_config.xml",
                    default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")

# cs = logging.StreamHandler()
# formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
# cs.setFormatter(formatter)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,format='[%(asctime)s] - %(levelname)s - %(message)s')
# logger.addHandler(cs)

scenario_events = {}


# Sorting comparator, splits the IP in format "A.B.C.D(/X),Y,Z"
# into tuple of IP (A, B, C, D), which is comparable by python (numerically)
def split_ip(ip):
    """Split a IP address given as string into a 4-tuple of integers."""
    # Extract only IP, without the prefix and indexes
    ip = ip.split('/')[0] if '/' in ip else ip.split(',')[0]
    tuple_ip = tuple(int(part) for part in ip.split('.'))

    return tuple_ip


class IP_URL_Interface:
    iface_num = 0
    template_type = pytrap.FMT_JSON
    template_in = "aggregated_blacklist"

    def __init__(self):
        # Set output format and disable output buffering
        trap.ifcctl(self.iface_num, False, pytrap.CTL_BUFFERSWITCH, 0)


class DNS_Interface:
    iface_num = 1
    template_type = pytrap.FMT_UNIREC
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint8 PROTOCOL," \
                  "uint16 DST_PORT,uint16 SRC_PORT,uint16 DNS_ID,uint16 DNS_ANSWERS,string DNS_NAME,uint16 DNS_QTYPE," \
                  "uint16 DNS_RLENGTH,uint8 DNS_RCODE,bytes DNS_RDATA,uint8 DNS_DO,uint16 DNS_CLASS," \
                  "uint16 DNS_PSIZE,uint32 DNS_RR_TTL,uint64 BLACKLIST"

    def __init__(self):
        self.ur_input = pytrap.UnirecTemplate(self.template_in)
        # Set output format and disable output buffering
        # trap.ifcctl(self.iface_num, False, pytrap.CTL_BUFFERSWITCH, 0)


class Adaptive_Interface:
    iface_num = 2
    template_type = pytrap.FMT_UNIREC
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST," + \
                  "time TIME_FIRST,time TIME_LAST,uint32 COUNT,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL,string ADAPTIVE_IDS"


class Receiver:
    def __init__(self):
        """
        Trap initialization for input and output interfaces
        """

        # Set up required format to accept any unirec format.
        trap.setRequiredFmt(IP_URL_Interface.iface_num, IP_URL_Interface.template_type, IP_URL_Interface.template_in)
        trap.setRequiredFmt(DNS_Interface.iface_num, DNS_Interface.template_type, DNS_Interface.template_in)
        trap.setRequiredFmt(Adaptive_Interface.iface_num, Adaptive_Interface.template_type, Adaptive_Interface.template_in)

        # Queue for received flows
        self.queue = Queue()

    def _create_threads(self):
        # import pdb; pdb.set_trace()
        # Create workers for each receiver
        self.ip_url_rcv = Thread(target=self._fetch_data, args=[IP_URL_Interface()])
        self.dns_rcv = Thread(target=self._fetch_data, args=[DNS_Interface()])
        self.adaptive_rcv = Thread(target=self._fetch_data, args=[Adaptive_Interface()])

    def run(self):
        self._create_threads()

        # Run multireceiver
        self.ip_url_rcv.start()
        self.dns_rcv.start()
        self.adaptive_rcv.start()

    def join_and_quit(self):
        # Join the threads
        self.ip_url_rcv.join()
        self.dns_rcv.join()
        self.adaptive_rcv.join()
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

            if isinstance(input_class, IP_URL_Interface):
                # IP and URL events are sent in JSON (from aggregator)
                rec = json.loads(data.decode())
            else:
                # DNS and Adaptive have Unirec format
                # There has to be a copy, otherwise only reference is stored in the queue and rec is rewritten
                rec = input_class.ur_input.copy()
                rec.setData(data)

            # No locking needed, the queue object does it internally
            self.queue.put((input_class.iface_num, rec))


class Controller:
    def __init__(self):
        self.detector_file_path = '/tmp/blacklistfilter/adaptive.blist'
        self.receiver = Receiver()

        # A dict of detected scenarios, e.g. those which fit some Scenario class
        # The dict key can be different for each scenario
        self.receiver.run()

    def create_detector_file(self):
        all_entities = []

        for detected_scenario in self.detected_events.values():
            all_entities.extend(detected_scenario.adaptive_entities)

        # Create sorted list of entities and their cumulative indexes
        all_entities = sorted(all_entities, key=split_ip)

        os.makedirs(os.path.dirname(self.detector_file_path), exist_ok=True)
        with open(self.detector_file_path, 'w') as f:
            f.write('\n'.join(all_entities))

        logger.info('Created new ADAPTIVE detector file')

    def run(self):
        logger.info('Adaptive controller running..')
        while True:
            # Wait until there is a detection event
            detection_iface, detection_event = self.receiver.queue.get()

            # logger.debug('Received detection event from iface {}'.format(detection_iface))

            # print("{} : {}".format(detection_iface, detection_event))

            if detection_iface == Adaptive_Interface.iface_num:
                # Handle event from adaptive filter
                self.handle_adaptive_detection(detection_event)
                continue

            detected_scenario = None

            # Try to fit the detection event to some scenario
            for scenario_class in scenarios.Scenario.__subclasses__():
                if scenario_class.fits(detection_iface, detection_event):
                    detected_scenario = scenario_class(detection_iface, detection_event)

            if detected_scenario:
                # Scenario fits, detected_scenario is an object of this scenario class
                logger.info('Detected scenario: {}'.format(type(detected_scenario).__name__))
                try:
                    # TODO: locking here?
                    # Do we know about this specific case of the scenario?
                    scenario_event = scenario_events[detected_scenario.key]

                    # Store the detection and update metadata
                    scenario_event.detection_events.append(detection_event)
                    scenario_event.detection_cnt += 1
                    scenario_event.last_ts = time()

                except KeyError:
                    # New scenario event
                    scenario_events[detected_scenario.key] = detected_scenario

                # TODO: Move this code to evaluator
                # adaptive_entitites = detected_scenario.get_entities()
                # if adaptive_entitites and not detected_scenario.adaptive_entities:
                #     detected_scenario.adaptive_entities = adaptive_entitites
                #     self.create_detector_file()

            else:
                # Do not store any event, just bypass it to the reporter
                self.send_to_reporter(detection_event)

    @staticmethod
    def send_to_reporter(detection_event):
        # Send data to output interface
        trap.send(bytearray(json.dumps(detection_event), "utf-8"))

    def handle_adaptive_detection(self, detection_event):
        pass


if __name__ == '__main__':
    options, args = parser.parse_args()
    g.blacklists = utils.load_blacklists(options.blacklist_config)
    g.botnet_blacklist_indexes = utils.get_botnet_blacklist_indexes(g.blacklists)

    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 3, 1)

    trap.setDataFmt(0, pytrap.FMT_JSON, "aggregated_blacklist")

    controller = Controller()
    controller.run()

    # Free allocated memory
    trap.finalize()
