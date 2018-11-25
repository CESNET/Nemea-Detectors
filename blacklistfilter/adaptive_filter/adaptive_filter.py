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
from time import sleep

import scenarios
import utils
import g

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option('-c', '--blacklist-config', help="Set path to config file of blacklist downloader. Default: /etc/nemea/blacklistfilter/bl_downloader_config.xml",
                    default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")
parser.add_option('-e', '--evidence-timeout', help="Timeout in seconds, meaning how much time after detection of a "
                                                   "scenario event it shall be sent to evidence. Default: 60",
                  type=int, default=60)

# cs = logging.StreamHandler()
# formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
# cs.setFormatter(formatter)
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,format='[%(asctime)s] - %(levelname)s - %(message)s')
# logger.addHandler(cs)

scenario_events = {}
adaptive_events = {}

EVIDENCE_TIMEOUT = 20
ADAPTIVE_BLACKLIST_ID = 999


# Sorting comparator, splits the IP in format "A.B.C.D(/X),Y,Z"
# into tuple of IP (A, B, C, D), which is comparable by python (numerically)
def split_ip(ip):
    """Split a IP address given as string into a 4-tuple of integers."""
    # Extract only IP, without the prefix and indexes
    ip = ip.split('/')[0] if '/' in ip else ip.split(',')[0]
    tuple_ip = tuple(int(part) for part in ip.split('.'))

    return tuple_ip


def send_to_reporter(detection_event):
    # Send data to output interface
    # TODO: catch exceptions
    trap.send(bytearray(json.dumps(detection_event), "utf-8"))


def send_to_evidence(detection_event):
    # Send data to output interface
    # TODO: catch exceptions
    print('Sending to Evidence')
    trap.send(bytearray(json.dumps(detection_event, default=lambda x: x.__dict__), "utf-8"), 1)


class IP_URL_Interface:
    iface_num = 0
    template_type = pytrap.FMT_JSON
    template_in = "aggregated_blacklist"


class DNS_Interface:
    iface_num = 1
    template_type = pytrap.FMT_UNIREC
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint8 PROTOCOL," \
                  "uint16 DST_PORT,uint16 SRC_PORT,uint16 DNS_ID,uint16 DNS_ANSWERS,string DNS_NAME,uint16 DNS_QTYPE," \
                  "uint16 DNS_RLENGTH,uint8 DNS_RCODE,bytes DNS_RDATA,uint8 DNS_DO,uint16 DNS_CLASS," \
                  "uint16 DNS_PSIZE,uint32 DNS_RR_TTL,uint64 BLACKLIST"

    def __init__(self):
        self.ur_input = pytrap.UnirecTemplate(self.template_in)


class Adaptive_Interface:
    iface_num = 2
    template_type = pytrap.FMT_UNIREC
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST,time TIME_FIRST," \
                  "time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,string ADAPTIVE_IDS"

    def __init__(self):
        self.ur_input = pytrap.UnirecTemplate(self.template_in)


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

        # Set local variables for faster access
        my_iface_num = input_class.iface_num
        if not isinstance(input_class, IP_URL_Interface):
            my_ur_input = input_class.ur_input

        while True:
            try:
                data = trap.recv(my_iface_num)
            except pytrap.FormatMismatch:
                print("Error: output and input interfaces data format or data specifier mismatch")
                break
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(my_iface_num)
                my_ur_input = pytrap.UnirecTemplate(inputspec)
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
                rec = my_ur_input.copy()
                rec.setData(data)

            # No locking needed, the queue object does it internally
            self.queue.put((my_iface_num, rec))


class Evaluator:
    def __init__(self):
        self.detector_file_path = '/tmp/blacklistfilter/adaptive.blist'

        # Evaluator holds the adaptive current entries, so it can check
        # whether there are new ones and detector file should be created
        self.current_adaptive_entities = set()

    def process_events(self):
        global scenario_events, adaptive_events
        all_adaptive_entities = set()
        event_keys_to_send = set()

        # TODO: lock the global structures
        for scenario_key, scenario_event in scenario_events.items():
            if scenario_event.last_detection_ts > scenario_event.processed_by_evaluator_ts:
                # Event updated since the last processing, get adaptive entities again
                entities = scenario_event.get_entities()
                scenario_event.adaptive_entities.update(entities)

                # Update the timestamp
                scenario_event.processed_by_evaluator_ts = time()

            # Gather the adaptive entities for all scenario events
            all_adaptive_entities.update(scenario_event.adaptive_entities)

            # TODO: Solve the case when no adaptive entities available for a long time
            if scenario_event.first_detection_ts + EVIDENCE_TIMEOUT < time() and scenario_event.id in adaptive_events.keys():
                # Timeout expired, let's export the scenario event along with adaptive detections (if there are any)
                scenario_event.adaptive_events = adaptive_events[scenario_event.id]
                event_keys_to_send.add(scenario_key)

        for event_key_to_send in event_keys_to_send:
            # Fetch the corresponding event
            event = scenario_events[event_key_to_send]

            # Delete the event's adaptive entities, we don't want to track adaptive events of this scenario event anymore
            all_adaptive_entities.difference_update(event.adaptive_entities)

            # TODO: Maybe more ephemeral variables
            # Adaptive entities are not relevant in the alert
            del event.adaptive_entities
            del event.processed_by_evaluator_ts

            send_to_evidence(event)

            # TODO: lock adaptive_events
            # Delete the adaptive events of this scenario event from the global structure
            del adaptive_events[event.id]

            # Delete the sent scenario from the global structure
            del scenario_events[event_key_to_send]

        if all_adaptive_entities != self.current_adaptive_entities:
            self.current_adaptive_entities = all_adaptive_entities
            self._create_detector_file()


    def run(self):
        print('Evaluator jede..')
        while True:
            # for event in scenario_events.values():
            #     print(event)
            print(scenario_events)
            print(adaptive_events)

            sleep(5)

            self.process_events()
            print('Events processed')

    def _create_detector_file(self):
        # Create sorted list of entities and their cumulative indexes
        sorted_entities = sorted(list(self.current_adaptive_entities), key=split_ip)

        os.makedirs(os.path.dirname(self.detector_file_path), exist_ok=True)
        with open(self.detector_file_path, 'w') as f:
            f.write('\n'.join(sorted_entities))

        logger.info('Created new ADAPTIVE detector file')


class Controller:
    def __init__(self):
        self.receiver = Receiver()

        # A dict of detected scenarios, e.g. those which fit some Scenario class
        # The dict key can be different for each scenario
        self.receiver.run()

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
                    scenario_event.last_detection_ts = time()

                except KeyError:
                    # New scenario event
                    scenario_events[detected_scenario.key] = detected_scenario

                if isinstance(detected_scenario, scenarios.BotnetDetection):
                    # We also want to send an alert for this scenario
                    send_to_reporter(detection_event)

            else:
                # Do not store any event, just bypass it to the reporter
                send_to_reporter(detection_event)

    @staticmethod
    def handle_adaptive_detection(detection_event):
        adaptive_ids = detection_event.ADAPTIVE_IDS.split(',')

        for adaptive_id in adaptive_ids:
            if adaptive_id in adaptive_events.keys():
                # There is already some detection for this adaptive event
                adaptive_events[adaptive_id].append(detection_event.strRecord())

            else:
                # New adaptive detection for this event
                adaptive_events[adaptive_id] = []
                adaptive_events[adaptive_id].append(detection_event.strRecord())


if __name__ == '__main__':
    options, args = parser.parse_args()
    g.blacklists = utils.load_blacklists(options.blacklist_config)
    g.botnet_blacklist_indexes = utils.get_botnet_blacklist_indexes(g.blacklists)
    EVIDENCE_TIMEOUT = options.evidence_timeout

    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 3, 2)

    trap.setDataFmt(0, pytrap.FMT_JSON, "aggregated_blacklist")
    trap.setDataFmt(1, pytrap.FMT_JSON, "blacklist_evidence")

    controller = Controller()
    evaluator = Evaluator()

    ctrl_thr = Thread(target=controller.run)
    ctrl_thr.start()

    evaluator.run()

    # Free allocated memory
    trap.finalize()
