#!/usr/bin/env python3

# Adaptive filter receives 2 types of data: Aggregated IP/URL events in JSON from blacklist aggregator
# and DNS flow from dnsblacklistfilter. The Controller tries to match these data to some scenarios defined
# in scenarios.py. If scenario matches, the event is stored in global dict. Processor then processes these events.
# It fetches adaptive entities and feeds them to the adaptive IP detector. This detector generates so called
# adaptive events and they are stored in Evidence flies. Processor also stores the original received detection into
# Evidence: these are so called scenario events. The two types of evidence are identified with UUID and
# further analyzed with Evaluator

import pytrap
import sys
import logging
import json
import os
import signal
import queue
from time import time
from threading import Thread, Timer, Lock

import scenarios
import utils
import g

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option('-c', '--blacklist-config', help="Set path to config file of blacklist downloader.",
                    default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")
parser.add_option('-e', '--evidence-timeout', help="Timeout in seconds, meaning how much time after detection of a "
                                                   "scenario event it shall be sent to evidence.",
                  type=int, default=600)
parser.add_option("-p", "--process-interval", type=int,
                  help="Interval in seconds when captured events are processed", default=30)

parser.add_option('--log-level', '-l',
                    help="Logging level value (from standard Logging library, 10=DEBUG, 20=INFO etc.)", type=int, default=20)

parser.add_option('--adaptive-blacklist', '-a',
                  help="Path to adaptive blacklist", type=str, default='/tmp/blacklistfilter/adaptive.blist')


# cs = logging.StreamHandler()
# formatter = logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s')
# cs.setFormatter(formatter)
logger = logging.getLogger('Adaptive filter')
logging.basicConfig(format='[%(asctime)s] - %(levelname)s - %(message)s')
# logger.addHandler(cs)

g_scenario_events = {}

events_lock = Lock()

ADAPTIVE_BLACKLIST_ID = 999
MAX_GROUPED_EVENTS_PER_SCENARIO_EVENT = 100

stop = 0


def signal_h(signal, f):
    global stop, trap
    if stop:
        print('Caught another SIGINT, exiting forcefully..')
        os._exit(1)
    print('Caught SIGINT, exiting gracefully..')
    trap.terminate()
    stop = 1


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
    try:
        trap.send(bytearray(json.dumps(detection_event), "utf-8"))
    except pytrap.TimeoutError:
        # TODO: handle properly
        logger.error('TimeoutError occured when sending to reporter')


def send_to_evidence(event):
    event = event.convert_to_evidence_fmt()
    # Send data to output interface
    logger.debug('Sending to Evidence')

    # To avoid too long messages, split the events
    if len(event["grouped_events"]) > MAX_GROUPED_EVENTS_PER_SCENARIO_EVENT:
        grouped_events = event["grouped_events"]
        event["event_scattered"] = True
        scatter_part = 1

        while grouped_events:
            event_copy = event.copy()
            event_copy["scatter_part"] = scatter_part
            event_copy["grouped_events"] = grouped_events[:MAX_GROUPED_EVENTS_PER_SCENARIO_EVENT]
            grouped_events = grouped_events[MAX_GROUPED_EVENTS_PER_SCENARIO_EVENT:]
            trap.send(bytearray(json.dumps(event_copy), "utf-8"), 1)
            scatter_part += 1
    else:
        event["event_scattered"] = False
        trap.send(bytearray(json.dumps(event), "utf-8"), 1)


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


class RepeatedTimer:
    def __init__(self, interval, function):
        self._timer = None
        self.function = function
        self.interval = interval
        self.is_running = False

    def _run(self):
        self.is_running = False
        self.start()
        self.function()

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class Receiver:
    def __init__(self):
        """
        Trap initialization for input and output interfaces
        """

        # Set up required format to accept any unirec format.
        trap.setRequiredFmt(IP_URL_Interface.iface_num, IP_URL_Interface.template_type, IP_URL_Interface.template_in)
        trap.setRequiredFmt(DNS_Interface.iface_num, DNS_Interface.template_type, DNS_Interface.template_in)

        # Queue for received flows
        self.queue = queue.Queue()

    def _create_threads(self):
        # Create workers for each receiver
        self.ip_url_rcv = Thread(target=self._fetch_data, args=[IP_URL_Interface()])
        self.dns_rcv = Thread(target=self._fetch_data, args=[DNS_Interface()])

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

        # Set local variables for faster access
        my_iface_num = input_class.iface_num
        if not isinstance(input_class, IP_URL_Interface):
            my_ur_input = input_class.ur_input

        while not stop:
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
                # DNS has Unirec format
                # There has to be a copy, otherwise only reference is stored in the queue and rec is rewritten
                rec = my_ur_input.copy()
                rec.setData(data)

            # No locking needed, the queue object does it internally
            self.queue.put((my_iface_num, rec))


class Processor:
    def __init__(self, adaptive_blacklist_path, process_interval, evidence_timeout):
        self.detector_file_path = adaptive_blacklist_path
        self.process_interval = process_interval
        self.evidence_timeout = evidence_timeout

        # Processor holds the adaptive current entries, so it can check
        # whether there are new ones and detector file should be created
        self.current_adaptive_entities = set()

        # Set repeater for the given interval
        self.rt = RepeatedTimer(int(process_interval), self.process_events)

    def process_events(self):
        global g_scenario_events
        all_adaptive_entities = set()
        event_keys_to_send = set()
        c = 0

        events_lock.acquire()
        for scenario_key, scenario_event in g_scenario_events.items():
            c += 1
            if scenario_event.last_detection_ts > scenario_event.processed_ts:
                # Event updated since the last processing, get adaptive entities again
                entities = scenario_event.get_entities()
                scenario_event.adaptive_entities.update(entities)

                # Update the timestamp
                scenario_event.processed_ts = time()

            # Gather the adaptive entities for all scenario events
            all_adaptive_entities.update(scenario_event.adaptive_entities)

            if scenario_event.first_detection_ts + self.evidence_timeout < time():
                # Evidence timeout expired, let's export the scenario event
                event_keys_to_send.add(scenario_key)

        for event_key_to_send in event_keys_to_send:
            # Fetch the corresponding event
            event = g_scenario_events[event_key_to_send]

            # Delete the event's adaptive entities, we don't want to track adaptive events of this scenario event anymore
            all_adaptive_entities.difference_update(event.adaptive_entities)

            # Adaptive entities are not relevant in the alert
            del event.adaptive_entities
            del event.processed_ts

            send_to_evidence(event)

            # Delete the sent scenario from the global structure
            del g_scenario_events[event_key_to_send]

        if all_adaptive_entities != self.current_adaptive_entities:
            self.current_adaptive_entities = all_adaptive_entities
            self._create_detector_file()

        events_lock.release()

        logger.debug('Processed {} events'.format(c))

    def run(self):
        self.rt.start()
        logger.info('Processor is running.. Checking events every {} seconds'.format(self.process_interval))

    def stop(self):
        self.rt.stop()

    def _create_detector_file(self):
        # Create sorted list of entities and their cumulative indexes
        sorted_entities = sorted(list(self.current_adaptive_entities), key=split_ip)

        os.makedirs(os.path.dirname(self.detector_file_path), exist_ok=True)
        with open(self.detector_file_path, 'w') as f:
            f.write('\n'.join(sorted_entities))

        logger.info('Created new ADAPTIVE detector file')


class Controller:
    def __init__(self, adaptive_blacklist, process_interval, evidence_timeout):
        self.receiver = Receiver()

        # A dict of detected scenarios, e.g. those which fit some Scenario class
        # The dict key can be different for each scenario
        self.receiver.run()

        self.processor = Processor(adaptive_blacklist,
                                   process_interval,
                                   evidence_timeout)

        self.processor.run()

    def run(self):
        logger.info('Adaptive controller running..')
        while not stop:
            # Wait until there is a detection event
            try:
                detection_iface, detection_event = self.receiver.queue.get(timeout=1)
            except queue.Empty:
                continue

            detected_scenario = None

            # Try to fit the detection event to some scenario
            for scenario_class in scenarios.Scenario.__subclasses__():
                if scenario_class.fits(detection_iface, detection_event):
                    detected_scenario = scenario_class(detection_event)

            if detected_scenario:
                # Scenario fits, detected_scenario is an object of this scenario class
                logger.debug('Detected scenario: {}'.format(type(detected_scenario).__name__))
                try:
                    events_lock.acquire()
                    # Do we know about this specific case of the scenario?
                    scenario_event = g_scenario_events[detected_scenario.key]

                    # Store the detection and update metadata
                    scenario_event.grouped_events.append(detection_event)
                    scenario_event.grouped_events_cnt += 1
                    scenario_event.last_detection_ts = time()

                except KeyError:
                    # New scenario event
                    g_scenario_events[detected_scenario.key] = detected_scenario
                finally:
                    events_lock.release()

            else:
                # Do not store any event, just bypass it to the reporter
                send_to_reporter(detection_event)

    def tear_down(self):
        self.receiver.join_and_quit()
        self.processor.stop()


if __name__ == '__main__':
    options, args = parser.parse_args()
    signal.signal(signal.SIGINT, signal_h)
    g.blacklists = utils.load_blacklists(options.blacklist_config)
    g.botnet_blacklist_indexes = utils.get_botnet_blacklist_indexes(g.blacklists)
    logger.setLevel(options.log_level)

    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 2, 2)

    trap.setDataFmt(0, pytrap.FMT_JSON, "aggregated_blacklist")
    trap.setDataFmt(1, pytrap.FMT_JSON, "blacklist_evidence")

    controller = Controller(options.adaptive_blacklist,
                            options.process_interval,
                            options.evidence_timeout)

    # Run Controller until stopped by signal
    controller.run()

    controller.tear_down()

    # Free allocated memory
    trap.finalize()
