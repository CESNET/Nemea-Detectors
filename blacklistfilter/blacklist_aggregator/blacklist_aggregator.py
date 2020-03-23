#!/usr/bin/env python3

# Aggregation of alerts from all blacklist detectors (IP, URL, DNS).
# Output of IP detector is pre-aggregated with standard UniRec aggregator,
# output of URL and DNS detectors is roughly the same
# Records are being aggregated 1-N in time window, where 1 is the blacklisted entry.

from threading import Timer
from threading import Thread
from datetime import datetime
import queue
import sys
import os
import signal
import json
import pytrap

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option("-t", "--time", dest="time", type="float",
                  help="Length of time interval in which alerts are aggregated.", metavar="MINUTES", default=5)

# All ports higher than MINSRCPORT are considered as dynamic/private;
# therefore, let's put lower ports into IDEA messages.
MINSRCPORT=49152

# Maximum number of dest. IPs in an event record (if there are more, they are trimmed)
MAX_DST_IPS_PER_EVENT = 1000

WWW_PREFIX = 'www.'

stop = 0


def signal_h(signal, f):
    global stop, trap
    if stop:
        print('Caught another SIGINT, exiting forcefully..')
        os._exit(1)
    print('Caught SIGINT, exiting gracefully..')
    trap.terminate()
    stop = 1


# Global dicts of events
ip_events = {}
url_events = {}

template_out = "aggregated_blacklist"


# Send aggregated events by RepeatedTimer
def send_events():
    global ip_events
    global url_events

    # No need for locking, store reference global lists to local variables and point global lists to new, empty dicts.
    # The processor threads then write into those new (empty) dicts
    my_ip_events = ip_events
    my_url_events = url_events
    ip_events = {}
    url_events = {}

    for events in [my_ip_events, my_url_events]:
        for event in events.values():
            # Convert targets from IPAddr objects to str
            event["targets"] = [str(target) for target in event["targets"]]
            event["source_ports"] = list(event["source_ports"])

            # Convert source/source_ip to str
            try:
                event["source"] = str(event["source"])
            except KeyError:
                event["source_ip"] = str(event["source_ip"])

            try:
                # To avoid too long messages, split the event if there are more 1000 IPs
                if len(event["targets"]) > MAX_DST_IPS_PER_EVENT:
                    targets = event["targets"]
                    while targets:
                        event_copy = event.copy()
                        event_copy["targets"] = targets[:MAX_DST_IPS_PER_EVENT]
                        targets = targets[MAX_DST_IPS_PER_EVENT:]
                        trap.send(bytearray(json.dumps(event_copy), "utf-8"))

                else:
                    # Send data to output interface
                    trap.send(bytearray(json.dumps(event), "utf-8"))
            except pytrap.Terminated:
                print("Terminated TRAP.")
                break

            except pytrap.TimeoutError:
                print("{}: Warning: dropped event because of TimeoutError".format(datetime.now().strftime("%F-%T")))


class RepeatedTimer:
    def __init__(self, interval, function):
        self._timer = None
        self.function = function
        self.interval = interval
        self.is_running = False
        self.start()

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


class IPProcessor:
    iface_num = 0

    # exact output match of pre-aggregated ipblacklistfilter
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST," + \
                  "time TIME_FIRST,time TIME_LAST,uint32 COUNT,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL"

    def __init__(self):
        self.queue = queue.Queue()
        self.ur_input = pytrap.UnirecTemplate(IPProcessor.template_in)

    def _insert_event(self, key):
        event = {
            "type": "ip",
            "ts_first": float(self.ur_input.TIME_FIRST),
            "ts_last": float(self.ur_input.TIME_LAST),
            "protocol": self.ur_input.PROTOCOL,
            "source_ports": set(),
            "source": self.ur_input.SRC_IP if self.ur_input.SRC_BLACKLIST else self.ur_input.DST_IP,
            "targets": {self.ur_input.DST_IP} if self.ur_input.SRC_BLACKLIST else {self.ur_input.SRC_IP},
            "src_sent_bytes": self.ur_input.BYTES if self.ur_input.SRC_BLACKLIST else 0,
            "src_sent_flows": self.ur_input.COUNT if self.ur_input.SRC_BLACKLIST else 0,
            "src_sent_packets": self.ur_input.PACKETS if self.ur_input.SRC_BLACKLIST else 0,
            "tgt_sent_bytes": self.ur_input.BYTES if self.ur_input.DST_BLACKLIST else 0,
            "tgt_sent_flows": self.ur_input.COUNT if self.ur_input.DST_BLACKLIST else 0,
            "tgt_sent_packets": self.ur_input.PACKETS if self.ur_input.DST_BLACKLIST else 0,
            "blacklist_id": self.ur_input.SRC_BLACKLIST | self.ur_input.DST_BLACKLIST,
            "agg_win_minutes": options.time
        }

        # if self.ur_input.SRC_BLACKLIST and self.ur_input.SRC_PORT <= MINSRCPORT:
        #     event["source_ports"].add(self.ur_input.SRC_PORT)

        if self.ur_input.DST_BLACKLIST and self.ur_input.DST_PORT <= MINSRCPORT:
            event["source_ports"].add(self.ur_input.DST_PORT)

        ip_events[key] = event

    def _update_event(self, event):
        """
        Update already existing event, data is passed implicitly through self.ur_input object
        """
        if self.ur_input.SRC_BLACKLIST:
            # source_ports.add(self.ur_input.SRC_PORT)
            event["targets"].add(self.ur_input.DST_IP)
            event["src_sent_bytes"] += self.ur_input.BYTES
            event["src_sent_flows"] += self.ur_input.COUNT
            event["src_sent_packets"] += self.ur_input.PACKETS
        else:
            if self.ur_input.DST_PORT <= MINSRCPORT:
                event["source_ports"].add(self.ur_input.DST_PORT)
            event["targets"].add(self.ur_input.SRC_IP)
            event["tgt_sent_bytes"] += self.ur_input.BYTES
            event["tgt_sent_flows"] += self.ur_input.COUNT
            event["tgt_sent_packets"] += self.ur_input.PACKETS

        event["ts_first"] = min(event["ts_first"], float(self.ur_input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(self.ur_input.TIME_LAST))

    def store_event(self):
        """
        There are following cases for aggregation:
        1) SRC_IP is on some blacklist:
            we can aggregate by SRC_IP, its blacklist and protocol,
            SRC_IP is Source and DST_IP is Target
        2) DST_IP is on some blacklist:
            we can aggregate by DST_IP, its blacklist and protocol,
            DST_IP is Source and SRC_IP is Target

        If the entity is on more than one blacklist, there will be an event for each blacklist index
        """

        bmp = self.ur_input.SRC_BLACKLIST if self.ur_input.SRC_BLACKLIST else self.ur_input.DST_BLACKLIST

        if bmp & (bmp - 1) == 0:
            # Bitmap is a power of 2, so the entity is only on one blacklist (most of the cases)
            blists = [bmp]
        else:
            # Split blacklist bitmap, so we aggregate only one blacklist
            blists = split_blacklist_bmp(bmp)

        for blist in blists:
            if self.ur_input.SRC_BLACKLIST:
                self.ur_input.SRC_BLACKLIST = blist
                key = (self.ur_input.SRC_IP, self.ur_input.PROTOCOL, blist)
            else:
                self.ur_input.DST_BLACKLIST = blist
                key = (self.ur_input.DST_IP, self.ur_input.PROTOCOL, blist)

            event = ip_events.get(key)
            if event is None:
                self._insert_event(key)
            else:
                self._update_event(event)


class URLProcessor:
    iface_num = 1

    # exact output match of urlblacklistfilter
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BLACKLIST,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS," + \
                  "uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL"

    def __init__(self):
        self.queue = queue.Queue()
        self.ur_input = pytrap.UnirecTemplate(URLProcessor.template_in)

    def _insert_event(self, key):
        url = str(self.ur_input.HTTP_REQUEST_HOST)
        only_fqdn = True

        if len(str(self.ur_input.HTTP_REQUEST_URL)) > 1:
            url += str(self.ur_input.HTTP_REQUEST_URL)
            only_fqdn = False

        event = {
            "type": "url",
            # Every source/src means source of trouble (the blacklisted address)
            "source_ip": self.ur_input.DST_IP,
            "source_url": url,
            "referer": str(self.ur_input.HTTP_REQUEST_REFERER),
            "targets": {self.ur_input.SRC_IP},
            "source_ports": {self.ur_input.DST_PORT},
            "ts_first": float(self.ur_input.TIME_FIRST),
            "ts_last": float(self.ur_input.TIME_LAST),
            "protocol": self.ur_input.PROTOCOL,
            # The detected flow is a HTTP request to blacklisted URL, so the communication we can observe is from the client
            "tgt_sent_bytes": self.ur_input.BYTES,
            "tgt_sent_flows": 1,
            "tgt_sent_packets": self.ur_input.PACKETS,
            "blacklist_id": self.ur_input.BLACKLIST,
            "agg_win_minutes": options.time,
            "is_only_fqdn": only_fqdn
        }

        url_events[key] = event

    def _update_event(self, event):
        """
        Update already existing event, data is passed implicitly through self.ur_input object
        """
        # Update ports of the source (of trouble) and target IPs
        event["source_ports"].add(self.ur_input.DST_PORT)
        event["targets"].add(self.ur_input.SRC_IP)

        event["ts_first"] = min(event["ts_first"], float(self.ur_input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(self.ur_input.TIME_LAST))

        event["tgt_sent_bytes"] += self.ur_input.BYTES
        event["tgt_sent_flows"] += 1
        event["tgt_sent_packets"] += self.ur_input.PACKETS

    def store_event(self):
        """
        Aggregation is done using blacklisted URL, destination IP and L4 protocol as a key

        If the entity is on more than one blacklist, there will be an event for each blacklist index
        """

        bmp = self.ur_input.BLACKLIST

        if bmp & (bmp - 1) == 0:
            # Bitmap is a power of 2, so the entity is only on one blacklist (most of the cases)
            blists = [bmp]
        else:
            # Split blacklist bitmap, so we aggregate only one blacklist
            blists = split_blacklist_bmp(self.ur_input.BLACKLIST)

        for blist in blists:
            self.ur_input.BLACKLIST = blist
            # Set key (Host+URL, destination and L4 protocol)
            key = (self.ur_input.HTTP_REQUEST_HOST.lstrip(WWW_PREFIX),
                   self.ur_input.HTTP_REQUEST_URL,
                   self.ur_input.DST_IP,
                   self.ur_input.PROTOCOL,
                   blist
                   )

            event = url_events.get(key)
            if event is None:
                self._insert_event(key)
            else:
                self._update_event(event)


class Aggregator:
    def __init__(self):
        """
        Trap initialization for input and output interfaces
        """
        # Set up required format to accept any unirec format.
        trap.setRequiredFmt(IPProcessor.iface_num, pytrap.FMT_UNIREC, IPProcessor.template_in)
        trap.setRequiredFmt(URLProcessor.iface_num, pytrap.FMT_UNIREC, URLProcessor.template_in)
        # trap.setRequiredFmt(blfilter_interfaces['DNS'])    # Refers to flows with DNS headers from dnsdetect

        # Create workers for each receiver
        ip = IPProcessor()
        url = URLProcessor()
        self.ip_receiver = Thread(target=self._receive_data, args=[ip])
        self.ip_processor = Thread(target=self._process_data, args=[ip])

        self.url_receiver = Thread(target=self._receive_data, args=[url])
        self.url_processor = Thread(target=self._process_data, args=[url])

    def run(self):
        # Run multireceiver
        self.ip_receiver.start()
        self.url_receiver.start()
        self.ip_processor.start()
        self.url_processor.start()

    def join(self):
        # Join the threads
        self.ip_receiver.join()
        self.url_receiver.join()
        self.ip_processor.join()
        self.url_processor.join()

    @staticmethod
    def _process_data(detector_class):
        my_queue = detector_class.queue
        my_store_event = detector_class.store_event

        while not stop:
            try:
                data = my_queue.get(timeout=1)
            except queue.Empty:
                continue
            detector_class.ur_input.setData(data)
            my_store_event()

    @staticmethod
    def _receive_data(detector_class):
        """
        Fetches data from trap context and aggregates them
        Arguments:
        trap        pytrap.trapCtx
        iface_num   int IP/URL/DNS
        queue       Queue
        """
        my_iface_num = detector_class.iface_num
        my_queue = detector_class.queue

        while not stop:
            try:
                data = trap.recv(my_iface_num)
            except pytrap.FormatMismatch:
                print("Error: output and input interfaces data format or data specifier mismatch")
                break
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(my_iface_num)
                detector_class.ur_input = pytrap.UnirecTemplate(inputspec)
                data = e.data
            except pytrap.Terminated:
                print("Terminated TRAP.")
                break
            except pytrap.TrapError:
                print("TrapError.")
                break

            if len(data) <= 1:
                break

            my_queue.put(data)


def split_blacklist_bmp(blacklist_bmp):
    bin_bmp = bin(blacklist_bmp).replace('0b', '')[::-1]
    return [2 ** i for i, c in enumerate(bin_bmp) if c == '1']


if __name__ == '__main__':
    # Parse remaining command-line arguments
    options, args = parser.parse_args()
    signal.signal(signal.SIGINT, signal_h)

    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 2, 1)
    trap.setDataFmt(0, pytrap.FMT_JSON, template_out)

    rt = RepeatedTimer(float(options.time) * 60, send_events)

    agg = Aggregator()
    agg.run()
    agg.join()

    rt.stop()
    send_events()

    trap.sendFlush()
    trap.finalize()

