#!/usr/bin/env python3

# Aggregation of alerts from all blacklist detectors (IP, URL, DNS).
# Output of IP detector is pre-aggregated with standard UniRec aggregator,
# output of URL and DNS detectors is roughly the same
# Records are being aggregated 1-N in time window, where 1 is the blacklisted entry.

from threading import Timer
from threading import Lock
from threading import Thread
import sys
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
MINSRCPORT=30000

# Maximum number of dest. IPs in an event record (if there are more, they are trimmed)
MAX_DST_IPS_PER_EVENT = 1000

WWW_PREFIX = 'www.'


def signal_h(signal, f):
    global trap
    trap.terminate()


signal.signal(signal.SIGINT, signal_h)

# Global locks
locks = [Lock(), Lock()]

# Global list of events
ip_event_list = {}
url_event_list = {}

template_out = "aggregated_blacklist"


# Send aggregated events by RepeatedTimer
def send_events():
    global ip_event_list
    global url_event_list

    for event_list in [ip_event_list, url_event_list]:
        for key in event_list:
            event = event_list[key]
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

    ip_event_list = {}
    url_event_list = {}


class RepeatedTimer:
    def __init__(self, interval, function):
        self._timer = None
        self.function = function
        self.interval = interval
        self.is_running = False
        self.start()

    def _run(self):
        global locks

        for lock in locks:
            lock.acquire()

        self.is_running = False
        self.start()
        self.function()

        for lock in locks:
            lock.release()

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class IP:
    iface_num = 0

    # exact output match of pre-aggregated ipblacklistfilter
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST," + \
                  "time TIME_FIRST,time TIME_LAST,uint32 COUNT,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL"

    def __init__(self):
        self.ur_input = pytrap.UnirecTemplate(IP.template_in)
        # Set output format and disable output buffering
        trap.ifcctl(IP.iface_num, False, pytrap.CTL_BUFFERSWITCH, 0)

    def _insert_event(self, key):
        event = {
                 "type": "ip",
                 "ts_first": float(self.ur_input.TIME_FIRST),
                 "ts_last": float(self.ur_input.TIME_LAST),
                 "protocol": self.ur_input.PROTOCOL,
                 "source_ports": [],
                 "source": str(self.ur_input.SRC_IP) if self.ur_input.SRC_BLACKLIST else str(self.ur_input.DST_IP),
                 "targets": [str(self.ur_input.DST_IP)] if self.ur_input.SRC_BLACKLIST else [str(self.ur_input.SRC_IP)],
                 "src_sent_bytes": self.ur_input.BYTES if self.ur_input.SRC_BLACKLIST else 0,
                 "src_sent_flows": self.ur_input.COUNT if self.ur_input.SRC_BLACKLIST else 0,
                 "src_sent_packets": self.ur_input.PACKETS if self.ur_input.SRC_BLACKLIST else 0,
                 "tgt_sent_bytes": self.ur_input.BYTES if self.ur_input.DST_BLACKLIST else 0,
                 "tgt_sent_flows": self.ur_input.COUNT if self.ur_input.DST_BLACKLIST else 0,
                 "tgt_sent_packets": self.ur_input.PACKETS if self.ur_input.DST_BLACKLIST else 0,
                 "blacklist_bmp": self.ur_input.SRC_BLACKLIST | self.ur_input.DST_BLACKLIST,
                 "agg_win_minutes": options.time
        }

        # if self.ur_input.SRC_BLACKLIST and self.ur_input.SRC_PORT <= MINSRCPORT:
        #     event["source_ports"].append(self.ur_input.SRC_PORT)

        if self.ur_input.DST_BLACKLIST and self.ur_input.DST_PORT <= MINSRCPORT:
            event["source_ports"].append(self.ur_input.DST_PORT)

        ip_event_list[key] = event

    def _update_event(self, key):
        event = ip_event_list[key]

        # Update ports of the source (of trouble) and target IPs, this way because JSON can't handle set() itself
        source_ports = set(event["source_ports"])
        targets = set(event["targets"])

        if self.ur_input.SRC_BLACKLIST:
            # source_ports.add(self.ur_input.SRC_PORT)
            targets.add(str(self.ur_input.DST_IP))
            event["src_sent_bytes"] += self.ur_input.BYTES
            event["src_sent_flows"] += self.ur_input.COUNT
            event["src_sent_packets"] += self.ur_input.PACKETS
            event["blacklist_bmp"] |= self.ur_input.SRC_BLACKLIST
        else:
            if self.ur_input.DST_PORT <= MINSRCPORT:
                source_ports.add(self.ur_input.DST_PORT)
            targets.add(str(self.ur_input.SRC_IP))
            event["tgt_sent_bytes"] += self.ur_input.BYTES
            event["tgt_sent_flows"] += self.ur_input.COUNT
            event["tgt_sent_packets"] += self.ur_input.PACKETS
            event["blacklist_bmp"] |= self.ur_input.DST_BLACKLIST

        event["source_ports"] = list(source_ports)
        event["targets"] = list(targets)

        event["ts_first"] = min(event["ts_first"], float(self.ur_input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(self.ur_input.TIME_LAST))

    def store_event(self):
        """
        There are following cases for aggregation:
        1) SRC_IP is on some blacklist:
            we can aggregate by SRC_IP and protocol,
            SRC_IP is Source and DST_IP is Target
        2) DST_IP is on some blacklist:
            we can aggregate by DST_IP and protocol,
            DST_IP is Source and SRC_IP is Target
        """

        # Set key (blacklisted address and protocol)
        if self.ur_input.SRC_BLACKLIST:
            key = (self.ur_input.SRC_IP, self.ur_input.PROTOCOL)
        else:
            key = (self.ur_input.DST_IP, self.ur_input.PROTOCOL)

        if key in ip_event_list:
            self._update_event(key)
        else:
            self._insert_event(key)


class URL:
    iface_num = 1

    # exact output match of urlblacklistfilter
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BLACKLIST,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS," + \
                  "uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL"

    def __init__(self):
        self.ur_input = pytrap.UnirecTemplate(URL.template_in)
        # Set output format and disable output buffering
        trap.ifcctl(URL.iface_num, False, pytrap.CTL_BUFFERSWITCH, 0)

    def _insert_event(self, key):
        url = str(self.ur_input.HTTP_REQUEST_HOST)
        only_fqdn = True

        if len(str(self.ur_input.HTTP_REQUEST_URL)) > 1:
            url += str(self.ur_input.HTTP_REQUEST_URL)
            only_fqdn = False

        event = {
            "type": "url",
            # Every source/src means source of trouble (the blacklisted address)
            "source_ip": str(self.ur_input.DST_IP),
            "source_url": url,
            "referer": str(self.ur_input.HTTP_REQUEST_REFERER),
            "targets": [str(self.ur_input.SRC_IP)],
            "source_ports": [self.ur_input.DST_PORT],
            "ts_first": float(self.ur_input.TIME_FIRST),
            "ts_last": float(self.ur_input.TIME_LAST),
            "protocol": self.ur_input.PROTOCOL,
            # The detected flow is a HTTP request to blacklisted URL, so the communication we can observe is from the client
            "tgt_sent_bytes": self.ur_input.BYTES,
            "tgt_sent_flows": 1,
            "tgt_sent_packets": self.ur_input.PACKETS,
            "blacklist_bmp": self.ur_input.BLACKLIST,
            "agg_win_minutes": options.time,
            "is_only_fqdn": only_fqdn
        }

        url_event_list[key] = event

    def _update_event(self, key):
        event = url_event_list[key]

        # Update ports of the source (of trouble) and target IPs
        if self.ur_input.DST_PORT not in event["source_ports"]:
            event["source_ports"].append(self.ur_input.DST_PORT)

        if str(self.ur_input.SRC_IP) not in event["targets"]:
            event["targets"].append(str(self.ur_input.SRC_IP))

        event["ts_first"] = min(event["ts_first"], float(self.ur_input.TIME_FIRST))
        event["ts_last"] = max(event["ts_last"], float(self.ur_input.TIME_LAST))

        event["blacklist_bmp"] |= self.ur_input.BLACKLIST
        event["tgt_sent_bytes"] += self.ur_input.BYTES
        event["tgt_sent_flows"] += 1
        event["tgt_sent_packets"] += self.ur_input.PACKETS

    def store_event(self):
        """
        Aggregation is done using blacklisted URL, destination IP and L4 protocol as a key
        """

        # Set key (Host+URL, destination and L4 protocol)
        key = (self.ur_input.HTTP_REQUEST_HOST.strip(WWW_PREFIX),
               self.ur_input.HTTP_REQUEST_URL,
               self.ur_input.DST_IP,
               self.ur_input.PROTOCOL)

        if key in url_event_list:
            self._update_event(key)
        else:
            self._insert_event(key)


class Aggregator:
    def __init__(self):
        """
        Trap initialization for input and output interfaces
        """

        # Set up required format to accept any unirec format.
        trap.setRequiredFmt(IP.iface_num, pytrap.FMT_UNIREC, IP.template_in)
        trap.setRequiredFmt(URL.iface_num, pytrap.FMT_UNIREC, URL.template_in)
        # trap.setRequiredFmt(blfilter_interfaces['DNS'])    # Refers to flows with DNS headers from dnsdetect

    def _create_threads(self):
        # Create workers for each receiver
        self.ip_rcv = Thread(target=self._fetch_data, args=[IP()])
        self.url_rcv = Thread(target=self._fetch_data, args=[URL()])
        # self.dns_rcv = Thread(target=self._fetch_data, args=[blfilter_interfaces['DNS']])

    def run(self):
        self._create_threads()

        # Run multireceiver
        self.ip_rcv.start()
        self.url_rcv.start()
        # self.dns_rcv.start()

    def join(self):
        # Join the threads
        self.ip_rcv.join()
        self.url_rcv.join()
        # self.dns_rcv.join()

    def _fetch_data(self, detector_class):
        """
        Fetches data from trap context and aggregates them
        Arguments:
        trap        pytrap.trapCtx
        iface_num   int IP/URL/DNS
        queue       Queue
        """
        while True:
            try:
                data = trap.recv(detector_class.iface_num)
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(detector_class.iface_num)
                type(detector_class).ur_input = pytrap.UnirecTemplate(inputspec)
                data = e.data
            except pytrap.Terminated:
                print("Terminated TRAP.")
                break
            except pytrap.TrapError:
                break

            if len(data) <= 1:
                break

            locks[detector_class.iface_num].acquire()

            # Set data for access using attributes
            detector_class.ur_input.setData(data)
            detector_class.store_event()

            locks[detector_class.iface_num].release()


if __name__ == '__main__':
    # Parse remaining command-line arguments
    options, args = parser.parse_args()

    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 2, 1)
    trap.setDataFmt(0, pytrap.FMT_JSON, template_out)

    rt = RepeatedTimer(10, send_events)
    agg = Aggregator()
    agg.run()
    agg.join()

    rt.stop()
    send_events()
    trap.sendFlush()
    trap.finalize()



