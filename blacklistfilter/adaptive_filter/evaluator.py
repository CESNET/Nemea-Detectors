#!/usr/bin/env python3

import pytrap
import sys
import json
import adaptive_filter_files.utils as utils

from collections import defaultdict

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")

IRC_MIN_PORT = 6660
IRC_MAX_PORT = 6670
ADAPTIVE_BLACLIST_IDS = 999

g_cc_ips = []
g_nerd_api_key = None

from optparse import OptionParser
parser = OptionParser(add_help_option=True)
parser.add_option("-i", "--ifcspec", dest="ifcspec",
                  help="TRAP IFC specifier", metavar="IFCSPEC")
parser.add_option('-c', '--blacklist-config', help="Set path to config file of blacklist downloader.",
                  default="/etc/nemea/blacklistfilter/bl_downloader_config.xml")
parser.add_option('-4', '--ip4-detector-file', help="Set path to file with all blacklisted IPv4 addresses "
                                                     "(detector file for IP detector)",
                  default="/tmp/blacklistfilter/ip4.blist")
parser.add_option('-n', '--nerd-api-key', help="Set NERD api key for obtaining info about clients", default=None)


class Evidence:
    def __init__(self):
        self.adaptive_evidence = AdaptiveEvidence().load_data()
        self.detection_evidence = DetectionEvidence().load_data()
        self.gathered_adaptive_evidence = self.gather_adaptive_evidence_by_id()
        self.final_evidence = []

    def gather_adaptive_evidence_by_id(self):
        gathered = {}
        for event in self.adaptive_evidence:
            ids = event.ADAPTIVE_IDS.split(',')
            for id in ids:
                try:
                    gathered[id].append(event)
                except KeyError:
                    gathered[id] = []
        return gathered

    def merge_evidence(self):
        for event in self.detection_evidence:
            try:
                event["adaptive_events"] = self.gathered_adaptive_evidence[event["id"]]
            except KeyError:
                # No adaptive evidence for this detection event
                event["adaptive_events"] = None
            finally:
                self.final_evidence.append(event)

    @staticmethod
    def get_cc_communication_count(adaptive_events, cc):
        cc_flows = defaultdict(list)
        for adaptive_event in adaptive_events:
            if str(adaptive_event.SRC_IP) == cc:
                cc_flows[adaptive_event.DST_IP].append(adaptive_event)

            elif str(adaptive_event.DST_IP) == cc:
                cc_flows[adaptive_event.SRC_IP].append(adaptive_event)

        return cc_flows

    @staticmethod
    def get_irc_flows(adaptive_events, suspicious_clients):
        irc_flows = defaultdict(list)
        for adaptive_event in adaptive_events:
            if IRC_MIN_PORT <= int(adaptive_event.DST_PORT) <= IRC_MAX_PORT or \
               IRC_MIN_PORT <= int(adaptive_event.SRC_PORT) <= IRC_MAX_PORT:
                    if str(adaptive_event.SRC_IP) in suspicious_clients:
                        # Store the event to the suspicious client, not the other IP
                        irc_flows[adaptive_event.SRC_IP].append(adaptive_event)
                    else:
                        irc_flows[adaptive_event.DST_IP].append(adaptive_event)

        return irc_flows

    @staticmethod
    def get_other_cc_flows(adaptive_events):
        other_cc_flows = defaultdict(list)
        for adaptive_event in adaptive_events:
            if str(adaptive_event.DST_IP) in g_cc_ips:
                other_cc_flows[adaptive_event.SRC_IP].append(adaptive_event)
            elif str(adaptive_event.SRC_IP) in g_cc_ips:
                other_cc_flows[adaptive_event.DST_IP].append(adaptive_event)

        return other_cc_flows

    @staticmethod
    def clear_dns_traffic(adaptive_events):
        to_del = []
        for adaptive_event in adaptive_events:
            if adaptive_event.DST_PORT == 53 or adaptive_event.SRC_PORT == 53:
                to_del.append(adaptive_event)

        for event_to_del in to_del:
            adaptive_events.remove(event_to_del)

        return adaptive_events

    def process(self):
        for event in self.final_evidence:
            if not event["adaptive_events"]:
                # No adaptive events for this detection event
                continue
            suspicious_clients = defaultdict(set)
            adaptive_events = self.clear_dns_traffic(event["adaptive_events"])

            for adaptive_event in adaptive_events:
                if adaptive_event.SRC_BLACKLIST == ADAPTIVE_BLACLIST_IDS:
                    suspicious_clients[adaptive_event.SRC_IP].add(str(adaptive_event.DST_IP))
                else:
                    suspicious_clients[adaptive_event.DST_IP].add(str(adaptive_event.SRC_IP))

            cc = event['key']
            cc_flows = self.get_cc_communication_count(adaptive_events, cc)
            irc_flows = self.get_irc_flows(adaptive_events, suspicious_clients.keys())
            other_cc_flows = self.get_other_cc_flows(adaptive_events)

            for suspicious_client in suspicious_clients.keys():
                nerd_events = None
                if g_nerd_api_key:
                    nerd_events = consult_nerd(suspicious_client, g_nerd_api_key)

                cc_flow_count = 0
                irc_flow_count = 0
                other_cc_flow_count = 0

                if suspicious_client in cc_flows.keys():
                    cc_flow_count += len(cc_flows[suspicious_client])
                if suspicious_client in irc_flows.keys():
                    irc_flow_count += len(irc_flows[suspicious_client])
                if suspicious_client in other_cc_flows.keys():
                    other_cc_flow_count += len(other_cc_flows[suspicious_client])

                if cc_flow_count or irc_flow_count or other_cc_flow_count:
                    print('-------------------- SUSPICIOUS CLIENT REPORT --------------------')
                    print('event ID: {}'.format(event["id"]))
                    print('CC Server: {}'.format(event["key"]))
                    print('Suspicious client: {}'.format(suspicious_client))
                    if cc_flow_count:
                        print('Detected flows with this CC server: {}'.format(cc_flow_count))
                    if irc_flow_count:
                        print('Detected flows with IRC ports: {}'.format(irc_flow_count))
                    if other_cc_flows:
                        print('Detected flows with other blacklisted CC: {}'.format(other_cc_flow_count))
                    if nerd_events:
                        print('NERD INFO: {}'.format(nerd_events))


class EvidenceLoader:
    def load_data(self):
        all_data = []
        while True:
            try:
                data = trap.recv(self.iface_num)
            except pytrap.FormatMismatch:
                print("Error: output and input interfaces data format or data specifier mismatch")
                break
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(self.iface_num)
                self.input = pytrap.UnirecTemplate(inputspec)
                data = e.data
            except pytrap.Terminated:
                print("Terminated TRAP.")
                break
            except pytrap.TrapError:
                break
            if len(data) <= 1:
                break

            if isinstance(self, DetectionEvidence):
                rec = json.loads(data.decode())
            else:
                rec = self.input.copy()
                rec.setData(data)

            all_data.append(rec)

        return all_data


class AdaptiveEvidence(EvidenceLoader):
    iface_num = 0

    template_type = pytrap.FMT_UNIREC
    template_in = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST," \
                           "time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL," \
                           "string ADAPTIVE_IDS"

    def __init__(self):
        trap.setRequiredFmt(self.iface_num, self.template_type, self.template_in)
        self.input = pytrap.UnirecTemplate(self.template_in)
        self.data = None


class DetectionEvidence(EvidenceLoader):
    iface_num = 1

    template_type = pytrap.FMT_JSON
    template_in = "blacklist_evidence"

    def __init__(self):
        trap.setRequiredFmt(self.iface_num, self.template_type, self.template_in)
        self.data = None


def consult_nerd(suspicious_client, api_key):
    client_data = utils.nerd_query(api_key, suspicious_client)

    if client_data and "events" in client_data.keys():
        return client_data["events"]
    else:
        return None


def get_other_cc_ips_from_detection_file(file, botnet_idxs):
    cc_ips = []
    with open(file, 'r') as f:
        for line in f.readlines():
            ip, bl_idx = line.split(',')
            if int(bl_idx) in botnet_idxs:
                cc_ips.append(ip)
    return cc_ips


if __name__ == '__main__':
    options, args = parser.parse_args()
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 2, 0)
    blacklists = utils.load_blacklists(options.blacklist_config)

    botnet_idxs = utils.get_botnet_blacklist_indexes(blacklists)
    g_cc_ips = get_other_cc_ips_from_detection_file(options.ip4_detector_file, botnet_idxs)
    g_nerd_api_key = options.nerd_api_key
    if not g_nerd_api_key:
        print('To use NERD for client info, please enter api-key')

    evidence = Evidence()

    evidence.gather_adaptive_evidence_by_id()
    evidence.merge_evidence()

    evidence.process()
