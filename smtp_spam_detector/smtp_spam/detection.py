"""
Copyright (C) 2017-2018 CESNET

LICENSE TERMS

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.
3. Neither the name of the Company nor the names of its contributors
   may be used to endorse or promote products derived from this
   software without specific prior written permission.

ALTERNATIVELY, provided that this notice is retained in full, this
product may be distributed under the terms of the GNU General Public
License (GPL) version 2 or later, in which case the provisions
of the GPL apply INSTEAD OF those given above.

This software is provided ``as is'', and any express or implied
warranties, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose are disclaimed.
In no event shall the company or contributors be liable for any
direct, indirect, incidental, special, exemplary, or consequential
damages (including, but not limited to, procurement of substitute
goods or services; loss of use, data, or profits; or business
interruption) however caused and on any theory of liability, whether
in contract, strict liability, or tort (including negligence or
otherwise) arising in any way out of the use of this software, even
if advised of the possibility of such damage.
"""
#!/usr/bin/env python
#from cluster import Cluster
from flow import Flow, SMTP_Flow
from smtp_entity import *
from pytrap import TrapCtx
from threading import *
from global_def import *
import pytrap, sys, os, time, datetime, logging, json, report2idea
# In case we are in nemea/modules/report2idea/ and we want to import from repo:
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "nemea-framework", "pycommon"))

class SpamDetection(Thread):
    """
    Data is dict of flows from multirecievers
    """
    def __init__(self, trap):
        Thread.__init__(self)
        # Storage for both flow types
        self.data = dict()
        self.white_list = dict()
        self.data_lock = RLock()

        # Blacklisted entites that are probably spammers
        self.potencial_spammers = list()
        # TODO
        self.whitelist = {}
        self.blacklist = {}

        # Timers and timestamps
        self.t_clean = 0                # last cleaning time
        self.t_detect = 0               # last detection time
        #self.t_cluster = 0             # last clustering time
        self.t_cflow = 0                # current time in context of processing flows
        """
        Counters for how many flows has been checked, and how many alerts
        has been generated.
        """
        self.checked = 0
        self.alerts = 0

        # Cluster for clustering spammers, further analysis
        #self.cluster = Cluster()
        self.trap = trap

    def add_entity(self, flow, key):
        """
        If record of entity with flow.SRC_IP already exist in database
        then it appends its history, otherwise add new entity to database.

        Arguments:
        flow    Basic or SMTP Flow
        key     entity identifier (SRC_IP / DST_IP)
        """
        with self.data_lock:
            if key in self.data.keys():
                # Check for receivers
                if flow.DST_IP in self.data.keys():
                    self.data[flow.DST_IP].incoming += 1
                else:
                    self.data[flow.DST_IP] = SMTP_ENTITY(flow.DST_IP, flow.TIME_LAST)
                self.data[key].add_new_flow(flow)
            else:
                self.data[key] = SMTP_ENTITY(flow)
        if flow.TIME_LAST.getTimeAsFloat() > self.t_cflow:
                self.t_cflow = flow.TIME_LAST.getTimeAsFloat()
        return True

    def create_report(self, entity):
        ip = ()
        if entity.id.isIPv4() is True:
            ip = ("IP4", entity.id)
        else:
            ip = ("IP6", entity.id)
        idea = {}
        first_senders =  list(entity.get_emails())
        hosts = list(entity.get_hostnames())
        if (len(first_senders) > 5):
            first_senders = first_senders[:5]
        if (len(hosts) > 5):
            hosts = hosts[:5]

        try:
            idea = {
                "Format": "IDEA0",
                "ID": report2idea.getRandomId(),
                "DetectTime": datetime.datetime.fromtimestamp(self.t_detect).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "CreateTime": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "EventTime": report2idea.getIDEAtime(entity.time_start),
                "CeaseTime": report2idea.getIDEAtime(entity.time_end),
                "Category": ["Abusive.Spam"],
                "Note": "Testing example",
                "Confidence": entity.conf_lvl,
                "Source": [{
                  "Hostname" : hosts,
                  "Email" : first_senders,
                  ip[0] : str(ip[1]),
                  "Proto" : list(entity.get_proto()),
                }],
                "ByteCount" : entity.bytes,
                "FlowCount" : len(entity.sent_history),
                "PacketCount" : entity.packets,
                "ConnCount" : entity.conn_cnt
            }
        except Exception:
            sys.stderr.write("Idea creation for {0} failed.\n".format(entity))
            pass

        return json.dumps(idea)

    def send_reports(self, reports):
        rep_cnt = 0
        for report in reports:
            if report is not None:
                try:
                    self.trap.send(str(report).encode())
                    rep_cnt += 1
                except Exception:
                    sys.stderr.write("detection: Could not send json through trap interface.\n")
        print("Sent {0} / {1} reports".format(rep_cnt, len(reports)))

    def analysis(self):
        """
        Do frequency analysis here
        """
        self.t_detect  = self.t_cflow
        potencial_spammers = set()
        print("Probing...")
        with self.data_lock:
            for entity in self.data:
                self.checked += 1
                if self.data[entity].is_spam() > 0.85:
                    potencial_spammers.add(self.data[entity])
                #print(self.data[entity])
        ps = len(potencial_spammers)
        dl = len(self.data)
        if ps is not 0:
            part = (float(ps)/float(dl))
        else:
            part = 0
        print("Found {0} potential spammers in {1} [{2:.5%}]".format(ps, dl, float(part)))
        self.send_reports([ self.create_report(entity) for entity in potencial_spammers ])
        print("Analysis run done!")

    def clear(self):
        """
        Do clean up here, get rid off old data
        """
        if self.t_clean + CLEAN_INTERVAL < self.t_cflow:
            self.data.clear()
            self.t_clean = time.time()

    def run(self):
        sys.stderr.write("Detection running with probe interval:{0}\n".format(PROBE_INTERVAL))
        workers = []
        while (True):
            if self.t_detect + PROBE_INTERVAL < self.t_cflow:
                sys.stderr.write("Creating analysis thread {0}.\n".format(len(workers)))
                worker = Thread(target=self.analysis, args=())
                worker.start()
                workers.append(worker)
                self.t_detect  = self.t_cflow
                #self.analysis()
            if self.t_clean + CLEAN_INTERVAL < self.t_cflow:
                self.clear()

            if len(workers) > MAX_WORKERS:
                for worker in workers: worker.join()
                workers.clear()

