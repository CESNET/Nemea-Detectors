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
""" Module imports """
from cluster import Cluster
from flow import Flow, SMTP_Flow
from smtp_entity import *
""" Partial imports """
from difflib import SequenceMatcher
from pytrap import TrapCtx
from threading import *
from global_def import *
""" Full imports """
import pytrap, sys, os, time, logging, json
# In case we are in nemea/modules/report2idea/ and we want to import from repo:
sys.path.insert(0, os.path.join(os.path.dirname(__file__),
                "..", "..", "nemea-framework", "pycommon"))

import argparse
import report2idea
import datetime
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
        self.cluster = Cluster()
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
                self.data[key].update_time(flow)
            else:
                self.data[key] = SMTP_ENTITY(flow)

            if flow.TIME_LAST.getTimeAsFloat() > self.t_cflow:
                self.t_cflow = flow.TIME_LAST.getTimeAsFloat()
        return True

    def create_report(self, entity):
        print("Creating report for {0}".format(entity))
        ip = ()
        if entity.id.isIPv4() is True:
            ip = ("IP4", entity.id)
        else:
            ip = ("IP6", entity.id)

        if len(entity.smtp_pool) is 0 and len(entity.basic_pool) is 0:
            return None

        confidience = 0.1 #entity.get_confidence()

        idea = {
            "Format": "IDEA0",
            "ID": report2idea.getRandomId(),
            "DetectTime": self.t_detect,
            "CreateTime": datetime.datetime.utcnow().isoformat("T") + "Z",
            "EventTime": report2idea.getIDEAtime(entity.time_start),
            "CeaseTime": report2idea.getIDEAtime(entity.time_end),
            "Category": ["Abusive.Spam"],
            "Note": "Testing example",
            "Confidence": confidience,
            "Source": [{
              "Hostname" : list(entity.get_hostnames()),
              "Email" : list(entity.get_emails()),
              ip[0] : str(ip[1]),
              "Proto" : list(entity.get_proto()),
            }]
        }
        print("*******************************IDEA*************************************")
        print(json.dumps(idea, sort_keys=True, indent=4, separators=(',', ': ')))
        return json.dumps(idea)

    def send_reports(self, reports):
        rep_cnt = 0
        for report in reports:
            if report is not None:
                self.trap.send(str(report).encode())
                rep_cnt += 1
            print("Send reports : {0} / {1}".format(rep_cnt, len(reports)))

    def analysis(self):
        """
        Do frequency analysis here
        """
        potencial_spammers = set()
        self.t_detect  = time.time()
        print("Probing...")
        with self.data_lock:
            for entity in self.data:
                self.checked += 1
                if not self.data[entity].is_legit():
                    potencial_spammers.add(self.data[entity])
        # Data analysis
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
        workers = []
        while (True):
            if self.t_detect + PROBE_INTERVAL < self.t_cflow:
                worker = Thread(target=self.analysis, args=())
                worker.start()
                workers.append(worker)
                self.t_detect = time.time()

            if self.t_clean + CLEAN_INTERVAL < self.t_cflow:
                self.clear()
                [ worker.join() for worker in workers ]

