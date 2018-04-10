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
import pytrap
import sys
import time
import logging

class SpamDetection(Thread):
    """ Data is dict of flows from multirecievers """
    def __init__(self):
        Thread.__init__(self)
        # Storage for both flow types
        self.data = dict()
        self.white_list = dict()

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

    """
    Functions that compares two strings and decide their similarity according
    to SIMILARITY_INDEX, return true if they are similar otherwise false
    """
    def is_similar(server, cluster):
        #Server, list(Server)
        for s_flow in server.sent_history:
            for cluster_server in cluster:
                for c_flow in cluster_server.sent_history:
                    if SequenceMatcher(None, s_flow.get_name(),
                                      c_flow.get_name()).ratio() > SIMILARITY_INDEX:
                        return True
        return False

    def add_entity(self, flow, key):
        """
        If record of entity with flow.SRC_IP already exist in database
        then it appends its history, otherwise add new entity to database.

        Arguments:
        flow    Basic or SMTP Flow
        key     entity identifier (SRC_IP / DST_IP)
        """
        if key in self.data.keys():
            if flow.DST_IP in self.data.keys():
                self.data[flow.DST_IP].incoming += 1
            else:
                self.data[flow.DST_IP] = SMTP_ENTITY(flow)
            self.data[key].add_new_flow(flow)
            self.data[key].update_time(flow)
        else:
            self.data[key] = SMTP_ENTITY(flow)

        if flow.TIME_LAST.getTimeAsFloat() > self.t_cflow:
            self.t_cflow = flow.TIME_LAST.getTimeAsFloat()

        return True

    def analysis(self):
        """ Do frequencual analysis here """
        potencial_spammers = list()
        self.t_detect  = time.time()

        for entity in self.data:
            self.data[entity].set_up_traffic_ratio()

            if not self.data[entity].is_legit():
                potencial_spammers.append(self.data[entity])
                print("Found potencial entity")

        print("Probing done.")
        return None

    def clean_up(self):
        """ Do clean up here, get rid off old data """
        if curr_time - last_clean > CLEAN_INTERVAL:
            data.clear()
        return None

    def run(self):
        while (True):
            if self.t_detect + PROBE_INTERVAL < self.t_cflow:
                print("Probing")
                self.analysis()
                probing = Thread(target=self.analysis, args=())
                probing.start()
                self.t_detect = time.time()

            if self.t_clean + CLEAN_INTERVAL < self.t_cflow:
                print("Cleaning")
                #self.clean_up()
                time.sleep(5)
                print("Cleaning done")
                self.t_clean = time.time()

