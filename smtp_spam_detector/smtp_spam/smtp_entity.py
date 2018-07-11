"""
Copyright (C) 2016-2018 CESNET

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

#!/usr/bin/env python3
import pytrap, math
from functools import reduce
from flow import *
from global_def import *
from threading import RLock

def get_proto_by_port(port):
    for key, value in email_protocols.items():
        if value == port:
            return key

class SMTP_ENTITY:
    # SMTP_ENTITY constructor from whole unirec record or just ip from traffic
    def __init__(self, *args):
        self.id = None              # an unique entity identification (it's IP)
        self.sent_history = []      # history of sent msgs from this entity
        self.protocols = set()
        self.smtp_pool = []         # SMTP communication database
        self.basic_pool = []        # POP3/IMAP communication database
        # traffic counters
        self.incoming = 0           # counter for incoming messages from others
        self.outgoing = 0           # counter for outgoing messages from this entity
        # entity parameters
        self.bytes = 0
        self.avg_score = 0.0
        self.traffic_ratio = 0.0    # ratio of incoming/outgoing traffic
        self.packets = 0
        self.conn_cnt = 0
        self.conf_lvl = 0
        self.spam_flag = 0
        # Data lock
        self.__lock = RLock()
        # Set up parameters based on input data
        # got whole template
        if isinstance(args[0], Flow):
            # Separate basic/smtp flows
            if isinstance(args[0], SMTP_Flow):
                self.smtp_pool.append(args[0])
            else:
                self.basic_pool.append(args[0])

            self.id = args[0].SRC_IP
            self.sent_history.append(args[0])
            self.bytes = args[0].BYTES
            self.packes = args[0].PACKETS
            self.time_start = args[0].TIME_FIRST
            self.time_end = args[0].TIME_LAST
            self.outgoing += 1

        # got only ip address (args[0] is ip and args[1] is time)
        elif isinstance(args[0], pytrap.UnirecIPAddr):
            self.id = args[0]
            self.incoming += 1
            self.time_start = args[1]
            self.time_end = args[1]

        self.time_window = self.time_end.getTimeAsFloat() - self.time_start.getTimeAsFloat()

    def __hash__(self):
        return hash(self.id)

    def __str__(self):
        return ("{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}:{8}:{9}".format(self.id,
            self.packets, self.bytes, self.conn_cnt, self.conf_lvl, self.spam_flag,
            len(self.smtp_pool), len(self.basic_pool), self.incoming, self.outgoing)
        )

    def __repr__(self):
        return ("{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}:{8}:{9}:{10}".format(self.id,
            self.packets, self.bytes, self.conn_cnt, self.conf_lvl, self.spam_flag,
            len(self.smtp_pool), len(self.basic_pool),self.incoming, self.outgoing)
        )

    def update_avg_score(self, score):
        self.avg_score += score / len(self.sent_history)

    # Updates time_end parameter of this entity
    def update_time(self, flow):
        if flow.TIME_LAST > self.time_end:
            self.time_end = flow.TIME_LAST
            self.time_window = self.time_end.getTimeAsFloat() - self.time_start.getTimeAsFloat()
        else:
            return None

    # Function that adds flows for server history
    def add_new_flow(self, flow):
        with self.__lock:
            self.packets += flow.PACKETS
            self.bytes += flow.BYTES
            self.sent_history.append(flow)
            if type(flow) is Flow:
                self.basic_pool.append(flow)
                self.protocols.add(get_proto_by_port(flow.DST_PORT))
                if flow.TCP_FLAGS > 2: # if there is not only SYN flag
                    self.avg_score -= 5
            else:
                self.smtp_pool.append(flow)
                self.update_avg_score(flow.get_score())
                self.protocols.add("SMTP")
            self.update_time(flow)
            self.outgoing += 1

    def set_conf(self, score):
        self.conf_lvl = (1/(math.exp(-1 * score/3) + 1))
        return self.conf_lvl

    def is_spam(self):
        score = self.avg_score
        if (self.incoming == 0):
            try:
                score += math.log(self.outgoing)
            except ValueError:
                sys.stderr.write("smtp_entity: Math error")
        sent = len(self.sent_history)
        if sent is not 0:
            traffic_ratio = self.incoming / sent
        else:
            traffic_ratio = 0
        # Check for unique DST_IPs
        unique_ips = set()
        with self.__lock:
            for flow in self.sent_history:
                unique_ips.add(flow.DST_IP)
        self.conn_cnt = len(unique_ips)
        if self.conn_cnt > MAX_ALLOWED_SERVERS or traffic_ratio > 1.2:
            score -= 1
        else:
            score += 1
        return self.set_conf(score)


    def get_emails(self):
        emails = set()
        with self.__lock:
            for host in self.smtp_pool:
                emails.add(host.SMTP_FIRST_SENDER)
        return list(emails)

    def get_hostnames(self):
        hosts = set()
        with self.__lock:
            for host in self.smtp_pool:
                hosts.add(host.SMTP_DOMAIN)
        return list(hosts)

    def get_proto(self):
        return self.protocols

