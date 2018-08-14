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

Authors:
    Ladislav Macoun <ladislavmacoun@gmail.com>

"""

#!/usr/bin/env python3
import pytrap
import math
import logging

from flow import *
from g import *
from threading import RLock

def get_proto_by_port(port):
    for key, value in email_protocols.items():
        if value == port:
            return key

log = logging.getLogger('smtp_spam.smtp_entity')

class SMTP_ENTITY:
    # SMTP_ENTITY constructor from whole unirec record or just ip from traffic
    def __init__(self, *args):
        self.id = None              # an unique entity identification (it's IP)
        self.sent_history = []      # history of sent msgs from this entity #TODO
        self.protocols = set()
        self.smtp_pool = []         # SMTP communication database
        self.basic_pool = []        # POP3/IMAP communication database
        # traffic counters
        self.incoming = 0           # counter for incoming messages from others
        self.outgoing = 0           # counter for outgoing messages from this entity
        # entity parameters (feature vector)
        self.bytes = 0              # counter for volume of sent data
        self.avg_score = 0.0        # average score of communication rules
        self.traffic_ratio = 0.0    # ratio of incoming/outgoing traffic
        self.packets = 0            # counter for volume of sent packets
        self.conn_cnt = 0           # unique entity connection counter
        self.conf_lvl = 0           # level of confidence
        self.fv = []                # feature vector
        self.tags = set()           # triggered rules by detector
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
        with self.__lock:
            return ("SMTP_ENTITY[{0}]\n"
                    "\tpackets sent:{1}\n"
                    "\tbytes sent:{2}\n"
                    "\tconnection count:{3}\n"
                    "\tconfidence level:{4}\n"
                    "\tsent smtp messages:{5}\n"
                    "\tsent basic messages:{6}\n"
                    "\ttotal received:{7}\n"
                    "\ttotal sent:{8}\n".format(self.id, self.packets, self.bytes,
                                                self.conn_cnt, self.conf_lvl,
                                                len(self.smtp_pool), len(self.basic_pool),
                                                self.incoming, self.outgoing)
                    )

    def __repr__(self):
        with self.__lock:
            return ("{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}:{8}:{9}:{10}:{11}".format(self.id,
                    self.time_start, self.time_end, self.time_window,
                    self.incoming, self.outgoing, len(self.smtp_pool), len(self.basic_pool),
                    self.bytes, self.packets, self.avg_score, self.conf_lvl)
                   )

    def update_avg_score(self, score):
        with self.__lock:
            self.avg_score += score / len(self.sent_history)
        return None

    # Updates time_end parameter of this entity
    def update_time(self, flow):
        """
        The detection time is based on flow time. Thus we need an updater for
        time based on flow parameters
        """
        if flow.TIME_LAST > self.time_end:
            self.time_end = flow.TIME_LAST
            self.time_window = self.time_end.getTimeAsFloat() - self.time_start.getTimeAsFloat()
        else:
            return None

    def add_new_flow(self, flow):
        """
        Adds new flow the history records of this entity and filter different
        protocols that are evaluated with score value to help distinguish
        legit servers
        """
        with self.__lock:
            self.packets += flow.PACKETS
            self.bytes += flow.BYTES
            self.sent_history.append(flow)

            if type(flow) is Flow:
                self.basic_pool.append(flow)
                self.protocols.add(get_proto_by_port(flow.DST_PORT))

            else:
                #log.debug("added flow with addr: {}".format(flow.SMTP_FIRST_SENDER))
                self.smtp_pool.append(flow)
                self.update_avg_score(flow.get_score())
                self.protocols.add("SMTP")

            self.update_time(flow)
            self.outgoing += 1

        return None

    def set_conf(self, score):
        """
        Set the confidence level of the entity being a spam.
        It used a non-linear function that adjust the value to correspond
        with the percentage value.

        The math function is          1
                                  ----------
                            f :=  e^-x/2 + 1

        Which will result to 99% confidence level at 10 pts and approximately 0%
        at -5 pts.


        Returns:
            A (float) number that represents the confidence of the detection
            that this entity is spam.
            The higher the value the more confidence.
        """

        #if (score > 0):
        try:
            self.conf_lvl = (1/(math.exp(-1*score/2)+ 1))
        except OverflowError as math_error:
            log.error("{0}\nValues: score={1}".format(str(math_error), score))
        #else:
        #    self.conf_lvl = 0

        return self.conf_lvl


    def get_features(self):
        return [self.incoming, self.outgoing, self.bytes, self.avg_score,
                self.traffic_ratio, self.packets, self.conn_cnt, self.conf_lvl]

    def is_spam(self):
        """
        Goes through various features of the entity and determines whether
        the entity is a spammer or not. First it computes the ratio of sent
        and received messages. Firstly it gets an average score of the entity
        flows, the score is based on BCP and RFC filter that evaluate whether
        the communication is legit or not, also the  communication protocol is
        used to distinguish a legit server from a spam machine..
        Then it looks at the communication ratio which is then compared with
        constant that is computed with the CDF function (TODO dynamically adjust
        the ratio threshold). Then it creates an unique list which is basically
        a connection count value.

        The evaluation happens in set_conf() function where the score is
        adjusted with non-linear function so the score responds with the
        percentage value.

        Arguments:
            self - self.tags
                 - self.fv

        Returns:
            Returns a (double) confidence level of this entity being a spammer or not in percentage.

        """
        tags = set()
        score = self.avg_score

        if (self.incoming == 0):
            try:
                score += math.log(self.outgoing)
            except ValueError:
                sys.stderr.write("smtp_entity: Math error")
        sent = len(self.sent_history)

        if (sent != 0):
            traffic_ratio = self.incoming / sent
        else:
            traffic_ratio = 0
        # Check for unique DST_IPs
        unique_ips = set()
        with self.__lock:
            for flow in self.sent_history:
                unique_ips.add(flow.DST_IP)
        self.conn_cnt = len(unique_ips)

        if (self.conn_cnt > MAX_ALLOWED_SERVERS):
            tags.add("CONN_CNT")
            score += 1
        else:
            score -= 1
        if (traffic_ratio > 1.2):
            tags.add("TR_RAT")
            score += 1
        else:
            score -= 1

        self.fv = self.get_features()
        self.fv.append(score)
        self.tags = tags
        return self.set_conf(score)


    def get_emails(self):
        """
        Getter for a list of all unique email addresses used by this entity
        """
        #log.debug("{}".format(self))
        addrs = set()
        for host in self.smtp_pool:
            addrs.add(str(host.SMTP_FIRST_SENDER))
            #log.debug("Added addr to report {}".format(str(host.SMTP_FIRST_SENDER)))
        return list(addrs)

    def get_hostnames(self):
        """
        Getter for a list of all unique domain name addresses used by this entity
        """
        hosts = set()
        for host in self.smtp_pool:
            hosts.add(str(host.SMTP_DOMAIN))
        return list(hosts)

    def get_proto(self):
        """
        Getter for a list of all protocols used by this entity
        """
        with self.__lock:
            return self.protocols

