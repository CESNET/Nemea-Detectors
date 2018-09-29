#!/usr/bin/env python3

import logging
import pytrap
from contextlib import suppress
from uuid import uuid4
from time import time

logger = logging.getLogger('Adaptive-filter')

blfilter_interfaces = {'IP': 0,
                       'URL': 1,
                       'DNS': 2}

WWW_PREFIX = 'www.'

# Thrown by Scenario subclass' init function when the detection flow doesn't
# fit the scenario
class ScenarioDoesNotFit(BaseException):
    def __init__(self, expression=None, message=None):
        self.expression = expression
        self.message = message


class Scenario:
    def __init__(self, detection_flow):
        self.detection_flows = []
        self.detection_flows.append(detection_flow)
        self.detection_cnt = 1
        self.id = 0
        self.first_ts = time()
        self.last_ts = time()
        self.adaptive_entities = set()

    def set_random_id(self):
        self.id = str(uuid4())

    def _get_suffix(self):
        """ Returns suffix for adaptive blacklist entries"""
        return ',{}'.format(self.id)

    def get_entities(self):
        raise NotImplemented

    def __str__(self):
        return str(self.__dict__)

class BotnetDetection(Scenario):
    """
    Scenario class for enhanced botnet detection. Since often only C&C servers are blacklisted,
    we also want to track the clients/botnet, so we feed these IP addresses to the adaptive filter
    """
    def __init__(self, detection_iface, detection_flow):
        if detection_iface != blfilter_interfaces['IP']:
            raise ScenarioDoesNotFit

        super().__init__(detection_flow)
        self.key = (detection_flow.SRC_IP, detection_flow.DST_IP)


        # TODO: if type == C&C

    def get_entities(self):
        # Add entity which was NOT on the blacklist
        if self.detection_flow.DST_BLACKLIST:
            self.adaptive_entities.add(str(self.detection_flow.SRC_IP) + self._get_suffix())
        else:
            self.adaptive_entities.add(str(self.detection_flow.DST_IP) + self._get_suffix())


class DNSDetection(Scenario):
    """
    Scenario class for DNS detection. When we observe a DNS query to a blacklisted domain,
    we can only see recursive DNS server as a source of the query. Let's feed the domain's IP address
    to the adaptive filter to track down the client

    Detection flows are DNS answers with A, AAAA, CNAME records
    """
    def __init__(self, detection_iface, detection_flow):
        # We are interested in valid DNS answers
        if detection_iface != blfilter_interfaces['DNS'] or detection_flow.DNS_ANSWERS < 1:
            raise ScenarioDoesNotFit

        # Consider www.domain.com and domain.com the same
        detection_flow.DNS_NAME = detection_flow.DNS_NAME.strip(WWW_PREFIX)

        # The key is just the domain
        self.key = detection_flow.DNS_NAME

        super().__init__(detection_flow)

        # TODO: How to get all data from DNS_RDATA? This only retrieves first record
        try:
            # Use the record only if its A record
            pytrap.UnirecIPAddr(detection_flow.DNS_RDATA.decode())
        except pytrap.TrapError:
            raise ScenarioDoesNotFit

    def get_entities(self):
        """ Get entities for the adaptive filter, from DNS_RDATA, from PassiveDNS etc."""

        adaptive_entities = set()
        for detection_flow in self.detection_flows:
            with suppress(pytrap.TrapError):
                ip_addr = str(pytrap.UnirecIPAddr(detection_flow.DNS_RDATA.decode()))
                adaptive_entities.add(ip_addr + self._get_suffix())

        return adaptive_entities
