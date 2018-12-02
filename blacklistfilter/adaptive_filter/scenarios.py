#!/usr/bin/env python3

import logging
from uuid import uuid4
from time import time

import adaptive_filter
import enrichers
import g

logger = logging.getLogger('Adaptive filter')

WWW_PREFIX = 'www.'


class Scenario:
    def __init__(self, detection_event):
        self.event_type = type(self).__name__
        self.detection_events = []
        self.detection_events.append(detection_event)
        self.detection_cnt = 1
        self.id = str(uuid4())
        self.first_detection_ts = time()
        self.last_detection_ts = time()
        self.processed_by_evaluator_ts = 0
        self.adaptive_entities = set()
        self.adaptive_events = None

    def _get_suffix(self):
        """ Returns suffix for adaptive blacklist entries, i.e. Adaptive blacklist "magic" index and event ID"""
        return ',{},{}'.format(adaptive_filter.ADAPTIVE_BLACKLIST_ID, self.id)

    def get_entities(self):
        raise NotImplemented

    def __str__(self):
        return type(self).__name__

    @classmethod
    def fits(cls, detection_iface, detection_event):
        """
        Method to determine if the detection fits the current scenario
        :return: bool
        """
        raise NotImplemented

    def convert_to_evidence_fmt(self):
        raise NotImplemented


class BotnetDetection(Scenario):
    """
    Scenario class for enhanced botnet detection. Since often only C&C servers are blacklisted,
    we also want to track the clients/botnet, so we feed these IP addresses to the adaptive filter
    """
    def __init__(self, detection_event):
        super().__init__(detection_event)

        # The key is only the blacklisted C&C server
        self.key = detection_event['source']
        logger.debug('Detected BOTNET with CC: {}. ID: {}'.format(self.key, self.id))

    @classmethod
    def fits(cls, detection_iface, detection_event):
        if detection_iface == adaptive_filter.IP_URL_Interface.iface_num \
                and detection_event['blacklist_id'] in g.botnet_blacklist_indexes:
            return True
        else:
            return False

    def get_entities(self):
        # Gather all the targets (bots communicating with the C&C server)
        adaptive_entities = set()
        for detection_event in self.detection_events:
            adaptive_entities.update([target + self._get_suffix() for target in detection_event["targets"]])
        return adaptive_entities

    def convert_to_evidence_fmt(self):
        return self.__dict__


class DNSDetection(Scenario):
    """
    Scenario class for DNS detection. When we observe a DNS query to a blacklisted domain,
    we can only see recursive DNS server as a source of the query. Let's feed the domain's IP address
    to the adaptive filter to track down the client

    Detection flows are DNS answers with A, AAAA, CNAME records
    """
    def __init__(self, detection_event):
        super().__init__(detection_event)

        # Consider www.domain.com and domain.com the same
        detection_event.DNS_NAME = detection_event.DNS_NAME.lstrip(WWW_PREFIX).lower()

        # The key is just the domain
        self.key = detection_event.DNS_NAME
        logger.debug('Detected blacklisted DNS: {}. ID: {}'.format(self.key, self.id))

    @classmethod
    def fits(cls, detection_iface, detection_event):
        if detection_iface == adaptive_filter.DNS_Interface.iface_num:
            return True
        else:
            return False

    def get_entities(self):
        """ Get entities for the adaptive filter, from DNS, PassiveDNS etc."""
        adaptive_entities = set()
        entities = enrichers.dns_query(self.key)
        for entity in entities:
            adaptive_entities.add(str(entity) + self._get_suffix())
        return adaptive_entities

    def convert_to_evidence_fmt(self):
        evid_format = self.__dict__
        evid_format['detection_events'] = [x.strRecord() for x in evid_format['detection_events']]
        return evid_format
