#!/usr/bin/env python3

# TODO: How to solve the dependency?
import dns.resolver


def dns_query(domain, qtype='A'):
    answers = []
    try:
        answers = dns.resolver.query(domain, qtype)
    except dns.exception.DNSException:
        pass

    return answers


def virus_total_query():
    pass


def shodan_query():
    pass

