# DNS blacklistfilter

This module is a part of the blacklistfilter suite. For information about other modules, see the main [README](../README.md)

## Goal	

Module receives the UniRec record and checks if the domain name (FQDN) is present in any DNS/FQDN blacklists 
that are available. If the FQDN is present in any blacklist the record is changed by adding an index of the blacklist. 
UniRec with this flag is then sent to the output interface. Blacklists are downloaded by a separate module
Blacklist downloader which saves blacklists to a file (specified in configuration) and blacklistfilter uses
this file to reload blacklists.

## Input/Output

```
Input Interface:  UniRec format (<BASIC_FLOW>,<DNS_FLOW>)
Output Interface: UniRec format (<BASIC_FLOW>,<DNS_FLOW>,BLACKLIST)
```

## Usage

```
Usage:	dnsblacklistfilter -i <trap_interface> [-c <config_file>] [-b <blacklist_file>]
```

## Configuration
Is done via configuration file (command-line options override config file)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <struct name="main struct">
        <!-- Name of the file with blacklisted DNSs (FQDNs).
             These blacklists are meant to be prepared by blacklist downloader. -->
        <element name="blacklist_file">
            /tmp/blacklistfilter/dns.blist
        </element>
        <!-- When set to true, watch the blacklist file(s) for changes (with inotify mechanism)
        and reload them instantly when there is a blacklist update, false means just to load blacklists at startup
        -->
        <element name="watch_blacklists">
            true
        </element>
    </struct>
</configuration>
```

- `blacklist_file`: A DNS file created by Blacklist downloader, containing (sorted) entries (FQDNs) from all blacklists

- `watch_blacklists`: A flag indicating whether the blacklist file is being reloaded everytime the file changes. When set to false, 
the blacklists are loaded only once at the startup of the module

## Operation

- Module reports every single flow (request and reply) with DNS present on some blacklist, it is checking DNS_NAME field (request and reply)
- If `watch_blacklists` flag is true, the module listens for changes (IN_CLOSE_WRITE events) in the file(s) and reloads
them everytime there is a change
- Detection of the FQDN is case-insensitive and deals with little nuances in the FQDNs (such as redundant backslashes). Following 
domain names (DNS_NAME field) are treated the same:

![URL preprocessing](../doc/url_dns.png)

## Required data

This module is implemented on TRAP platform, so it receives data on
TRAP input interface in UniRec format.

UniRec fields required:

- `DST_IP` (ipaddr): destination IP address of the flow
- `SRC_IP` (ipaddr): source IP address of the flow
- `DST_PORT` (uint16): destination port of the flow
- `SRC_PORT` (uint16): source port of the flow
- `PROTOCOL` (uint8): protocol used (TCP, UDP...)
- `PACKETS` (uint32): packets in the flow
- `BYTES` (uint32): bytes in the flow
- `TIME_FIRST` (time): time of the first packet in the flow
- `TIME_LAST` (time): time of the last packet in the flow
- `DNS_NAME` (string): requested FQDN


## Output data

Upon detection, the input data are sent to the output, enriched with this value:

- `BLACKLIST` (uint64): indexes of the blacklists (bitmap) which blacklisted the URL

For example, when the `BLACKLIST` field contains number 9, it means the URL is present on 
blacklists with ID 1 and 4 (in binary: 1001)

## Compilation and linking

This module requires compilation with `-std=c++11`, because of the usage of *std::vector, streams, etc.*.

For linking add `-ltrap -lunirec -lnemea-common`
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).


## Example detection
Below is an example output of this detector. IP addresses are made-up.
There are both requests and replies (can be identified with DNS_ID). DNS_RDATA field is the raw reply.

```
ipaddr DST_IP,ipaddr SRC_IP,uint64 BLACKLIST,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 DNS_RR_TTL,uint32 PACKETS,uint16 DNS_ANSWERS,uint16 DNS_CLASS,uint16 DNS_ID,uint16 DNS_PSIZE,uint16 DNS_QTYPE,uint16 DNS_RLENGTH,uint16 DST_PORT,uint16 SRC_PORT,uint8 DNS_DO,uint8 DNS_RCODE,uint8 PROTOCOL,string DNS_NAME,bytes DNS_RDATA
192.168.1.1,192.168.1.107,32,59,2018-09-28T14:16:28.552,2018-09-28T14:16:28.552,0,1,0,1,63445,0,1,0,53,57649,0,0,17,"zstresser.com",
192.168.1.107,192.168.1.1,32,75,2018-09-28T14:16:28.594,2018-09-28T14:16:28.594,300,1,1,1,63445,0,1,14,57649,53,0,0,17,"zstresser.com",3138352e31312e3134352e323439
192.168.1.107,192.168.1.1,1,132,2018-09-28T14:17:23.677,2018-09-28T14:17:23.677,0,1,0,1,238,0,28,0,57649,53,0,0,17,"zverinova-kucharka.cz",
192.168.1.107,192.168.1.1,1,83,2018-09-28T14:17:23.677,2018-09-28T14:17:23.677,1800,1,1,1,44066,0,1,14,57649,53,0,0,17,"zverinova-kucharka.cz",33372e3135372e3139372e313231
```
