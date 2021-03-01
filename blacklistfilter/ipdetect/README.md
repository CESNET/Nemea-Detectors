# IP blacklistfilter

This module is a part of the blacklistfilter suite. For information about other modules, see the main [README](../README.md)

## Goal

Module receives the UniRec basic flow and checks if the stored source
address or destination address is present in any 
blacklist that are available. If any of the addresses is 
blacklisted, the record is changed by adding a number/index of 
the blacklists that contain this address. UniRec with this 
flag is then sent to the output interface. Blacklists are downloaded by a separate module
Blacklist downloader which saves blacklists to a file (specified in configuration) and blacklistfilter uses
this file to reload blacklists.

## Input/Output

```
Input Interface:  UniRec format (<BASIC_FLOW>)
Output Interface: UniRec format (<BASIC_FLOW>,SRC_BLACKLIST,DST_BLACKLIST)
```

## Usage

```
Usage:	ipblacklistfilter -i <trap_interface> [-c <config_file>] [-4 <ipv4_blacklist_file>] [-6 <ipv6_blacklist_file>]
```

## Configuration
Is done via configuration file (command-line options override config file)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <struct name="main struct">
        <!-- Name of the file with blacklisted IP (or prefixes).
             These blacklists are meant to be prepared by blacklist downloader.
             Blacklists must be preprocessed such that IP addresses and prefixes
             are sorted (numerically) -->
        <element name="ipv4_blacklist_file">
             /tmp/blacklistfilter/ip4.blist
        </element>

        <element name="ipv6_blacklist_file">
             /tmp/blacklistfilter/ip6.blist
        </element>
        <!-- When set to dynamic, watch the blacklist file(s) for changes (with inotify mechanism)
        and reload them instantly, static means just to load files at startup
        -->
        <element name="watch_blacklists">
            true
        </element>
    </struct>
</configuration>
```


- `{ipv4/ipv6}_blacklist_file`: An IPv4/IPv6 file created by Blacklist downloader, containing (sorted) entries from all blacklists

- `watch_blacklists`: A flag indicating whether the blacklist file is being reloaded everytime the file changes. When set to false, 
the blacklists are loaded only once at the startup of the module


## Operation

- Upon startup, if the module can not find/read `ipv4_blacklist_file`, it immediately exits with an error. 
The `ipv6_blacklist_file` is optional and its absence only produces a warning.
- Module reports every single flow with src/dst address present on some blacklist, 
the only exception is a flow with src/dst port 53 (DNS queries).
- If `watch_blacklists` flag is true, the module listens for changes (IN_CLOSE_WRITE events) in the files and reloads
them everytime there is a change


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

## Output data

Upon detection, the input data are sent to the output, enriched with these values:

- `DST_BLACKLIST` (uint64): indexes of the blacklists (bitmap) which blacklisted `DST_IP`, zero if not blacklisted
- `SRC_BLACKLIST` (uint64): indexes of the blacklists (bitmap) which blacklisted `SRC_IP`, zero if not blacklisted

For example, when the `DST_BLACKLIST` field contains number 9, it means the DST_IP is present on 
blacklists with ID 1 and 4 (in binary: 1001)

The very rare situation, when both addresses are present on some blacklist, is not handled. There is always just one
non-zero value for `{DST,SRC}_BLACKLIST` (either DST or SRC is blacklisted, not both).

## Compilation and linking

This module requires compilation with `-std=c++11`, because of the usage of *std::vector, streams, etc.*.

For linking add `-ltrap -lunirec -lnemea-common`
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).

## Example detection
```
ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL
192.168.1.1,192.168.1.2,123,0,8,2017-08-18T14:16:08.256,2017-08-18T14:16:13.177,3,1433,6
192.168.1.1,192.168.1.2,41,0,8,2017-08-18T14:16:13.405,2017-08-18T14:16:13.405,1,1433,6
192.168.1.1,192.168.1.2,404,8,0,2017-08-18T14:16:10.106,2017-08-18T14:16:25.100,8,25,6
```
