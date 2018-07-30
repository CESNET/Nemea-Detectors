## URL blacklistfilter

# Goal	
    Module receives the UniRec HTTP flow records and checks if the HTTP PATH (HTTP_HOST+HTTP_URL) is present in any 
	blacklist that are available. If any of the addresses is 
	blacklisted, the record is changed by adding a number/index of 
	the blacklists that contain this URL. UniRec with this 
	flag is then sent to the output interface. Blacklists are downloaded by a separate module
	bl_downloader.py which saves blacklists to a file (specified in configuration) and blacklistfilter uses
	this file to reload blacklists.

# Input/Output
    Input Interface: UniRec format (<HTTP_FLOW>)
    Output Interface: UniRec format (<HTTP_FLOW>, BLACKLIST)

# Usage
```
Usage:	./urlblacklistfilter -u <config_file> -i <trap_interface>
```

# Blacklist downloader
URL blacklistfilter uses blacklist file which is handled by Python downloader (bl_downloader.py).
The downloader periodically checks for new blacklist updates and feeds it to the blacklistfilter
using inotify mechanism. The data are preprocessed by the downloader (sorted, trimmed whitespaces etc.)

See "TODO: downloader README ref"


## Required data

This module is implemented on TRAP platform, so it receives data on
TRAP input interface in UniRec format.

UniRec fields required:
 - DST\_IP (ipaddr): destination IP address of the flow
 - SRC\_IP (ipaddr): source IP address of the flow
 - DST\_PORT (uint16): destination port of the flow
 - SRC\_PORT (uint16): source port of the flow
 - TIME\_FIRST (time): time of the first packet in the flow
 - TIME\_LAST (time): time of the last packet in the flow
 - HTTP_HOST (string): HTTP Host header
 - HTTP_REFERER (string): HTTP Referer header
 - HTTP_URL (string): HTTP URL


## Output data

Upon detection, the input data are sent to the output, enriched with this value:
  - BLACKLIST (uint64): indexes of the blacklists (bitmap) which blacklisted the URL

## Compilation and linking

This module requires compilation with -std=c++11, because of the usage of *std::vector, streams, etc.*.

For linking add -ltrap -lunirec -lnemea-common
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).