Miner detector module
=====================


Table of Contents
----------------

* [General information about module](#general-information-about-module)
* [How it works](#how-it-works)
* [Score computation](#score-computation)
* [Stratum protocol check](#stratum-protocol-check)
* [Aggregation](#aggregation)
* [Module usage](#module-usage)
* [Output](#output)
* [Documentation](#documentation)
* [Compilation](#compilation)


General information about module
--------------------------------

Miner detector module was implemented to detect hosts in network that participate
in bitcoin mining and communicate with mining pool server. If miners are using
[stratum mining protocol](https://en.bitcoin.it/wiki/Stratum_mining_protocol), this
communication is detected and corresponding miner and server IP addresses are reported.

To greatly reduce false positive detection, after module detect suspicious communication
it will connect to the suspicious server and try to communicate with it using stratum
protocol. After positive reply from the server, detection is done and detected incident
is reported.


How it works
------------

Module works in two threads. One thread reads input flows and second periodically
checks for miners in special table to store data - Suspect table.
There are three tables, each with special functionality:

1. Suspect table - First thread stores suspicious communication into this table and second
thread it periodically checks for possible miner-server communication. Item of this table
 consists of statistical data about suspicious flows. Single item holds data for common
source IP, destination IP and destination port. So a suspect (item in this table) is
a communication from one host to one server to one port.
2. Blacklist table - If second thread detects a miner-server communication, it will store
the pool server IP (destination IP in the Suspect table), the miner was communicating with,
in this table. First thread checks destination IP of input flows against this table to
determine if these flows belongs to previously detected pool server IPs. This table reduces
both CPU and network load, because it reduces number of suspects to check - no need to
again detect miner-server communication if it was previously detected.
3. Whitelist table - This table contains IP addresses of servers which are not pool
servers. Usage of this table is crucial if we want to reduce number of stratum protocol
checks - without it, the module would periodically check same servers even knowing that
these servers are not mining pool servers.

So the program flow of the module is as follows:

1. First thread reads flow data from input interface and checks IP addresses in
this flow data against Suspect, Blacklist and Whitelist tables. Four outcomes can
happen now:

  - If dst. IP is in the Whitelist table, then flow is ignored.
  - If IP addresses from this flow are already in the Suspect table, then information
in the Suspect table is updated with data from this flow.
  - If dst. IP is in the Blacklist table, then new record with information about
this flow is inserted into the Suspect table.
  - If flow is TCP and TCP flags are ACK or ACK+PUSH, then information about this
flow is inserted into the Suspect table.

2. Second thread checks every suspect (communication from src. IP to dst. IP to dst. port)
in the Suspect table against both Whitelist table and Blacklist table. Three outcomes can
happen now:

  - If dst. IP is found in the Whitelist table, suspect is removed from Suspect table.
  - If dst. IP is found in the Blacklist table, suspect is reported.
  - If not found in any table, compute score of the suspect. Score is computed from
aggregated information about suspect (stored in the Suspect table). If score is higher
than threshold, dst. IP (server) is checked for stratum protocol on dst. port.


Score computation
-----------------

To determine if suspect is miner-server communication, a score is computed from aggregated
information about this suspect as follows:

1. Set score = 0
2. If ACK + (ACK | PUSH) flows is more than 80%, score + 2 ('|' stands for bitwise OR)
3. If bytes per packet is between 50 and 130, score + 2
4. If packets per flow is NOT between 10 and 20, score + 1
5. If packets per minute is between 8 and 30, score + 2
6. If active time of suspect is more than 300 seconds, score + 3

Score of 7 (by default) and more is needed to pass.


Stratum protocol check
----------------------

If suspect's score is high enough, it is checked if it support stratum protocol.
This check is done by directly connecting to server. Module connects to suspicious server and
sends it typical request for stratum protocol. Module then waits for response. If response
arrives and contains typical answer for given request, then this server is considered as mining
pool server and its IP is added into the Blacklist table.


Aggregation
-----------

Aggregated data consist of data from the Suspect table, so as was stated above these data
are aggregated for common source IP, destination IP and destination port and they are:

- Number of TCP flows with only ACK TCP flag set
- Number of TCP flows with only ACK and PUSH TCP flag set
- Number of all other flows
- Number of packets sent
- Number of bytes sent
- Time when was this communication first seen
- Time when was this communication last seen
- Time when was this communication last reported 


Every time second thread checks suspect from Suspect table it also checks if this record
timeouted. There are three timeouts:

1. Inactive timeout - Record is removed from the Suspect table if no similar records was
seen for small period of time.
2. Active timeout - Record is removed from the Suspect table even if similar records was
seen. This timeout is much larger than inactive timeout.
3. Report timeout - Reports of detected incidents are aggregated until this timeout runs out. Then
only a single report is sent with a special value specifying how many detected incidents
were detected in this time window.


Module usage
------------

Module contains help for possible arguments. To show this help, run module like this:

```
./miner_detector -h
```

Module is configured using configuration file (default is `userConfigFile.xml`) and example
run of the module could look like this:

```
./miner_detector -i "u:flow_data_source,u:miner_detector_output" -u userConfigFile.xml
```


Output
------

Module outputs detected miners information by trap output interface. Template of this
unirec record is `TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,DST_PORT,EVENT_SCALE`, where:

- `SRC_IP` : IP address of the detected miner
- `DST_IP` : IP address of the detected pool server
- `TIME_FIRST` : Time when the detected miner was first seen
- `TIME_LAST` : Time when the detected miner was last seen
- `DST_PORT` : Port on the detected pool server
- `EVENT_SCALE` : Number of aggregated incidents for this report


Documentation
-------------

Source code files was commented using doxygen style comments. To generate
documentation for implemented functions, structures and variables use
doxygen.


Compilation of module
---------------------

No special compilation parameters are needed. For linking add -ltrap, -lunirec and -lnemea-common
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).

