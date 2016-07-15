Bruteforce detector module
==========================


Table of Contents
-----------------

* [Module description](#module-description)
* [How it works](#how-it-works)
* [Input and Output](#input-and-output)
* [How to use](#how-to-use)
* [Reconfiguration](#reconfiguration)
* [Compilation and linking](#compilation-and-linking)


Module description
------------------

The module can be used for detecting brute force attacks on different services.
Protocols as SSH, Telnet and RDP are currently supported. 


How it works
------------

The method is storing last N flow records within each source host. Under
this window detection method is performed. Every incoming flow record is
compared versus predefined rules as a TCP flags, range number of packets
or bytes. If threshold is reached, an alarm is triggered and a report is 
send via output interface.


Input and Output
----------------

Module has two interfaces, one input interface and one output interface.

Unirec template for input interface is `SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS`.
This is a classic sub-template output both by ipfixcol unirec plugin and by nfdump reader module.

Unirec template for output interface is `DETECTION_TIME,WARDEN_TYPE,SRC_IP,PROTOCOL,DST_PORT,EVENT_SCALE,NOTE`, where:

* `DETECTION_TIME` : Timestamp of detected event
* `WARDEN_TYPE` : Type of detected event - always `WT_BRUTEFORCE` (see Warden for more information)
* `SRC_IP` : IP address of the attacker
* `PROTOCOL` : TCP protocol number
* `DST_PORT` : Port of the attacked service
* `EVENT_SCALE` : Scale of the detected event
* `NOTE` : This field contains (comma is used as separator):
  1. Total number of targets since start of the attack from both 
directions separated by a dash  
  2. Flag if the scan is performed
  3. Number of suspicious flows from both directions and since 
last report separated by a dash 


How to use
----------

The module is implemented on TRAP platform so you have to specify TRAP interfaces correctly. Then you can specify one of the parameters listed below.

Usage:

```
./brute_force_detector -i <trap_parameters> <detection_mode> <config>
```
     
* `<detection_mode>` can be `-S` (SSH) `-R` (RDP) `-T` (Telnet) (at least one parameter is required)
* `<config>` : `-c configFile` (default is `config/config.conf`, not required)
* `<whitelist>` : `-w whitelistFile` (default is `config/whitelist.wl`, not required)
* `-W` : set verbose for parsing whitelist file

Example of usage:

```
./brute_force_detector -i "u:flow_data_source,u:bfd_data_out" -R -S -T
```

This will run module listening for input flows on Unix socket `flow_data_source`, set module so
it will detect -R (RDP) -S (SSH) and -T (Telnet) bruteforce attacks and output detected events
to Unix socket `bfd_data_out`. Because no configuration file is specified, module will use
default values for detecting.


Reconfiguration
---------------

Module can by reconfigured during runtime. This can be done by sending specific signal to module.
Supported signals are:

* `SIGUSR1` : Reload configuration from a file specified at startup
* `SIGUSR2` : Reload configuration of whitelist from a file specified at startup

 
Compilation and linking
-----------------------

No special compilation parameters are needed. For linking add -ltrap and -lunirec
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).

