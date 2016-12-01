# SIP Brute-Force Detector


## Table of Contents

* [Module description](#module-description)
* [How it works](#how-it-works)
* [Required data](#required-data)
* [How to use](#how-to-use)
* [Compilation and linking](#compilation-and-linking)


## <a name="module-description">Module description</a>

Module for detecting brute-force attacks and user search attack on Session Initiation Protocol.
It analyses SIP response traffic and is capable of detecting distributed
brute-force attacks and username scans.


## <a name="how-it-works">How it works</a>

This module checks status codes of SIP servers and looks for
"401 Unauthorized" responses to Register requests.
Once the count of these responses for a certain user name exceeds a threshold,
alert is generated.

This module has two output interfaces. Alert of an attack is generated once it is considered as ceased. 
That means after a period of time since the last received attack message. This period can be set with parameter -f.
When a breach is detected, IP address of the breached server is sent via the second output interface and can be used by TimeMachine.
This is useful for collecting data which might be used as a proof of the attack.

The alert itself is in UniRec format. It contains vital information about the attack:

 - SBFD\_EVENT\_ID (uint64): unique number for this alert
 - SBFD\_EVENT\_TYPE (uint8): type of alert (0 - simple brute-force, 1 - distributed brute-force, 2 - user scan)
 - SBFD\_TARGET (ipaddr): IP address of the targeted server
 - SBFD\_SOURCE (ipaddr): IP address of the attacker
 - SBFD\_USER (string): name of targeted user (can be empty in case of user scan alert)
 - SBFD\_LINK\_BIT\_FIELD (uint64): indicator of the particular monitoring probe
 - SBFD\_PROTOCOL (uint8): protocol used to perform the attack (TCP or UDP)
 - SBFD\_EVENT\_TIME (time): time of first attack message received
 - SBFD\_CEASE\_TIME (time): time of last attack message received
 - SBFD\_BREACH\_TIME (time): time of breach occurrence (can be 0 if the breach did not occur)
 - SBFD\_ATTEMPTS (uint32): total count of attack messages received
 - SBFD\_AVG\_ATTEMPTS (uint32): average count of attack messages received;
                                 in case of scan, shows how many attack messages were sent to each username;
                                 in case of distributed brute-force, shows how many messages were sent by each attacker

## <a name="required-data">Required data</a>

This module is implemented on TRAP platform, so it receives data on
TRAP input interface in UniRec format.

UniRec fields required:

 - DST\_IP (ipaddr): destination IP address of the flow
 - SRC\_IP (ipaddr): source IP address of the flow
 - LINK\_BIT\_FIELD (uint64): indicator of the particular monitoring probe
 - PROTOCOL (uint8): protocol used (TCP, UDP...)
 - TIME\_FIRST (time): time of the message capture
 - SIP\_MSG\_TYPE (uint16): SIP message type (see flow_meter documentation)
 - SIP\_STATUS\_CODE (uint16): SIP status code (see flow_meter documentation)
 - SIP\_CSEQ (string): 'Cseq' part of a SIP header
 - SIP\_CALLING\_PARTY (string): 'From' part of a SIP header

All of UniRec fields mentioned above can be obtained from module flow\_meter when launched with SIP plugin. (-p sip)

## <a name="how-to-use">How to use</a>

Since this module uses TRAP, input and output interfaces need to be specified.

Usage:

```
./sip_bf_detector -i <trap_interfaces> <Additional parameters>
```

Additional parameters:

    -a <num>		Number of unsuccessful authentication
                  attempts to consider this behaviour as
                  an attack (50 by default).

    -c <num>		Number of seconds between the checks on
                  ceased attacks (300 by default).

    -f <num>		Number of seconds after the last action to
                  consider attack as ceased (1800 by default).

Example:

```
./sip_bf_detector -i "u:voip_data_source,t:12009,t:12321" -a 50 -c 300 -f 1800 
```

The example of use of this module above receives data in UniRec format on
TRAP unix socket interface and uses TRAP tcp interfaces to send
alerts on port 12009, while alerting TimeMachine on port 12321.

Additional parameters ensure that:

 - 50 unsuccessful authentication attempts are considered as an attack (-a 50)

 - every 300 seconds (5 minutes) all ongoing attacks are checked whether they ceased or not (-c 300)

 - during every check, an attack is considered ceased if the last attack message was received
   more than 1800 seconds (30 minutes) from the currently processed message (-f 1800)

## <a name="compilation-and-linking">Compilation and linking</a>

No special compilation parameters are needed. For linking add -ltrap -lunirec -lnemea-common
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).

Doxygen documentation can be generated with `make doc` command.
