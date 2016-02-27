DNS Tunnel Detection
====================

Module description
------------------

The module detects communication tunnels over DNS protocol. Such tunnels can be
established e.g. by [iodine](http://code.kryo.se/iodine/),
[dns2tcp](https://www.aldeid.com/wiki/Dns2tcp) and others. It is based on
data encapsulation into DNS messages in order to bypass security policy.

How it works
------------

The module uses extended flow records with DNS fields. For testing purposes, such flow records
can be exported by [flow_meter](https://github.com/CESNET/Nemea-Modules/tree/master/flow_meter)
with `-p dns`. The list of exported DNS information is in [source file - UR_FIELDS](https://github.com/CESNET/Nemea-Modules/blob/master/flow_meter/dnsplugin.cpp).

The module analysis various fields such as domain names and builds a prefix tree of them. Once a given threshold is reach, i.e. there are many different requests for one domain name, the alert is generated.
The detection mechanism is described in more detail in [Stream-wise detection of surreptitious traffic over DNS](http://ieeexplore.ieee.org/xpl/articleDetails.jsp?reload=true&arnumber=7033254).


Output Interface sends alert in UniRec with the following fields:
* `EVENT_ID`: identifier of reported event
* `SRC_IP`: source of the tunnel (one end-point)
* `TIME_FIRST`: timestamp of the first observed flow record of the reported tunnel
* `TIME_LAST`:  timestamp of the last observed flow record of the reported tunnel
* `TUNNEL_PER_NEW_DOMAIN`: Percentage of new non-repeating subdomains
* `TUNNEL_PER_SUBDOMAIN`: Percentage of subdomain part that is probably used for data encapsulation
* `TUNNEL_DOMAIN`: sample of observed data
* `TUNNEL_CNT_PACKET`: Number of processed DNS flows
* `TUNNEL_TYPE`: can be one of the following values, not all anomaly types are reported:
   - TUN_T_REQUEST_TUNNEL (1): Request messages anomaly - possible tunnel
   - TUN_T_REQUEST_OTHER (2): Request messages anomaly - other anomaly (probably not a tunnel)
   - TUN_T_REQUEST_MALFORMED_P (3): Malformed packets in DNS requests messages
   - TUN_T_RESPONSE_TUNNEL_REQ (4): Response anomaly - detected tunnel in request string field
   - TUN_T_RESPONSE_TUNNEL_TXT (5): Response anomaly - detected tunnel in TXT field
   - TUN_T_RESPONSE_TUNNEL_CNAME (6): Response anomaly - detected tunnel in CNAME field
   - TUN_T_RESPONSE_TUNNEL_NS (7): Response anomaly - detected tunnel in MX field
   - TUN_T_RESPONSE_TUNNEL_MX (8): Response anomaly - detected tunnel in NS field
   - TUN_T_RESPONSE_OTHER (9): Response anomaly - detected other anomaly than tunnel
   - TUN_T_RESPONSE_MALFORMED_P (10): Response anomaly - malformed packets

List of parameters
------------------

    -u TMPL	Specify UniRec template expected on the input interface.
    -p N        Show progess - print a dot every N flows.
    -a          File with whitelist of domain which will not be analysed
    -b          File with whitelist of IPs which will not be analysed
    -c          Read packet from file - MEASURE_PARAMETERS mode
    -s          Folder with results and other information about detection
                (on the end of module). Specify folder for data saving.
    -d          File with results of detection anomaly (during modul runtime).
    -f          Read packets from file
    -g          Set Max and Min EX and VAR for suspision in requests,
                [MIN EX, MAX EX, MIN VAR, MAX VAR] (all values are int)
    -r          Set Max and Min EX and VAR for suspision in responses,
                [MIN EX, MAX EX, MIN VAR, MAX VAR] (all values are int)
    -j          Set Max count of used letters not to be in suspision mode
                [MAX number for Request, MAX number for response]
    -k          Max and Min percent of subdomain [MAX, MIN]
    -l          Max count and percent of numbers in domain not to be in
                suspicion mode [MAX count, MAX percent]
    -m          Max percent of mallformed packet to be in traffic anoly [MAX]
    -n          MIN count of suspected requests to be traffic anomaly
                or tunnel [MIN for traffic anomaly, MIN for tunnel]
    -o          MIN count of suspected responses to be traffic anomaly or
                tunnel [MIN for traffic anomaly, MIN for tunnel]
    -q          Max and Min percent of searching just ones [MAX, MIN]
    -t          MAX round in SUSPICTION MODE and ATTACK MODE [SUSPICTION, ATTACK]
    -w          MIN length of string to be tunnel [MIN]
    -z          Length of collecting packets berore analysis in sec [time in sec]

