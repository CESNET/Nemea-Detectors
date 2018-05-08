# Horizontal scan detector


### README outline

* [Module description](#module-description)
* [Algorithm thresholds](#algorithm-thresholds)
* [Input data](#input-data)
* [Output data](#output-data)
* [Module parameters](#module-parameters)


## Module description

This module is a **simple, threshold-based detector for horizontal
scans** which processes incoming flow records and outputs alerts. The
module uses TRAP platform and it has **one input and one output
interface**.

The detection algorithm uses information from basic flow records and
it is based on analysis of the number of destination addresses per
source address. It is important to remember all unique destination
addresses for each pair of source address and destination port
separately. The source address is a potential source of scan,
meanwhile, the destination addresses are victims.


## Algorithm thresholds

1. **Maximal number of packets per flow**. Only flows with 1 packet
   are processed, flows with more packets are rather a normal
   communication with data transfer. Size of packets is not considered
   at all since scanning tools may generate packets with any size.

2. **Maximal number of destination addresses per source IP and
   destination port pair**. After reaching this threshold set to 50,
   an alert is generated. The threshold affects memory consumption,
   detection delay and number of possibly undetectable scans (if a
   scanner probes less than 50 addresses, the scan remains
   undetected).

3. **Maximal age of unmodified list of addresses**. This threshold is
   set to 5 minutes. It defines the slowest scan that the detection
   algorithm is able to detect. The chosen value is related to the
   slowest time template of nmap (-T0). This means one address is
   probed every 5 minutes.


## Input data

The input of algorithm are all incoming flow records, however, only
the flow records satisfying a condition are processed. The condition
contains:

- **transport protocol** must be TCP
- **the number of packets** in a flow must be 1
- **TCP flags** must be equal to SYN

Data received via input interface are in Unirec format. The table
below shows required flow information together with the names of
Unirec fields:

| Flow info                    | Unirec field |
|:----------------------------:|:------------:|
| source IP address            | SRC_IP       |
| destination IP address       | DST_IP       |
| first time stamp             | TIME_FIRST   |
| last time stamp              | TIME_LAST    |
| transport protocol (TCP)     | PROTOCOL     |
| TCP flags                    | TCP_FLAGS    |
| number of packets            | PACKETS      |


## Output data

In case some source IP address reaches the threshold 50 for number of
destination addresses, an alert is sent via output interface. It is
also in Unirec format and it contains the following information:

| Unirec field | Description                        |
|:------------:|:----------------------------------:|
| EVENT_TYPE   | type of event (1 for scanning)     |
| TIME_FIRST   | first time stamp                   |
| TIME_LAST    | last time stamp                    |
| SRC_IP       | IP address of the attacker         |
| SRC_PORT     | last src port used by the attacker |
| DST_PORT     | dst port probed by the attacker    |
| PROTOCOL     | transport protocol (TCP)           |
| ADDR_CNT     | number of probed dst addresses     |


## Module parameters

The module has no special parameters, only implicit *libtrap*
parameters `-i IFC_SPEC`, `-h` and `-v` (see [Execute a
module](https://github.com/CESNET/Nemea#try-out-nemea-modules)).
