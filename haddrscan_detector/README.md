# Horizontal scan detector

## Table of contents

* [Detector module description](#detector-module-description)
* [Detector algorithm](#detector-algorithm)
* [Detector input data](#detector-input-data)
* [Detector output data](#detector-output-data)
* [Detector module parameters](#detector-module-parameters)


## Detector module description

This module is a **simple, threshold-based detector for horizontal
scans** which processes incoming flow records and outputs alerts. The
module uses the TRAP platform and it has **one input and one output
interface**.

The detection algorithm uses information from basic flow records and
it is based on analysis of the number of destination addresses per
source address and destination port. It is important to remember all
unique destination addresses for each pair of source address and
destination port separately. The source address is a potential source
of scan, meanwhile, the destination addresses are victims.


## Detector algorithm

Each flow with only 1 TCP packet that had the SYN flag set is recorded
in a table for source address and destination port pairs where an
address counter is incremented for new destinations, a timestamp is
updated and new destination addresses are added to a list.

If the address counter for a source address and destination port pair
climbs to `numaddrs-threshold` then an alert is generated immediately
and the entry for that pair is removed.

The table of source address and destination port pairs is examined
every `pruning-interval` for entries unmodified for more than
`idle-threshold` which are pruned.

### Detector thresholds and intervals

1. **Maximum number of packets per flow**. Only flows with 1 packet
   are processed, flows with more packets are rather a normal
   communication with data transfer. Size of packets is not considered
   at all since scanning tools may generate packets with any size.

2. **Maximum number of destination addresses per source address and
   destination port pair** (`numaddrs-threshold`, default 50). After
   reaching this threshold, an alert is generated. The threshold
   affects memory consumption, detection delay and number of possibly
   undetectable scans (if a scanner probes fewer addresses than the
   threshold, the scan remains undetected). This threshold is included
   in the alert as `ADDR_THRSD`.

3. **Maximum age of unmodified list of destination addresses**
   (`idle-threshold`, default 5 minutes). This threshold defines the
   slowest scan that the detection algorithm is able to detect. The
   default value is related to the slowest time template of nmap
   (-T0). This means one address is probed every 5 minutes.

4. **Pruning interval for source address and destination port table**
   (`pruning-interval`, defaults 1 minute). It defines how often the
   table of source address and destination port pairs is examined for
   entries unmodified in excess of the *maximum age of unmodified list
   of destination addresses*.


## Detector input data

This module expects flow records in Unirec format. The table below
shows required flow information together with the field names:

| Flow info                    | Unirec field |
|:----------------------------:|:------------:|
| source IP address            | `SRC_IP`     |
| destination IP address       | `DST_IP`     |
| destination port             | `DST_PORT`   |
| first time stamp             | `TIME_FIRST` |
| last time stamp              | `TIME_LAST`  |
| transport protocol (TCP)     | `PROTOCOL`   |
| TCP flags                    | `TCP_FLAGS`  |
| number of packets            | `PACKETS`    |


## Detector output data

Alerts are sent on the output interface, also in Unirec format, they
contain the following information:

| Unirec field | Description                                  |
|:------------:|:--------------------------------------------:|
| `EVENT_TYPE` | type of event (1 for scanning)               |
| `TIME_FIRST` | first time stamp                             |
| `TIME_LAST`  | last time stamp                              |
| `SRC_IP`     | IP address of the attacker                   |
| `SRC_PORT`   | last src port used by the attacker           |
| `DST_PORT`   | dst port probed by the attacker              |
| `PROTOCOL`   | transport protocol (TCP)                     |
| `ADDR_CNT`   | number of probed dst addresses               |
| `ADDR_THRSD` | threshold for number of probed dst addresses |
| `DST_IP0`    | sample probed dst address 0                  |
| `DST_IP1`    | sample probed dst address 1                  |
| `DST_IP2`    | sample probed dst address 2                  |
| `DST_IP3`    | sample probed dst address 3                  |


## Detector module parameters

In addition to the implicit *libtrap* parameters `-i IFC_SPEC`, `-h`
and `-v` (see [Execute a
module](https://github.com/CESNET/Nemea#try-out-nemea-modules)) this
module takes the following parameters:

* `-n` `--numaddrs-threshold` *uint32*: Threshold for number of
  destination addresses to produce an alert.

* `-d` `--idle-threshold` *uint16*: Threshold in seconds after which
  unchanged source address and destination port entries can be pruned.

* `-p` `--pruning-interval` *uint16*: Interval in seconds for the
  pruning task.

For more detailed information see above under [detector
algorithm](#detector-algorithm) and [detector thresholds and
intervals](#detector-thresholds-and-intervals).


# Horizontal scan aggregator

## Table of contents

* [Aggregator module description](#aggregator-module-description)
* [Aggregator algorithm](#aggregator-algorithm)
* [Aggregator input data](#aggregator-input-data)
* [Aggregator output data](#aggregator-output-data)
* [Aggregator module parameters](#aggregator-module-parameters)


## Aggregator module description

This module is a **simple, aggregator of alerts for horizontal scans**
which processes incoming alerts records and outputs aggregated alerts.
The module uses the pytrap platform and it has **one input and one
output interface**.


## Aggregator algorithm

Incoming alerts are held for up to *time* minutes (default 5) and
aggregated with further alerts for the same source address and
destination port pair.

The first three alerts fill the sample probed destination address
fields 0 though 11. The last alert fills fields 12 through 15.


## Aggregator input data

This module expects alerts in Unirec format. The table below shows
required data together with the field names:

| Unirec field | Description                                  |
|:------------:|:--------------------------------------------:|
| `EVENT_TYPE` | type of event (1 for scanning)               |
| `TIME_FIRST` | first time stamp                             |
| `TIME_LAST`  | last time stamp                              |
| `SRC_IP`     | IP address of the attacker                   |
| `SRC_PORT`   | last src port used by the attacker           |
| `DST_PORT`   | dst port probed by the attacker              |
| `PROTOCOL`   | transport protocol (TCP)                     |
| `ADDR_CNT`   | number of probed dst addresses               |
| `ADDR_THRSD` | threshold for number of probed dst addresses |
| `DST_IP0`    | sample probed dst address 0                  |
| `DST_IP1`    | sample probed dst address 1                  |
| `DST_IP2`    | sample probed dst address 2                  |
| `DST_IP3`    | sample probed dst address 3                  |


## Aggregator output data

Aggregated alerts are sent on the output interface, also in Unirec
format and they contain the following information:

| Unirec field | Description                                  |
|:------------:|:--------------------------------------------:|
| `EVENT_TYPE` | type of event (1 for scanning)               |
| `TIME_FIRST` | first time stamp                             |
| `TIME_LAST`  | last time stamp                              |
| `SRC_IP`     | IP address of the attacker                   |
| `SRC_PORT`   | last src port used by the attacker           |
| `DST_PORT`   | dst port probed by the attacker              |
| `PROTOCOL`   | transport protocol (TCP)                     |
| `ADDR_CNT`   | number of probed dst addresses               |
| `ADDR_THRSD` | threshold for number of probed dst addresses |
| `DST_IP0`    | sample probed dst address 0                  |
| `DST_IP1`    | sample probed dst address 1                  |
| `DST_IP2`    | sample probed dst address 2                  |
| `DST_IP3`    | sample probed dst address 3                  |
| `DST_IP4`    | sample probed dst address 4                  |
| `DST_IP5`    | sample probed dst address 5                  |
| `DST_IP6`    | sample probed dst address 6                  |
| `DST_IP7`    | sample probed dst address 7                  |
| `DST_IP8`    | sample probed dst address 8                  |
| `DST_IP9`    | sample probed dst address 9                  |
| `DST_IP10`   | sample probed dst address 10                 |
| `DST_IP11`   | sample probed dst address 11                 |
| `DST_IP12`   | sample probed dst address 12                 |
| `DST_IP13`   | sample probed dst address 13                 |
| `DST_IP14`   | sample probed dst address 14                 |
| `DST_IP15`   | sample probed dst address 15                 |


## Aggregator module parameters

In addition to the common pytrap parameter `-i` or `--ifcspec` this
module takes the following parameter:

* `-t` `--time` *integer*: Interval in minutes to wait between sending
  aggregated alerts.

For more detailed information see above under [aggregator
algorithm](#aggregator-algorithm).


<!--- Local variables: -->
<!--- mode: markdown; -->
<!--- mode: auto-fill; -->
<!--- mode: flyspell; -->
<!--- ispell-local-dictionary: "british"; -->
<!--- End: -->
