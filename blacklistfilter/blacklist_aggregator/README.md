# Blacklist aggregator

Blacklist aggregator receives IP and URL detection flows from blacklist detectors and aggregates them in a time window.
(DNS detection is not aggregated and goes straight to the Adaptive filter, this is explained in the main [README](../README.md)).
Output of IP detector is pre-aggregated with the [Universal aggregator](https://github.com/CESNET/Nemea-Modules/tree/master/aggregator). 
Records are being aggregated 1:N in time window, where 1 is the blacklisted entry, N are the clients who communicated with it.

## Usage:

```
Usage:	blacklist_aggregator.py -i <trap_interface> [-t <minutes>]
```

## Operation
- Modules receives IP flows (first interface) and URL flows (second interface)
- Default aggregation time window is 5 minutes, after this timeout, the aggregated events are sent to the output interface
- Index of the blacklist is split if containing more blacklists (when entity is on two and more blacklists, 
there is an aggregated event for each)
- Aggregation keys are as follows:
    - IP:
        - IP address of the blacklisted entity
        - IP protocol (6 - TCP, 17 - UDP, ..)
        - index of the blacklist where entity is listed (only one blacklist index)
    - URL:
        - HTTP Request host
        - HTTP Request URL
        - Destination IP address
        - IP protocol (6 - TCP, 17 - UDP, ..)
        - index of the blacklist where entity is listed (only one blacklist index)

## Example input


## Example output

```
{
  "src_sent_bytes": 360,
  "protocol": 6,
  "source_ports": [],
  "ts_last": 1540633771.87,
  "tgt_sent_packets": 0,
  "src_sent_flows": 7,
  "targets": [
    "33.74.225.111",
    "165.190.75.188",
    "244.53.103.8",
    "85.78.102.80",
    "85.135.214.126",
    "85.64.183.34",
    "222.93.53.217"
  ],
  "source": "244.67.210.241",
  "tgt_sent_flows": 0,
  "ts_first": 1540633770.261,
  "type": "ip",
  "blacklist_id": 8,
  "agg_win_minutes": 0.5,
  "tgt_sent_bytes": 0,
  "src_sent_packets": 9
}
{
  "src_sent_bytes": 600,
  "protocol": 6,
  "source_ports": [],
  "ts_last": 1540633771.997,
  "tgt_sent_packets": 0,
  "src_sent_flows": 3,
  "targets": [
    "12.69.59.88",
    "12.68.18.79",
    "12.68.16.157"
  ],
  "source": "244.67.210.182",
  "tgt_sent_flows": 0,
  "ts_first": 1540633764.959,
  "type": "ip",
  "blacklist_id": 8,
  "agg_win_minutes": 0.5,
  "tgt_sent_bytes": 0,
  "src_sent_packets": 10
}
```
