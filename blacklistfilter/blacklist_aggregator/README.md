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
- Ports are listed only when < 49152
- Maximum target IPs is 1000 (if more, the list is trimmed) 
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


## Fields
- **type**: _ip_ or _url_
- **ts_first**: first flow timestamp in agg window
- **ts_last**: last flow timestamp in agg window
- **protocol**: 6, 17 etc.
- **source/source_url/source_ip**: "source of trouble", the blacklisted entity
- **source_ports**: list of ports used by the blacklisted entity
- **targets**: IP list of the clients which communicated with the blacklisted entity
- **src_sent_\***: Bytes/flows/packets sent by the source of trouble (blacklisted entity)
- **dst_sent_\***: Bytes/flows/packets sent by the clients
- **blacklist_id**: bitmap ID of the blacklist 
- **agg_win_minutes**: Aggregation window in minutes (can be float)

- **referer**: HTTP Referer
- **is_only_fqdn**: boolean whether its only FQDN or the entire URL (with HTTP_PATH)

## IP Example input

IP addresses are anonymized.

```
ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 DST_BLACKLIST,uint64 SRC_BLACKLIST,time TIME_FIRST,time TIME_LAST,uint32 COUNT,uint32 PACKETS,uint16 DST_PORT,uint8 PROTOCOL

33.74.225.111,244.67.210.241,40,0,8,2018-10-27T09:49:31.225,2018-10-27T09:49:31.225,1,1,10674,6
85.135.214.126,244.67.210.241,80,0,8,2018-10-27T09:49:30.261,2018-10-27T09:49:30.317,1,2,11233,6
165.190.75.188,244.67.210.241,80,0,8,2018-10-27T09:49:31.805,2018-10-27T09:49:31.862,1,2,10890,6
85.64.183.34,244.67.210.241,40,0,8,2018-10-27T09:49:31.448,2018-10-27T09:49:31.448,1,1,9139,6
244.53.103.8,244.67.210.241,40,0,8,2018-10-27T09:49:30.477,2018-10-27T09:49:30.477,1,1,9656,6
12.69.59.88,244.67.210.182,120,0,8,2018-10-27T09:49:28.200,2018-10-27T09:49:30.203,1,2,22,6
12.68.18.79,244.67.210.182,240,0,8,2018-10-27T09:49:24.979,2018-10-27T09:49:31.997,1,4,22,6
12.68.16.157,244.67.210.182,240,0,8,2018-10-27T09:49:24.959,2018-10-27T09:49:31.975,1,4,22,6
85.78.102.80,244.67.210.241,40,0,8,2018-10-27T09:49:31.870,2018-10-27T09:49:31.870,1,1,10484,6
222.93.53.217,244.67.210.241,40,0,8,2018-10-27T09:49:31.614,2018-10-27T09:49:31.614,1,1,9369,6
```

## IP Example output

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



## URL Example input
```
ipaddr DST_IP,ipaddr SRC_IP,uint64 BLACKLIST,uint64 BYTES,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 PROTOCOL,string HTTP_REQUEST_HOST,string HTTP_REQUEST_REFERER,string HTTP_REQUEST_URL
25.41.145.5,73.167.62.100,32,999,2018-09-28T14:16:28.594,2018-09-28T14:16:29.656,11,80,43698,6,"zstresser.com","","/"
25.41.145.5,73.167.62.100,32,1003,2018-09-28T14:16:46.409,2018-09-28T14:16:59.675,6,80,43714,6,"www.zstresser.com","","/"
25.41.145.5,73.167.62.100,32,1296,2018-09-28T14:16:34.998,2018-09-28T14:17:58.126,13,80,43698,6,"zstresser.com","http://zstresser.com/","/"
51.39.31.34,73.167.62.100,1,339,2018-09-28T14:20:53.809,2018-09-28T14:20:54.300,6,80,46324,6,"xemphimhayhd.ga","","/"
185.56.137.60,73.167.62.100,17,498,2018-10-07T16:52:14.355,2018-10-07T16:52:15.110,8,80,35256,6,"029999.com","","/"
185.56.137.60,73.167.62.100,17,450,2018-10-07T16:52:42.145,2018-10-07T16:52:42.876,7,80,35260,6,"www.029999.com","","/"
10.116.32.232,73.167.62.100,4,450,2018-10-07T16:53:29.120,2018-10-07T16:53:30.301,6,80,58012,6,"112.e-democracy.bg","","/fre/verification/00m0b9b77e5093accacd/access.php"
149.59.29.188,73.167.62.100,32,935,2018-10-07T16:56:21.339,2018-10-07T16:56:21.457,21,80,50082,6,"123boot.pro","","/"

```


## URL Example output
Things to notice:
- `029999.com` appears twice, that's because it's on two blacklists.
- `www.zstresser.com` and `zstresser.com` are treated the same

```
{
  "protocol": 6,
  "source_ports": [
    80
  ],
  "tgt_sent_bytes": 3298,
  "blacklist_id": 32,
  "source_ip": "25.41.145.5",
  "tgt_sent_packets": 30,
  "is_only_fqdn": true,
  "source_url": "zstresser.com",
  "tgt_sent_flows": 3,
  "ts_first": 1538144188.594,
  "agg_win_minutes": 0.2,
  "ts_last": 1538144278.126,
  "referer": "",
  "type": "url",
  "targets": [
    "73.167.62.100"
  ]
}
{
  "protocol": 6,
  "source_ports": [
    80
  ],
  "tgt_sent_bytes": 935,
  "blacklist_id": 32,
  "source_ip": "149.59.29.188",
  "tgt_sent_packets": 21,
  "is_only_fqdn": true,
  "source_url": "123boot.pro",
  "tgt_sent_flows": 1,
  "ts_first": 1538931381.339,
  "agg_win_minutes": 0.2,
  "ts_last": 1538931381.457,
  "referer": "",
  "type": "url",
  "targets": [
    "73.167.62.100"
  ]
}
{
  "protocol": 6,
  "source_ports": [
    80
  ],
  "tgt_sent_bytes": 339,
  "blacklist_id": 1,
  "source_ip": "51.39.31.34",
  "tgt_sent_packets": 6,
  "is_only_fqdn": true,
  "source_url": "xemphimhayhd.ga",
  "tgt_sent_flows": 1,
  "ts_first": 1538144453.809,
  "agg_win_minutes": 0.2,
  "ts_last": 1538144454.3,
  "referer": "",
  "type": "url",
  "targets": [
    "73.167.62.100"
  ]
}
{
  "protocol": 6,
  "source_ports": [
    80
  ],
  "tgt_sent_bytes": 948,
  "blacklist_id": 1,
  "source_ip": "185.56.137.60",
  "tgt_sent_packets": 15,
  "is_only_fqdn": true,
  "source_url": "029999.com",
  "tgt_sent_flows": 2,
  "ts_first": 1538931134.355,
  "agg_win_minutes": 0.2,
  "ts_last": 1538931162.876,
  "referer": "",
  "type": "url",
  "targets": [
    "73.167.62.100"
  ]
}
{
  "protocol": 6,
  "source_ports": [
    80
  ],
  "tgt_sent_bytes": 450,
  "blacklist_id": 4,
  "source_ip": "10.116.32.232",
  "tgt_sent_packets": 6,
  "is_only_fqdn": false,
  "source_url": "112.e-democracy.bg/fre/verification/00m0b9b77e5093accacd/access.php",
  "tgt_sent_flows": 1,
  "ts_first": 1538931209.12,
  "agg_win_minutes": 0.2,
  "ts_last": 1538931210.301,
  "referer": "",
  "type": "url",
  "targets": [
    "73.167.62.100"
  ]
}
{
  "protocol": 6,
  "source_ports": [
    80
  ],
  "tgt_sent_bytes": 948,
  "blacklist_id": 16,
  "source_ip": "185.56.137.60",
  "tgt_sent_packets": 15,
  "is_only_fqdn": true,
  "source_url": "029999.com",
  "tgt_sent_flows": 2,
  "ts_first": 1538931134.355,
  "agg_win_minutes": 0.2,
  "ts_last": 1538931162.876,
  "referer": "",
  "type": "url",
  "targets": [
    "73.167.62.100"
  ]
}

```