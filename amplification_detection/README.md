Simple amplification detection module
=====================================


Table of Contents
-----------------

* [Module description](#module-description)
* [How it works](#how-it-works)
* [Detection method](#detection-method)
* [How to use](#how-to-use)
* [Compilation and linking](#compilation-and-linking)


Module description
------------------

Module implements simple amplification attacks detection, based
on flow's number of packets and bytes. It analyzes query and response traffic.
Works with flow data.


How it works
------------

The module uses history model to analyze number of packets and bytes of
queries and responses between two IP addresses. Detection process for the IP
address pair starts when certain time window of data is reached. Then the
oldest 5 minutes of data are erased from history. Inactive IP address pairs
are also deleted after some time.

Detection method is based on the amount of packets/bytes in the traffic. It uses
several thresholds specified in the section of Additional parameters. Method
calculates histograms of different monitored data, which are used to determine
the most occurred values.

Module input:	`<COLLECTOR_FLOW>`
Module output:	`<AMPLIFICATION_ALERT>`


Detection method
----------------

Detection process is triggered when the stored data for `<SRC_IP>` and `<DST_IP>`
key pair reached certain time window.

At first, 4 histograms from the stored data in the history model are generated:

- histogram of flow sizes in bytes for query direction (hvqb)
- histogram of flow sizes in packets for query direction (hvqp)
- histogram of flow sizes in bytes for response direction (hvrb)
- histogram of flow sizes in packets for response direction (hvrp)

Now we can use these histograms in the detection algorithm along with functions
which are required for detection. It is important that we are able to transform
histogram to normalized histogram, count number of occurrences of flow, sum
number of packets or bytes and compute average value of histogram. Very
important is that we can take only N of most occurring values sorted descending.

Algorithm is demonstrated by this pseudocode:

```
if (sum(topn(norm(hvrb),<N>) > <I> && sum(topn(hvrb),<N>) > <T> ) {
   if ( avgh(topn(hvrp,<N>)) > <Y> && avgh(topn(hvrb,<N>)) > <L> && avgh(topn(hvqb,<N>)) < <M> ) {
      if ( sum(topn(hvrb),<N>)/sum(topn(hvqb),<N>) ) > <A> ) {
            send(<AMPLIFICATION_ALERT>);
      }
   }
}
```

In first condition we normalize the histogram of flow sizes in bytes for response
direction, then we take `N` most occurring values from the histogram and we sum
the occurrences of pair. This value must be higher than threshold `I`.
Also we take top-N of the same histogram and we sum the occurrence of pair,
comparing it to the threshold `T`.

Second condition is created from three similar parts. We take three histograms,
get the top-N from each of them and then we compute their average values. Each
of these values must be higher or lower than certain threshold.

Then the third condition computes the amplification effect from summing the
top-N values of histograms of bytes for queries and responses. If the computed
amplification effect is higher than threshold set for this value, the condition
is met.

Now the `<AMPLIFICATION_ALERT>` is generated, which consists of:

- `SRC_IP`: SRC IP address		ip address of amplification server
- `DST_IP`: DST IP address		ip address of victim
- `SRC_PORT`: SRC PORT			port of detection
- `REQ_FLOWS`, `RSP_FLOWS`: total flows of attack	# of flows in detected as attack
- `REQ_PACKETS`, `RSP_PACKETS`: total packets of attack	# of attack packets
- `REQ_BYTES`, `RSP_BYTES`: total bytes of attack	# of attack bytes
- `TIME_FIRST`: attack start time		first timestamp of attack flow
- `TIME_LAST`: attack detection time	timestamp of positive detection


How to use
----------

The module is implemented on TRAP platform so you have to specify TRAP
interfaces correctly. Then you can specify one of the parameters listed below.
Default values of parameters are in the brackets

Usage:

```
./amplification_detection -i <trap_interface> <Additional parameters>
```

Additional parameters:
    -p <port>		port used for detection (53)
    -n <num>		number of topN values chosen (10)
    -q <step>		step of histogram (10)
    -a <num>		minimal amplification effect considered an attack (5)
    -t <num>		minimal threshold for number of flows in TOP-N (1000)
    -i <num>		minimal normalized threshold for count of flows in TOP-N (0.4)
    -y <num>		minimal threshold for average size of responses in packets in TOP-N (0)
    -l <num>		minimal threshold for average size of responses in bytes in TOP-N (1000)
    -m <num>		maximal threshold for average size of queries in bytes in TOP-N (300)
    -w <sec>		time window of detection / timeout of inactive flow key (3600)
    -s <sec>		time window of deletion / period of inactive flow keys checking (300)

Compilation and linking
-----------------------

No special compilation parameters are needed. For linking add -ltrap and -lunirec
(the module must be compiled as a part of [NEMEA](https://github.com/CESNET/Nemea) repository or using installed libtrap-devel and unirec packages).

Doxygen documentation can be generated with `make doxygen` command.

