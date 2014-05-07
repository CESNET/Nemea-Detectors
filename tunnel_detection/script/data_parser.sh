#!/bin/bash

if [ $# -lt 4 ]; then
   echo "$0 <filename> <start index> <stop index> <output file>"
   echo "Module expects PCAP files with this name convention:"
   echo "\"<filename><index>\", where index is iterated from <start index> to <stop index>"
   exit 0
fi

b=$1
thr=0
for (( i=$2 ; i<=$3; i=$i+1 ))
do
   ((thr++))
   tshark -r $1$i  -T fields -E separator=\; -e frame.time_epoch  -e ip.addr -e ipv6.addr -e dns.flags.response -e frame.len -e dns.qry.name -e dns.txt -e dns.resp.primaryname -e dns.mx.mail_exchange  -e dns.resp.ns > "thrpart.$thr"&
   if [ $thr -eq 4 ]; then
	thr=0
	wait
	cat thrpart.* >> "$4"
	rm thrpart.*
	echo $i done
   fi
done
