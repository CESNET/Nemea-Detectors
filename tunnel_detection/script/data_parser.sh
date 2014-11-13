#!/bin/bash
#
# Copyright (C) 2013,2014 CESNET
#
# LICENSE TERMS
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 3. Neither the name of the Company nor the names of its contributors
#    may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# ALTERNATIVELY, provided that this notice is retained in full, this
# product may be distributed under the terms of the GNU General Public
# License (GPL) version 2 or later, in which case the provisions
# of the GPL apply INSTEAD OF those given above.
#
# This software is provided ``as is'', and any express or implied
# warranties, INCluding, but not limited to, the implied warranties of
# merchantability and fitness for a particular purpose are disclaimed.
# In no event shall the company or contributors be liable for any
# direct, indirect, INCidental, special, exemplary, or consequential
# damages (INCluding, but not limited to, procurement of substitute
# goods or services; loss of use, data, or profits; or business
# interruption) however caused and on any theory of liability, whether
# in contract, strict liability, or tort (INCluding negligence or
# otherwise) arising in any way out of the use of this software, even
# if advised of the possibility of such damage.
#


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
