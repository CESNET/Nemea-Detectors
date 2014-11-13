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

if [ "$1" = "-h" ]; then
	echo "
Script sorts given histogram data by count of packets.
	 First argument is input file to sort.
	 Second argument is output file which is sorted."
	exit
fi
head -2 $1 > $2
tail -n +3 $1| awk '{ 
	sum=0;
	for (i=2; i<=NF;i++)
		sum+=$i;
	
	printf("%s\t", sum);

	for (i=1; i<=NF;i++)
		printf("%s\t", $i);
	printf("\n");
}'| sort -nr | awk '{
	for (i=2; i<NF;i++)
		printf("%s\t", $i);
	printf("%s\n", $NF);	
}' >> $2
