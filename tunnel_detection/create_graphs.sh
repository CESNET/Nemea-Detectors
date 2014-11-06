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
Script will sort data and create graphs.
Argument is folder with data"
	exit
fi
echo "Sorting data..."
./script/sort.sh $1/requests.dat $1/requests_sort.dat
./script/sort.sh $1/responses.dat $1/responses_sort.dat
./script/sort.sh $1/request_letters_count.dat $1/request_letters_count_sort.dat
echo "Data sorted."
mkdir $1/graphs
echo "Creating summary graph..."
Rscript script/run-summary.R $1/summary_requests.dat  $1/summary_responses.dat $1/graphs/summary.pdf
echo "Summary graph created."
echo "Creating requests graph..."
Rscript script/run-details.R $1/requests_sort.dat  $1/graphs/requests.pdf
echo "Requests graph created."
echo "Creating request letters count graph..."
Rscript script/run-details.R $1/request_letters_count_sort.dat  $1/graphs/request_letters_count.pdf
echo "Request letters count created."
echo "Creating responses graph..."
Rscript script/run-details.R $1/responses_sort.dat  $1/graphs/responses.pdf
echo "Responses graph created."

