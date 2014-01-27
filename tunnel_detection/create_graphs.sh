#!/bin/bash
if [ "$1" = "-h" ]; then
	echo "
Script will sort data and create graphs.
Argument is folder with data"
	exit
fi
echo "Sorting data..."
./script/sort.sh $1/requests.dat $1/requests_sort.dat
./script/sort.sh $1/responses.dat $1/responses_sort.dat
echo "Data sorted."
echo "Creating summary graph..."
Rscript script/run-summary.R $1/summary_requests.dat  $1/summary_responses.dat $1/graphs/summary.pdf
echo "Summary graph created."
echo "Creating requests graph..."
mkdir $1/graphs
Rscript script/run-details.R $1/requests_sort.dat  $1/graphs/requests.pdf
echo "Requests graph created."
echo "Creating responses graph..."
Rscript script/run-details.R $1/responses_sort.dat  $1/graphs/responses.pdf
echo "Responses graph created."

