#!/bin/bash
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
