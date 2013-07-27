#!/bin/bash

time=$1
i=0
let end=300-$2
while [ $i -lt 300 ]
do
   echo
   echo "For timebin starting at $time:"
   echo
   echo "Old version:"
	./checker.sh $time $2 1
	echo
	echo "New version:"
	./checker.sh $time $2 2
	echo "----------------------------------------------------------"
	let time=$time+$2
	let i=$i+$2
done