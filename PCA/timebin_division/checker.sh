#!/bin/sh
if [ $3 -eq 1 ]; then
	FILENAME="tb-old."$1
else
	FILENAME="tb-new."$1
fi

echo "File: $FILENAME"

ok=0
under=0
over=0

let X=$1+$2

while read LINE
do
   if [ $LINE -le $X ]; then
      if [ $LINE -ge $1 ]; then
			let ok++
		else
		   let under++
		fi
	else
		let over++
	fi
done < $FILENAME

let ERR=($ok+$over+$under)/100
let ERR=($over+$under)/$ERR

echo "OK: $ok"
echo "UNDER: $under (should be in some previous timebin)"
echo "OVER: $over (should be in some next timebin)"
echo "FAULT PERCENTAGE: $ERR%"