#!/bin/bash

# script that analysis diffrence between ip and domain in data

# setup variables
DATA_PATH=~/data/smtp*
DATA_NUM=10000
TIME_STAMP=$time
FILE=/tmp/smtp_analysis_$TIME_STAMP

# load data from logger 
/bin/nemea/logger -t -i f:$DATA_PATH | head -n $DATA_NUM |

# sort by ip 
sort -t: -k2 |

# make pretty outpu
tr ',' '\t' |
less -x 40 -S > $FILE

# awk analysis (compare sorted prev value with current)
awk 'BEGIN {
   stats=0;
}
{
   if (NR==1) {
      prev_ip = $2;
      prev_dom = $25;
   } else {
      if ($2 == prev_ip && $25 != prev_dom ) {
         stats++;
         print prev_ip " has diffrent domain (" $25 " != " prev_dom " )";
         prev_ip = $2;
         prev_dom = $25;

      } else {
         prev_ip = $2;
         prev_dom = $25;
      }
   }
}
END {
 print "Found " stats " diffrent stats." 
}' $FILE
