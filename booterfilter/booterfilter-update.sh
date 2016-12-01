#!/bin/bash

wget -qO - 'https://booterblacklist.com/data/booterlist_latest.txt' |
  sed 's/^.*$/HTTP_REQUEST_HOST == "&" ||/;
  1s/^/:HTTP_REQUEST_HOST != "" \&\& (/; $s/ ||$/)\;/;' > /data/booter-filter/filter &&
  pkill -USR1 -f "booter_filter "

