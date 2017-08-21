#!/bin/bash

curl https://www.spamhaus.org/drop/edrop.txt | sed 's/\s*;.*$//;' > spamhaus-org-edrop.txt

curl https://lists.blocklist.de/lists/ssh.txt > blocklist-de-ssh.txt

