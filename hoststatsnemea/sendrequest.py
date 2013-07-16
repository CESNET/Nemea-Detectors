#!/usr/bin/python

# This script can be used to test hoststatserv.
# It allows you to send arbitrary request with parameters to given port on localhost
# and prints reply.
# Example usage (GET_HOST_HISTORY request):
#  ./sendrequest.py 3333 35 "all;1.2.3.4;201303020100;201303020155"
# If port is not given, 3333 is used

from socket import *
import sys

if len(sys.argv) == 4:
   port = int(sys.argv[1])
   code = int(sys.argv[2])
   params = sys.argv[3]
elif len(sys.argv) == 3:
   port = 3333
   code = int(sys.argv[1])
   params = sys.argv[2]
else:
   print "Usage:", sys.argv[0], "[port] code params"
   exit(1)

s = socket(AF_INET, SOCK_STREAM)
s.connect(("localhost", port))

s.sendall(chr(code)+params)
s.shutdown(1)

reply = s.recv(1024)
while (reply):
   sys.stdout.write(reply)
   reply = s.recv(1024)

s.close()