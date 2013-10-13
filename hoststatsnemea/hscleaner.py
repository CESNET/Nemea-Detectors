#!/usr/bin/python

# hscleaner.py
#
# This script checks size of host-stats files in a given directory
# and deletes old files when their total size exceeds predefined threshold.
#
# Periodical execution of this script have to be done by some external tool
# (e.g. crond).
#

import sys
import os

# Check and read parameters
if len(sys.argv) < 3:
   print >> sys.stderr, "hscleaner: Please provide path and maximal total size (e.g. 1500M or 40G) as parameters." 
   exit(1)

path = sys.argv[1]

# Parse max size
try:
   max_size_str = sys.argv[2]
   mult = 1
   # ignore possible 'B' at the end
   if max_size_str[-1] == 'B':
      max_size_str = max_size_str[:-1]
   # parse multiplier (k,M,G,T) if specified
   if not max_size_str[-1].isdigit():
      char = max_size_str[-1]
      if char in ['k','K']:
         mult = 1024;
      elif char in ['m','M']:
         mult = 1024**2;
      elif char in ['g','G']:
         mult = 1024L**3;
      elif char in ['t','T']:
         mult = 1024L**4;
      else:
         raise ValueError()
      max_size_str = max_size_str[:-1]
   max_bytes = long(max_size_str)*mult
except ValueError:
   print >> sys.stderr, "hscleaner: Wrong argument: '"+sys.argv[2]+"' is not a valid size."
   exit(1)

# Get all files in path matching reg. exp. "^hs\.[0-9]{12}$"
files = filter(lambda x: x.startswith("hs.") and len(x) == 15 and x[3:].isdigit(),
               os.listdir(path))

# Sort files from the oldest to the newest
files.sort()

# Get size of all files
sizes = []
for f in files:
   try:
      sizes.append(os.path.getsize(os.path.join(path,f)))
   except OSError:
      print >> sys.stderr, "hscleaner: Warning: Can't get size of file '"+os.path.join(path,f)+"'."
      sizes.append(None)
   
total_size = sum(sizes)

# Delete files (starting with the oldest one) until total_size gets below max_size
i = 0
for f,s in filter(lambda (_,s): s is not None, zip(files,sizes)):
   if total_size < max_bytes:
      break
   try:
      os.remove(os.path.join(path,f))
      total_size -= s
      i += 1
   except OSError:
      print >> sys.stderr, "hscleaner: Error: Can't remove file '"+os.path.join(path,f)+"'."

print "hscleaner:", i, "files removed"

if total_size < max_bytes:
   exit(0) # Everything OK
else:
   print >> sys.stderr, "hscleaner: Warning: Script was not successfull for some reason, total size of host-stats files is still greater than maximum ("+str(max_bytes/(1024*1024))+" MB)"
   exit(-1) 
