#!/usr/bin/python
#

import os

from collections import namedtuple

source = namedtuple('source', 'file_name address')

program_prefix = "get_lists.py"

def report(rep_str):
    print program_prefix + ": " + rep_str

try:
    source_file = open('sources', 'r')
except IOError:
    report("No sources file available for reading.")
    exit(1)

source_line = source_file.readline()
if ( source_line == "" ):
    report("No sources specified in the sources file.")
    source_file.close()
    exit(1)

sources = []
while source_line != "":
    source_line = source_line.rstrip().split(" ")
    if len(source_line) != 2:
        report("Wrong source format, skipping.")
        source_line = source_file.readline()
        continue
    sources.append(source(source_line[0], source_line[1]))
    source_line = source_file.readline()

if len(sources) == 0:
    report("No sources specified correctly in the sources file.")
    source_file.close()
    exit(1)

for i in range(0, len(sources)):
    address = sources[i].address
    file_name = sources[i].file_name
    tmp_name = "." + sources[i].file_name + "~"

    command = "wget -O " + tmp_name + " " + address

    report("Downloading " + file_name)
    os.system(command)

    if os.path.exists(tmp_name) == False:
        report("Downloading " + file_name + " has FAILED, skipping.")
        continue

    if os.path.exists(file_name):
        report("Downloaded " + file_name + " as " + tmp_name)
        if os.path.getmtime(tmp_name) > os.path.getmtime(file_name):
            report(file_name + " is old, keeping new version.")
            os.remove(sources[i].file_name)
            os.rename(tmp_name, file_name)
        else:
            report(sources[i].file_name + " is up-to-date, removing temporary file.")
            os.remove(tmp_name)
    else:
        report("Downloaded "+ file_name +" for the first time")
        os.rename(tmp_name, file_name)


