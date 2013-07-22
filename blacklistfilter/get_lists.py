#!/usr/bin/python
#

"""
 * Copyright (C) 2013 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
"""

import os
import sys

from collections import namedtuple
from aux import report

source = namedtuple('source', 'file_name address')

try:
   source_file = open('sources', 'r')
except IOError:
   report("No sources file available for reading.")
   exit(1)

source_line = source_file.readline()
if not source_line:
   report("No sources specified in the sources file.")
   source_file.close()
   exit(1)

sources = []
while source_line:
   source_line = source_line.rstrip().split(" ")
   if len(source_line) != 2:
      report("Wrong source format, skipping.")
      source_line = source_file.readline()
      continue
   sources.append(source(source_line[0], source_line[1]))
   source_line = source_file.readline()

source_file.close()

if not len(sources):
   report("No sources specified correctly in the sources file.")   
   exit(1)

for i in range(0, len(sources)):
   address = sources[i].address
   file_name = sources[i].file_name
   tmp_name = "." + sources[i].file_name

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
         os.remove(file_name)
         os.rename(tmp_name, file_name)
      else:
         report(file_name + " is up-to-date, removing temporary file.")
         os.remove(tmp_name)
   else:
      report("Downloaded "+ file_name +" for the first time")
      os.rename(tmp_name, file_name)

exit(0)
