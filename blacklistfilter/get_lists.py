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
import subprocess
import sys

from collections import namedtuple
from socket import getaddrinfo

from funcs import report
from funcs import perror

source = namedtuple('source', 'file_name address')
source_name = 'sources.txt'
cwd = os.getcwd()

try:
   source_file = open(source_name, 'r')
except IOError:
   perror("No " + sources_name + " file available for reading.")
   exit(1)

source_line = source_file.readline()
if not source_line:
   perror("No sources specified in the " + sources_name + " file.")
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
   perror("No sources specified correctly in the sources file.")   
   exit(1)

sources_dir = cwd + '/sources/'

if not os.path.exists(sources_dir):
   try:
      os.mkdir(sources_dir)
   except OSError:
      perror("Failed to create " + sources_dir + " directory.")
      exit(1)

for i in range(0, len(sources)):
   address = sources[i].address
   file_name = sources[i].file_name + '.' + i
   file_dir = sources_dir + file_name
   tmp_name = "." + file_name
   tmp_dir = sources_dir + tmp_name

   report("Downloading " + file_name)
   command = "wget -O " + tmp_dir + " " + address
   os.system(command)

   if not os.path.exists(tmp_dir):
      report("Downloading " + file_name + " has FAILED, skipping.")
      continue

   if os.path.exists(file_dir):
      report("Downloaded " + file_name + " as " + tmp_name)

      if os.path.getmtime(tmp_dir) <= os.path.getmtime(file_dir):
         report(file_name + " is up-to-date, removing temporary file.")
         os.remove(tmp_dir)
         continue

      report("Downloaded file is newer.")
""" Basic variables for reading from the tmp file """
      cols = 1
      delimiter = None
      addr_col = 0

""" Overwrite values, if config exists """
      current_config = cwd + '/.conf.' + i
      if os.path.exists(current_config):
         config = read_config(current_config)
         cols = config['columns']
         delimiter = config['delimiter']
         addr_col = config['addr_col'] - 1

""" Open tmp file """
      try:
         tmp_file = open(tmp_dir, 'r')
      except IOError:
         perror("Unable to open " + tmp_dir + " for reading")
         exit(1)

""" Convert tmp file into correct format """
      new = {}
      next = tmp_file.readline().lstrip()
      tmp_line = next()
      j = 1
      while tmp_line:
         if not tmp_line[0].islanum():
            tmp_line = next()
            j += 1
            continue

         tmp_line = tmp_line.split(delimiter)
         if len(tmp_line) != cols:
            report("Number of columns in file " + tmp_dir + " on line " + j + " doesn\'t fit. Skipping.")
            tmp_line = next()
            j += 1
            continue

         # tuple indexes
         canonname = 4
         address = 0
         info = getaddrinfo(tmp_line[addr_col], None)
         for k in range(0, len(info))
            addr = info[k][canonname][address]
            new[addr] = None

         tmp_line = next()
         j += 1

      tmp_file.close()

      new_dir = cwd + '/sources/update/.' + i
      try:
         new_file = open(new_dir, 'w')
      except IOError:
         perror("Unable to open "+ new_dir + "for writing")
         exit(1)
      
      for k in new.iterkeys():
         
      
      new_file.close()

      add_command = 'grep -vhFxf ' + file_dir + ' ' + tmp_dir
      rem_command = 'grep -vhFxf ' + tmp_dir + ' ' + file_dir

      add_tmp = subprocess.Popen(['-c', add_command], stdout = subprocess.PIPE, shell = True)

      add_line = add_tmp.stdout.readline()

      os.remove(file_dir)
      os.rename(tmp_dir, file_dir)
   else:
      report("Downloaded "+ file_name +" for the first time")
      os.rename(tmp_dir, file_dir)

