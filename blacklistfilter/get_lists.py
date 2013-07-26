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

from collections import namedtuple
from shutil import copy
from socket import getaddrinfo

from funcs import create_directory
from funcs import perror
from funcs import read_config
from funcs import report

source = namedtuple('source', 'file_name address')
cwd = os.getcwd()

def diff(old, new, add = True, rem = False):
   if add:
      command = 'grep -vhFxf ' + old + ' ' + new
   else:
      command = 'grep -vhFxf ' + new + ' ' + old

   grep = subprocess.Popen(['-c', command], stdout = subprocess.PIPE, shell = True)

   return grep.stdout.read()

def convert_tmp_file(tmp_path, file_name, order):
   order = str(order)

# Default values for reading from the tmp file
   cols = 1
   delimiter = None
   addr_col = 0
   prefixes = False
   domains = False

# Overwrite values, if config exists
   current_config = cwd + '/configure/conf.' + file_name
   if os.path.exists(current_config):
      config = read_config(conf_name = current_config)
      cols = config.get('columns', cols)
      delimiter = config.get('delimiter', delimiter)
      addr_col = config.get('addr_col', addr_col)
      prefixes = config.get('prefixes', prefixes)
      domains = config.get('domains', domains)

# TODO: Remove these constrains after implementation
   if prefixes or domains:
      report("Unsupported address format. Skipping.")
      return False

# Open tmp file
   try:
      tmp_file = open(tmp_path, 'r')
   except IOError:
      perror("Unable to open " + tmp_path + " for reading")
      os.remove(tmp_path)
      return False

# Save needed contents of tmp as dictionary keys
   new = {}
   tmp_line = tmp_file.readline()
   line = 1
   while tmp_line:
      if tmp_line == "\n":
         tmp_line = tmp_file.readline()
         line += 1
         continue

      tmp_line = tmp_line.lstrip()
      if not tmp_line:
         tmp_line = tmp_file.readline()
         line += 1
         continue

      if not tmp_line[0].isalnum():
         report("Line " + str(line) + " in a file " + tmp_path + " doesn\'t start with alpha-numeric character. Skipping.")
         tmp_line = tmp_file.readline()
         line += 1
         continue

      tmp_line = tmp_line.split(delimiter)
      line_len = len(tmp_line)
      if line_len != cols:
         report("Number of columns in a file " + tmp_path + " on a line " + str(line) + " doesn\'t match. Expected: " + str(cols) + ", read: " + str(line_len) + ". Skipping.")
         tmp_line = tmp_file.readline()
         line += 1
         continue

      # tuple indexes
      canonname = 4
      address = 0

      report("Resolving: " + tmp_line[addr_col])
      try:
         info = getaddrinfo(tmp_line[addr_col], None)
      except:
         report("Unable to resolve: " + tmp_line[addr_col])
         tmp_line = tmp_file.readline()
         line += 1
         continue

      for i in range(0, len(info)):
         addr = info[i][canonname][address]
         report("Resolved as: " + addr)
         new[addr] = None

      tmp_line = tmp_file.readline()
      line += 1

   tmp_file.close()

# Save dictionary keys into a file
   new_path = cwd + '/sources/.' + order

   if os.path.exists(new_path):
      os.remove(new_path)

   try:
      new_file = open(new_path, 'w')
   except IOError:
      perror("Unable to open " + new_path + " for writing")
      os.remove(tmp_path)
      return False

   out = ""
   for k in new.iterkeys():
      out += k + '\n'

   new_file.write(out)
   new_file.close()

   return new_path

def create_update_file(updates_path, order):
   if not create_directory(updates_path):
      return False

   update_path = updates_path + order
   try:
      update_file = open(update_path, 'w')
   except IOError:
      perror("Unable to open " + update_path + " for writing")
      return False

   return (update_path, update_file)

def read_sources(source_path):
   try:
      source_file = open(source_path, 'r')
   except IOError:
      perror("No " + source_path + " file available for reading.")
      return False

   source_line = source_file.readline()
   if not source_line:
      perror("No sources specified in the " + source_path + " file.")
      source_file.close()
      return False

   sources = []
   while source_line:
      if source_line == "\n" or source_line.lstrip()[0] == "#":
         source_line = source_file.readline()
         continue
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
      return False

   return sources

"""-------------- Main program ---------------"""

updates_path = cwd + '/sources/update/'
sources_path = cwd + '/sources/'
source_path = cwd + '/configure/sources.txt'

sources = read_sources(source_path)

if not sources:
   exit(1)

if not create_directory(sources_path):
   exit(1)

for i in range(0, len(sources)):
   order = sources[i].file_name.split(".")[1]
   address = sources[i].address
   file_name = sources[i].file_name
   file_path = sources_path + file_name
   tmp_name = "." + file_name
   tmp_path = sources_path + tmp_name
   old_path = sources_path + order

   report("Downloading " + file_name)
   command = "wget -O " + tmp_path + " " + address
   os.system(command)

   if not os.path.exists(tmp_path):
      report("Downloading " + file_name + " has FAILED, skipping.")
      continue

   if os.path.exists(file_path):
      report("Downloaded " + file_name + " as " + tmp_name)

      if os.path.getmtime(tmp_path) <= os.path.getmtime(file_path):
         report(file_name + " is up-to-date, removing temporary file and update file.")
         update_path = updates_path + order
         if os.path.exists(update_path):
            os.remove(update_path)
         os.remove(tmp_path)
         continue

      report("Downloaded file is newer.")
      new_path = convert_tmp_file(tmp_path, file_name, order)
      if not new_path:
         os.remove(tmp_path)
         continue

#Determine changes between old and new version
      if os.path.exists(old_path):
         add = diff(old_path, new_path)
         rem = diff(old_path, new_path, add = False)

         update_file = create_update_file(updates_path, order)
         update_path = update_file[0]
         update_file = update_file[1]

         if not update_file:
            os.remove(tmp_path)
            exit(1)

         if add or rem:
            update_file.write(add + "# remove\n" + rem)
         update_file.close()

         if not add and not rem:
            os.remove(update_path)
         os.remove(old_path)

      os.rename(new_path, old_path)
      os.remove(file_path)
      os.rename(tmp_path, file_path)

   else:
      report("Downloaded " + file_name + " for the first time")

      new_path = convert_tmp_file(tmp_path, file_name, order)
      if not new_path:
         os.remove(tmp_path)
         continue

      if os.path.exists(old_path):
         os.remove(old_path)

      os.rename(new_path, old_path)

      if not create_directory(updates_path):
         exit(1)

      copy(old_path, updates_path + order)

      os.rename(tmp_path, file_path)

