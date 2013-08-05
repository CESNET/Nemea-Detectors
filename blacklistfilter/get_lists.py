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
import re
import subprocess

from collections import namedtuple
from shutil import copy
from socket import inet_pton

from funcs import create_directory
from funcs import error
from funcs import open_file
from funcs import read_config
from funcs import report
from funcs import write_dictionary_data

source = namedtuple('source', 'file_name address')
cwd = os.getcwd()

def diff(old, new, add = True, rem = False):
   if add:
      command = 'grep -vhFxf ' + old + ' ' + new
   else:
      command = 'grep -vhFxf ' + new + ' ' + old

   grep = subprocess.Popen(['-c', command], stdout = subprocess.PIPE, shell = True)

   return grep.stdout.read()

def convert_tmp_file(tmp_path, order):
   order = str(order)

# Open tmp file
   if not open_file(tmp_path, 'r'):
      return False

# Save needed contents of tmp as dictionary keys
   ips = {}
   urls = {}
   tmp_line = tmp_file.readline()
   line = 1
   while tmp_line:
      if tmp_line == '\n':
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

      addr = tmp_line[addr_col]
      report("Received address: "+ addr)

      report("Checking address for an URL.")
      match = re.match(r'^(?:http)s?://(?:www\.)?'
         r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'
         r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)'
         r'(?:/?|[/?]\S+)$', addr, re.IGNORECASE)

      if match:
         report("Saving valid URL.")
         urls[addr] = None
      else:
         report("Checking address for an IP.")

         if ':' in addr:
            report("Assuming IPv6 address.")
            family = AF_INET6
         else:
            report("Assuming IPv4 address.")
            family = AF_INET

         try:
            inet_pton(family, addr)
         except:
            report("Invalid address: " + addr + ". Skipping.")
            tmp_line = tmp_file.readline()
            line += 1
            continue

         report("Saving valid IP.")
         ips[addr] = None

      tmp_line = tmp_file.readline()
      line += 1

   tmp_file.close()

# Save dictionary keys into a file
   new_path = cwd + '/sources/.' + order
   ips_path = new_path + '.ips'
   urls_path = new_path + '.urls'

   ret = False
   if ips:
      write_dict_data(ips, ips_path, 'keys')
      ret = 'ips'

   if urls:
      write_dict_data(urls, urls_path, 'keys')
      if ret == 'ips':
         ret = 'both'
      else:
         ret = 'urls'

   return ret

def create_update_file(updates_path, order):
   if not create_directory(updates_path):
      return False

   update_path = updates_path + order
   if not update_file = open_file(update_path, 'w'):
      return False

   return (update_path, update_file)

def read_sources(source_path):
   if not source_file = open_file(source_path, 'r')
      return False

   source_line = source_file.readline()
   if not source_line:
      error("No sources specified in the " + source_path + " file.")
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
      error("No sources specified correctly in the sources file.")   
      return False

   return sources

def get_lists():
   updates_path = cwd + '/sources/update/'
   updates_url_path = cwd + '/urldetect/update/'
   updates_ips_path = cwd + '/ipdetect/update/'
   sources_path = cwd + '/sources/'
   source_path = cwd + '/configure/sources.txt'

   sources = read_sources(source_path)

   if not sources:
      return False

   if not create_directory(sources_path):
      return False

# TODO: Remove this constraint after implementation
   if prefixes:
      report(file_name + " has an unsupported address format. Skipping.")
      return False

   for i in range(0, len(sources)):
      order = sources[i].file_name.split(".")[1]
      address = sources[i].address
      file_name = sources[i].file_name
      file_path = sources_path + file_name
      tmp_name = "." + file_name
      tmp_path = sources_path + tmp_name
      old_path = sources_path + order

# Get variables from config, assing implicit ones, if it doesn't exist
      current_config = cwd + '/configure/conf.' + file_name
      if os.path.exists(current_config):
         config = read_config(conf_name = current_config)
      cols = config.get('columns', 1)
      delimiter = config.get('delimiter', None)
      addr_col = config.get('addr_col', 0)
      prefixes = config.get('prefixes', False)
      domains = config.get('domains', False)
      mixed = config.get('mixed', False)
      warden = config.get('warden', False)
      warden_type = config.get('warden_type', None)

      if warden == True:
         if warden_type == None:
            error("Warden request type is not specified in a file " + current_config + ". Skipping.")
            continue
         command = "perl hostrecvwarden.pl"
      else:
         command = "wget -O " + tmp_path + " " + address

      report("Downloading " + file_name)
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
         new_path = convert_tmp_file(tmp_path, order)
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
