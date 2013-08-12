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
from socket import AF_INET
from socket import AF_INET6
from shutil import copy
from socket import inet_pton

from funcs import create_directory
from funcs import error
from funcs import open_file
from funcs import read_config
from funcs import report
from funcs import write_dict_data

source = namedtuple( 'source', 'file_name address' )
convertor = namedtuple( 'convertor', 'mode ip_file url_file' )

cwd = os.getcwd()

updates_urls_path = cwd + '/urldetect/update/'
updates_ips_path = cwd + '/ipdetect/update/'
sources_path = cwd + '/sources/'
source_path = cwd + '/configure/sources.txt'

cols = 1
delimiter = ' '
addr_col = 1
warden = False
warden_type = None

def diff( old, new ):
   command = 'grep -vhFxf ' + old + ' ' + new
   grep = subprocess.Popen( ['-c', command], stdout = subprocess.PIPE, shell = True )
   return grep.stdout.read()

def check_line( line ):
   line = line.lstrip()
   if not line or not line[0].isalnum(): 
      return False
   return True

def check_cols( line, expected_len, file_path ):
   line = line.split( delimiter )
   line_len = len( line )
   if line_len != expected_len:
      report( "Number of columns in a file " + file_path + " on a line " + str( line ) + " doesn\'t match. "
      "Expected: " + str( expected_len ) + ", read: " + str( line_len ) + ". Skipping." )
      return False
   return True

def check_url( address ):
   report( "Checking address for an URL." )
   return re.match(
      r'^((?:http)s?://)?(?:www\.)?'
      r'(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'
      r'(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)'
      r'(?:/?|[/?])$', address, re.IGNORECASE
   )

def check_ip( address ):
   report( "Checking address for an IP." )

   if ':' in address:
      report( "Assuming IPv6 address." )
      family = AF_INET6
   else:
      report( "Assuming IPv4 address." )
      family = AF_INET

   try:
      inet_pton( family, address )
   except:
      report( "Invalid address: " + address + "." )
      return False
   return True

def save_addr_into_dict( addr_path ):
   addr_file = open_file( addr_path, 'r' )
   if not addr_file:
      return False

   ips = {}
   urls = {}
   line = 1
   addr_line = addr_file.readline()
   while addr_line:
      if not check_line( addr_line ) or not check_cols( addr_line, cols, addr_path ):
         addr_line = addr_file.readline()
         line += 1
         continue

      addr_line = addr_line.split( delimiter )
      addr = addr_line[addr_col-1].lstrip().rstrip()
      report( "Received address: "+ addr )

      if check_ip( addr ):
         report( "Saving valid IP." )
         ips[addr] = None
      elif check_url( addr ):
         report( "Saving valid URL." )
         urls[addr] = None

      addr_line = addr_file.readline()
      line += 1

   addr_file.close()
   return ips, urls

def convert_raw_file( raw_path, conv_path, order ):
   order = str( order )

   dicts = save_addr_into_dict( raw_path )
   if not dicts:
      return False

   ips = dicts[0]
   urls = dicts[1]

   new_conv_path = conv_path + '.' + order
   ips_path = new_conv_path + '.ip'
   urls_path = new_conv_path + '.url'

   mode = None
   if ips:
      write_dict_data( ips, ips_path, 'keys' )
      mode = 'ips'

   if urls:
      write_dict_data( urls, urls_path, 'keys' )
      if mode:
         mode = 'both'
      else:
         mode = 'urls'

   return convertor( mode, ips_path, urls_path )

def read_sources( source_path ):
   source_file = open_file( source_path, 'r' )
   if not source_file:
      return False

   source_line = source_file.readline()
   if not source_line:
      error( "No sources specified in the " + source_path + " file." )
      source_file.close()
      return False

   sources = []
   while source_line:
      if source_line == "\n" or source_line.lstrip()[0] == '#':
         source_line = source_file.readline()
         continue
      source_line = source_line.rstrip().split( ' ' )
      if len( source_line ) != 2:
         report( "Wrong source format, skipping." )
         source_line = source_file.readline()
         continue
      sources.append( source( source_line[0], source_line[1] ) )
      source_line = source_file.readline()

   source_file.close()

   if not len( sources ):
      error( "No sources were specified correctly in the " + source_path + " file." )   
      return False

   return sources

def replace_old_version( old_file_path, new_file_path ):
   if not os.path.exists( new_file_path ):
      raise NameError( "File \'" + new_file_path + "\' doesn\'t exist." )
      return False
   if os.path.exists( old_file_path ):
      os.remove( old_file_path )
   os.rename( new_file_path, old_file_path )

def save_conv_diffs( old_conv_path, new_conv_path, out_path ):
   if not os.path.exists( old_conv_path ) or not os.path.exists( new_conv_path ):
      raise NameError( "One of converted files doesn\'t exist." )
      return False
   add = diff( old_conv_path, new_conv_path )
   rem = diff( new_conv_path, old_conv_path )

   if not add and not rem:
      return False

   out_file = open_file( out_path, 'w' )
   if not update_file:
      return False
   out_file.write( add + '# remove\n' + rem )
   out_file.close()

def get_lists( parameter = 'update' ):
sources = read_sources( source_path )

if not sources:
   return False

if not create_directory( sources_path ):
   return False

for i in range( 0, len( sources ) ):
   order = sources[i].file_name.split( '.' )[1]
   address = sources[i].address
   old_raw_name = sources[i].file_name
   old_raw_path = sources_path + old_raw_name
   new_raw_name = '.' + old_raw_name
   new_raw_path = sources_path + new_raw_name
   old_ips_path = sources_path + order + '.ips'
   old_urls_path = sources_path + order + '.urls'

   # Get variables from config or assign implicit values
   current_config = cwd + '/configure/conf.' + old_raw_name
   config = {}
   if os.path.exists ( current_config ):
      config = read_config( conf_name = current_config )
   cols = config.get( 'columns', cols )
   delimiter = config.get( 'delimiter', delimiter )
   addr_col = config.get( 'addr_col', addr_col )
   warden = config.get( 'warden', warden )
   warden_type = config.get( 'warden_type', warden_type )

   if warden:
      if not warden_type:
         error( "Warden request type is not specified in a file " + current_config + ". Skipping." )
         continue
      command = "perl hostrecvwarden.pl"
      cols = 13
      addr_col = 7
      delimiter = ','
   else:
      command = "wget -O " + new_raw_path + " " + address

   if os.path.exists( new_raw_path ):
      os.remove( new_raw_path )

   report( "Obtaining " + old_raw_name + "." )
   if not warden:
      os.system( command )

   if not os.path.exists( new_raw_path ):
      error( "Obtaining " + old_raw_name + " has FAILED, skipping." )
      continue

# Update existing blacklist
   if os.path.exists( old_raw_path ) and parameter == 'update':
      report( "Obtained " + old_raw_name + " as " + new_raw_name + "." )

      if os.path.getmtime( new_raw_path ) <= os.path.getmtime( old_raw_path ):
         report( old_raw_name + " is up-to-date, removing raw file and update file." )
         if os.path.exists( updates_ips_path + order ):
            os.remove( updates_ips_path )
         if os.path.exists( updates_urls_path + order ):
            os.remove( updates_urls_path )
         os.remove( new_raw_path )
         continue

      report( "Obtained file is newer." )
      converted = convert_raw_file( new_raw_path, sources_path, order )
      if not converted:
         os.remove( new_raw_path )

      mode = converted.mode
      if mode == None:
         report( "No conversion could\'ve been done with the \'" + old_raw_name + "\' file.")

      if mode == 'ips' or mode == 'both':
         if create_directory( updates_ips_path ):
            if os.path.exists( old_ips_path ):
               save_conv_diffs( old_ips_path, converted.ip_file, updates_ips_path + order )

      if mode == 'urls' or mode == 'both':
         if create_directory( updates_url_path ):
            if os.path.exists( old_urls_path ):
               save_conv_diffs( old_urls_path, converted.url_file, updates_urls_path + order )

# Save new blacklist
   else:
      report( "Obtained " + old_raw_name + " for the first time." )
      converted = convert_raw_file( new_raw_path, sources_path, order )
      if not converted:
         os.remove ( new_raw_path )
         continue

      mode = converted.mode
      if mode == 'ips' or mode == 'both':
         if create_directory( updates_ips_path ):
            replace_old_version( updates_ips_path + order, converted.ip_file )
         else:
            os.remove( new_raw_path )
            os.remove( converted.ip_file )
      if mode == 'urls' or mode == 'both':
         if create_directory( updates_urls_path ):
            replace_old_version( updates_urls_path + order, converted.url_file )
         else:
            os.remove( new_raw_path )
            os.remove( converted.url_file )

   replace_old_version( old_raw_path, new_raw_path )
