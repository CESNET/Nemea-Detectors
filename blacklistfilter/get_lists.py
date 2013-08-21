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

# address = unicode(address, 'utf-8')
# address = address.encode('idna')

import os
import re
import subprocess

from collections import namedtuple
from shutil import copy
from socket import AF_INET
from socket import AF_INET6
from socket import inet_pton

from funcs import create_directory
from funcs import error
from funcs import open_file
from funcs import read_config
from funcs import report
from funcs import write_dict_data

source = namedtuple( 'source', 'file_name address' )
convertor = namedtuple( 'convertor', 'path name' )
detector = namedtuple( 'detector', 'name check')

detectors = []

cwd = os.getcwd()
sources_path = cwd + '/sources/'
source_path = cwd + '/configure/sources.txt'

cols = 1
delimiter = ' '
addr_col = 1
warden = False
warden_type = None
local = False

def diff( old, new ):
   command = 'grep -vhFxf ' + old + ' ' + new
   grep = subprocess.Popen( ['-c', command], stdout = subprocess.PIPE, shell = True )
   return grep.stdout.read()

def check_line( line ):
   line = line.lstrip()
   if not line or not line[0].isalnum():
      return False
   return True

def check_cols( line, expected_len ):
   if len( line ) != expected_len:
      return False
   return True

def check_domain( address ):
   report( "Checking address for a domain." )
   return re.match(
   r'^'
      r'(?!' # Address doesn't contain IPv4
         r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
      r')'
      r'(?:'
         r'(?:' # Address starts with
            r'(?:[\w\d])|' # a single alphanumeric character as a subdomain, or
            r'(?:(?:[\w\d])(?:[\w\d-]){0,61}(?:[\w\d]))' # a sequence of alphanumeric characters (max 63.), that may contain dash between two alphanumeric characters.
         r')\.' # Then there is a single dot separator after each subdomain
      r')+'
      r'(?:\w){2,6}' # followed by country domain, which is 2-6 characters long.
      r'/?' # Address then may be finished with the slash character.
   r'$', address, re.IGNORECASE)

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
      report( "Invalid address: \'" + address + "\'." )
      return False
   return True

def check_url( address ):
   report( "Checking address for an URL." )
   return re.match(
   r'^'
      r'(?:http(?:s)?://)?(?:www\.)?' # Address may start with (http(s)://)(www.)
      r'(?:'
         r'(?:' # continues with
            r'(?:[\w\d])|' # a single alphanumeric character as a subdomain, or
            r'(?:(?:[\w\d])(?:[\w\d-]){0,61}(?:[\w\d]))' # a sequence of alphanumeric characters (max 63.), that may contain dash between two alpahnumeric characters.
         r')\.' # Then there is a single dot separator after each subdomain
      r')+'
      r'(?:\w){2,6}' # followed by country domain, which is 2-6 characters long.
      r'(?:'
         r'/|' # Address then may be finished with the slash character.
         r'(?:'
            r'(?:/)?'
            r'(?:'
               r'(?:/[\w\d\-\+_%]+)+' # Or continue with a group of folders, separated by slashes.
               r'(?:/)?'
            r')?'
            r'(?:\?' # And followed by parameters, separated with &
               r'(?:[\w\d\-\+_%]+=[\w\d\-\+_%/:\.]+)'
               r'(?:&[\w\d\-\+_%]+=[\w\d\-\+_%/:\.]+)*'
            r')'
         r')|'
         r'(?:' # Or continue with name of a file with a type-suffix
            r'(?:/[\w\d\-\+_%]+)+'
            r'(?:\.[\w\d\-\+_%]+)*'
            r'(?:\?' # that again can be followed by parameters, separated with &
               r'(?:[\w\d\-\+_%]+=[\w\d\-\+_%/:\.]+)'
               r'(?:&[\w\d\-\+_%]+=[\w\d\-\+_%/:\.]+)*'
            r')?'
         r')'
      r')?'
   r'$', address, re.IGNORECASE )

def check_hash( address ):
   return False

def save_addr_into_dicts( addr_path ):
   addr_file = open_file( addr_path, 'r' )
   if not addr_file:
      return False

   exports = [None] * len( detectors )

   for i in range( len( detectors ) ):
      exports[i] = {}

   line_count = 1
   addr_line = addr_file.readline()
   while addr_line:
      if not check_line( addr_line ):
         report( "Line " + str( line_count ) + " in a file \'" + addr_path + "\' doesn\'t start with an alpha-numeric character. Skipping." )
         addr_line = addr_file.readline()
         line_count += 1
         continue

      addr_line = addr_line.split( delimiter )
      if not check_cols( addr_line, cols ):
         report( "Number of columns in a file \'" + addr_path + "\' on a line " + str( line_count ) + " doesn\'t match with expected " + str( cols ) + ". Skipping." )
         addr_line = addr_file.readline()
         line_count += 1
         continue

      addr = addr_line[addr_col-1].lstrip().rstrip()
      report( "Received address: \'" + addr + "\'." )

      for i in range( len( detectors ) ):
         if detectors[i].check( addr ):
            report( "Saving valid \'" + detectors[i].name + "\' detector address.")
            exports[i].update({addr:None})

      addr_line = addr_file.readline()
      line_count += 1

   addr_file.close()
   return exports

def convert_raw_file( raw_path, order ):
   dicts = save_addr_into_dicts( raw_path )
   if not dicts:
      return False

   converted_list = []
   for i in range( len( dicts ) ):
      updates_name = '.' + str( order ) + '.' + detectors[i].name
      updates_path = sources_path + updates_name

      if dicts[i]:
         if not write_dict_data( dicts[i], updates_path, 'keys' ):
            return False
         converted_list.append( convertor( updates_path, updates_name ) )

   return converted_list

def read_sources( source_path ):
   source_file = open_file( source_path, 'r' )
   if not source_file:
      return False

   source_line = source_file.readline()
   if not source_line:
      error( "No sources specified in the \'" + source_path + "\' file." )
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
      error( "No sources were specified correctly in the \'" + source_path + "\' file." )
      return False

   return sources

def replace_old_versions( new_raw_path, old_raw_path, order ):
   if os.path.exists( old_raw_path ):
      os.remove( old_raw_path )
   os.rename( new_raw_path, old_raw_path )

   for i in range( len( detectors ) ):
      new_conv_path = sources_path + '.' + order + '.' + detectors[i].name
      if not os.path.exists( new_conv_path ):
         continue

      old_conv_path = cwd + '/' + detectors[i].name + 'detect/update/' + order
      if os.path.exists( old_conv_path ):
         os.remove( old_conv_path )
      os.rename( new_conv_path, old_conv_path )

def save_conv_diffs( old_conv_path, new_conv_path, out_path ):
   if not os.path.exists( old_conv_path ) or not os.path.exists( new_conv_path ):
      raise NameError( "One of converted files doesn\'t exist." )
      return False
   add = diff( old_conv_path, new_conv_path )
   rem = diff( new_conv_path, old_conv_path )

   if not add and not rem:
      return False

   out_file = open_file( out_path, 'w' )
   if not out_file:
      return False
   out_file.write( add + '# remove\n' + rem )
   out_file.close()

def delete_converted( order ):
   for i in range( len( detectors ) ):
      new_conv_path = sources_path + '.' + order + '.' + detectors[i].name
      if os.path.exists( new_conv_path ):
         os.remove( new_conv_path )

def create_update_dirs():
   for i in range( len( detectors ) ):
      updates_path = cwd + '/' + detectors[i].name + 'detect/update/'
      if not create_directory( updates_path ):
         for j in range( i ):
            updates_path = cwd + '/' + detectors[j].name + 'detect/update/'
            os.remove( updates_path )
         return False
   return True

def get_init():
   global detectors
   detectors.append( detector( 'ip', check_ip ) )
   detectors.append( detector( 'dns', check_domain ) )
   detectors.append( detector( 'url', check_url ) )
   detectors.append( detector( 'hash', check_hash ) )

def compare_converted( converted, detector, order ):
   updates_path = cwd + '/' + detector.name + 'detect/update/'
   detector_path = updates_path + order

   if not os.path.exists( detector_path ):
      copy( converted.path, detector_path )
      replace_old_version( detector_path, converted.path )
      os.rename( converted.path, sources_path + order + '.' + detector.name )
   else:
      if not save_conv_diffs( old_ips_path, converted.path, detector_path ):
         return False

def delete_updates( order ):
   for i in range( len( detectors ) ):
      updates_path = cwd + '/' + detectors[i].name + 'detect/update/' + order
      if os.path.exists( updates_path ):
         os.remove( updates_path )

def assign_cfg_values( current_config ):
   config = {}
   if os.path.exists ( current_config ):
      config = read_config( conf_name = current_config )
   global cols
   global delimiter
   global addr_col
   global warden
   global warden_type
   global local
   cols = config.get( 'columns', 1 )
   delimiter = config.get( 'delimiter', ' ' )
   addr_col = config.get( 'addr_col', 1 )
   warden = bool( config.get( 'warden', False ) )
   warden_type = config.get( 'warden_type', None )
   local = bool( config.get( 'local', False ) )

def get_lists( parameter = 'update' ):
   get_init()

   sources = read_sources( source_path )

   if not sources:
      return False

   if not create_directory( sources_path ):
      return False

   for i in range( 0, len( sources ) ):
      order = sources[i].file_name.split( '.' )[1]
      address = sources[i].address
      old_raw_name = sources[i].file_name
      new_raw_name = '.' + old_raw_name
      old_raw_path = sources_path + old_raw_name
      new_raw_path = sources_path + new_raw_name

      # Get variables from config or assign implicit values
      current_config = cwd + '/configure/conf.' + old_raw_name

      assign_cfg_values( current_config )

      if warden:
         if not warden_type:
            error( "Warden request type is not specified in a file \'" + current_config + "\'. Skipping." )
            continue
         command = 'perl hostrecvwarden.pl ' + warden_type ' > ' + new_raw_path
         cols = 13
         addr_col = 7
         delimiter = ','
      else:
         command = 'wget -O ' + new_raw_path + ' ' + address

      if os.path.exists( new_raw_path ):
         os.remove( new_raw_path )

      report( "Obtaining \'" + old_raw_name + "\'." )

      if not warden and not local:
         os.system( command )
      elif local:
         copy( address, new_raw_path )

      if not os.path.exists( new_raw_path ):
         error( "Obtaining \'" + old_raw_name + "\' has FAILED, skipping." )
         continue

      # Update existing blacklist
      if os.path.exists( old_raw_path ) and parameter == 'update':
         report( "Obtained \'" + old_raw_name + "\' as \'" + new_raw_name + "\'." )

         if os.path.getmtime( new_raw_path ) <= os.path.getmtime( old_raw_path ):
            report( old_raw_name + " is up-to-date, removing raw file and update file." )
            os.remove( new_raw_path )
            delete_updates( order )
            continue

         report( "Obtained file is newer." )
         converted = convert_raw_file( new_raw_path, order )
         if not converted:
            delete_converted( order )
            os.remove( new_raw_path )

         if not create_update_dirs():
            delete_converted( order )
            os.remove( new_raw_path )

         failed = False
         for j in range( len( converted ) ):
            if not compare_converted( converted[j], order ):
               failed = True
               break

         if failed:
            delete_converted( order )
            os.remove( new_raw_path )
            continue

   # Save new blacklist
      else:
         report( "Obtained \'" + old_raw_name + "\' for the first time." )
         converted = convert_raw_file( new_raw_path, order )
         if not converted:
            os.remove ( new_raw_path )
            continue

         if not create_update_dirs():
            delete_converted( order )
            os.remove( new_raw_path )

      replace_old_versions( new_raw_path, old_raw_path, order )
