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

def report( rep_str ):
   program_prefix = sys.argv[0]
   print program_prefix + ": " + rep_str

def error( err_str ):
   program_prefix = sys.argv[0]
   sys.stderr.write( program_prefix + ": " + err_str + '\n' )

def create_directory( dir_path ):
   if not os.path.exists( dir_path ):
      try:
         os.makedirs( dir_path )
      except OSError:
         error( "Failed to create " + dir_path + " directory." )
         return False
   else:
      report("Directory "+ dir_path +" already exists.")
   return True

def open_file( file_path, flag = 'r' ):
   if flag == 'r':
      operation = "reading"
   elif flag == 'w':
      operation = "writing"
   elif flag == 'a':
      operation = "appending"
   elif flag == 'r+':
      operation = "reading and appending"
   elif flag == 'rb':
      operation = "binary reading"
   elif flag == 'wb':
      operation = "binary writing"
   elif flag == 'ab':
      operation = "binary appending"
   elif flag == 'r+b':
      operation = "binary reading and appending"
   else:
      raise TypeError( "Wrong flag(\'" + flag + "\') specified." )

   try:
      opened_file = open( file_path, flag )
   except IOError:
      error( "Unable to open " + file_path + " for " + operation + "." )
      return False

   return opened_file

def read_config( conf_name = './configure/conf', delimiter = ' ', comment = '#' ):
   config = {}
   conf_file = open_file( conf_name, 'r' )
   if not conf_file:
      return config

   conf_line = conf_file.readline()
   while conf_line:
      if conf_line[0] == comment or conf_line == '\n':
         conf_line = conf_file.readline()
         continue

      conf_line = conf_line.rstrip().split( delimiter )
      if len( conf_line ) != 2:
         report( "Wrong configuration file format." )
         conf_file.close()
         exit( 1 )
      conf_key = conf_line[0]
      conf_val = conf_line[1]
      config[conf_key] = conf_val
      conf_line = conf_file.readline()

   conf_file.close()
   return config

def write_dict_data( dictionary, destination, item, delimiter = '\n' ):
   out = ""

   if item == 'keys':
      for key in dictionary.iterkeys():
         out += key + delimiter
   elif item == 'values':
      for value in dictionary.itervalues():
         out += value + delimiter
   else:
      raise NameError( "Wrong item name(\'" + item + "\') specified." )

   if destination == 'stderr':
      sys.stderr.write( out )
   elif destination == 'stdout':
      sys.stdout.write( out )
   else:
      dest_file = open_file( destination, 'w' )
      if not dest_file:
         return False
      dest_file.write( out )
      dest_file.close()
   return True
