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
import subprocess

from getpass import getuser
from signal import SIGTERM
from signal import SIGUSR1

from funcs import error
from funcs import read_config
from funcs import open_file

from get_lists import get_lists

def get_pid(pid_name):
   pid_file = open_file( pid_name, 'r' )
   if not pid_file:
      exit( 1 )
   pid = pid_file.readline().rstrip().lstrip()
   pid_file.close()
   return pid

def is_running(pid):
   command = 'ps -e | grep ' + pid
   tmp = subprocess.Popen( ['-c', command], stdout = subprocess.PIPE, shell = True )
   output = tmp.communicate()
   return bool(output[0])

program_prefix = sys.argv[0]
cwd = os.getcwd()
ip_detector = cwd + '/ipdetect/ipblacklistfilter'
ip_sources = cwd + '/ipdetect/update/'
url_detector = cwd + '/urldetect/urlblacklistfilter'
url_sources = cwd + '/urldetect/update/'

usage = "Usage: \n\t" + program_prefix + " start|stop|install|download ip|url"

if len( sys.argv ) != 3:
   error( "Bad argument count supplied.\n" + usage )
   exit( 1 )

call_method = sys.argv[1]
filter_type = sys.argv[2]

if filter_type == 'ip':
   main_program = ip_detector
   sources = ip_sources
   detector_name = "IP-Blacklist"
elif filter_type == 'url':
   main_program = url_detector
   sources = url_sources
   detector_name = "URL-Blacklist"
else:
   error( "Bad arguments supplied.\n" + usage )
   exit( 1 )

if call_method != 'start' and call_method != 'stop' and call_method != 'install' and call_method != 'download':
   error( "Bad arguments supplied.\n" + usage )
   exit( 1 )

# Get parameters from config or use implicit ones
config = read_config()
pid_name = config.get( 'pid_loc', '.pid_file' )
pid_name += filter_type
ref = config.get( 'refresh_time', 60 )
cron_path = config.get( 'cron_loc', '/etc/crontab' )
user = config.get( 'user', getuser() )

if call_method == 'start':
   get_lists('new')

   pid_file = open_file( pid_name, 'w' )
   if not pid_file:
      exit( 1 )

   tmp = subprocess.Popen(
      [main_program, '-i', 'tb;localhost,7000;', sources],
      stdout = subprocess.PIPE,
      stderr = subprocess.PIPE,
      stdin = subprocess.PIPE
   )

   tmp.poll()
   if tmp.returncode != None:
      error( "Couldn\'t start " + detector_name + " Detector." )
      pid_file.close()
      os.remove( pid_name )
      exit( 1 )

   pid_file.write( str(tmp.pid) )
   pid_file.close()

elif call_method == 'stop':
   pid = get_pid(pid_name)
   if not pid:
      error( "Couldn\'t stop " + detector_name + " Detector. No PID in PID file." )
      exit( 1 )

   if not is_running(pid):
      error( "Couldn\'t stop " + detector_name + " Detector. Couldn\'t find process specified in PID file." )
      exit( 1 )
   else:
      os.kill ( int(pid), SIGTERM )
      os.remove( pid_name )

elif call_method == 'install':
   if int( ref ) == 60:
      command = '0 */1 * * * '

   elif int( ref ) > 0 and int( ref ) < 60:
      command = '*/' + ref + ' * * * * '

   else:
      error( "Wrong update time specified in the config file." )
      exit( 1 )

   command += user + ' ' + sys.executable + ' ' + cwd + '/' + program_prefix + ' download ' + sys.argv[2] + '\n\n'

   cron_file = open_file( cron_path, 'r' )
   if not cron_file:
      exit ( 1 )

   whole_cron = ''
   cron_line = cron_file.readline()
   while cron_line:
      if cron_line[0] == '#' or cron_line == '\n':
         whole_cron += cron_line
         cron_line = cron_file.readline()
         continue

      if cron_line.find(program_prefix) != -1: # Lines containing 'program_prefix' are ignored
         cron_line = cron_file.readline()
         continue

      whole_cron += cron_line
      cron_line = cron_file.readline()
   cron_file.close()

   cron_file = open_file( cron_path, 'w' )
   if not cron_file:
      exit ( 1 )
   cron_file.write( whole_cron + command )
   cron_file.close()

elif call_method == 'download':
   if not get_lists('update'):
      exit( 1 ) 

   pid = get_pid(pid_name)
   if not pid:
      error( "Couldn't send signal to " + detector_name + " Detector. No PID in PID file." )
      exit( 1 )

   if not is_running(pid):
      error( "Couldn't send signal to " + detector_name + " Detector. Couldn\'t find process specified in PID file." )
      exit( 1 )
   else:
      os.kill( int(pid), SIGUSR1 )

exit( 0 )
