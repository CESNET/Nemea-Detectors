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

import getpass
import os
import sys
import subprocess

import aux
report = aux.report

program_prefix = sys.argv[0]
main_program = os.getcwd() + 'blacklistfilter'
usage = "Usage: \n\t" + program_prefix + " start|stop|install|download"

if len(sys.argv) != 2:
   report("Bad argument count supplied.\n" + usage)
   exit(1)

if sys.argv[1] == 'start':
   config = aux.read_config()

   pid_name = config['pid_loc']
   try:
      pid_file = open(pid_name, 'w')
   except IOError:
      report("Unable to open \'" + pid_name + "\' file for writing.")
      exit(1)

   tmp = subprocess.Popen(
   ['/usr/bin/sh', main_program],
   stdout=subprocess.PIPE,
   stderr=subprocess.PIPE,
   stdin=subprocess.PIPE
   )
   if tmp.poll() != 0:
      report("Couldn\'t start main program.")
      pid_file.close()
      exit(1)
   pid_file.write(tmp)
   pid_file.close()

elif sys.argv[1] == 'stop':
   config = aux.read_config()

   pid_name = config['pid_loc']
   try:
      pid_file = open(pid_name, 'r')
   except IOError:
      report("Unable to open \'" + pid_name + "\' file for reading.")
      exit(1)

   pid = pid_file.readline().rstrip()
   pid_file.close()

   if not pid:
      report("Main program is not running.")
      exit(1)

   command = 'ps -e | grep ' + pid
   tmp = subprocess.Popen(['-c', command], stdout = subprocess.PIPE, shell = True)
   output = tmp.communicate()

   if not output[0]:
      report("Main program is not running.")
      exit(1)
   else:
      subprocess.Popen(['kill', pid], shell = True)

elif sys.argv[1] == 'install':
   config = aux.read_config()

   ref = config['refresh_time']
   cron_path = config['cron_loc']
   user = getpass.getuser()

   if int(ref) == 60:
      command = '0 */1 * * * '

   elif int(ref) > 0 and int(ref) < 60:
      command = '*/' + ref + ' * * * * '

   else:
      report("Wrong update time specified in the config file.")
      exit(1)

   command += user + ' ' + sys.executable + os.getcwd() + '/' + program_prefix + ' download\n\n'

   try:
      cron_file = open(cron_path, 'r')
   except IOError:
      report("Unable to open \'" + cron_path + "\' file for reading.")
      exit(1)

   cron_line = cron_file.readline()
   whole_cron = ''

   while cron_line:
      if cron_line[0] == '#' or cron_line == '\n':
         whole_cron += cron_line
         cron_line = cron_file.readline()
         continue

      if cron_line.find(program_prefix) != -1:
         cron_line = cron_file.readline()
         continue

      whole_cron += cron_line
      cron_line = cron_file.readline()
   cron_file.close()

   try:
      cron_file = open(cron_path, 'w')
   except IOError:
      report("Unable to open \'" + cron_path + "\' file for writing.")
      exit(1)

   cron_file.write(whole_cron + command)
   cron_file.close()

elif sys.argv[1] == 'download':
   subprocess.call(['python get_lists.py'], shell = True)

   config = aux.read_config()

   pid_name = config['pid_loc']
   try:
      pid_file = open(pid_name, 'r')
   except IOError:
      report("Unable to open \'" + pid_name + "\' file for reading.")
      exit(1)

   pid = pid_file.readline().rstrip()
   pid_file.close()

   if not pid:
      report("Main program is not running. No PID in PID file.")
      exit(1)

   command = 'ps -e | grep ' + pid
   tmp = subprocess.Popen(['-c', command], stdout = subprocess.PIPE, shell = True)
   output = tmp.communicate()

   if not output[0]:
      report("Main program is not running. Couldn\'t find process specified in PID file.")
      exit(1)
   else:
      subprocess.Popen(['kill', '-USR1 ' + pid], shell = True)

else:
   report("Bad arguments supplied.\n" + usage)
   exit(1)

exit(0)
