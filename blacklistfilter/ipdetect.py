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
import sys
import subprocess

from read_config import read_config

program_prefix = sys.argv[0]
main_program = 'blacklistfilter'
usage = "Usage: \n\t" + program_prefix + " start|stop|install|download"

def report(rep_str):
   print program_prefix + ": " + rep_str

if len(sys.argv) != 2:
   report("Bad argument count supplied.\n" + usage)
   exit(1)

if sys.argv[1] == 'start':
   config = read_config()

   pid_name = config[pid_loc]
   try:
      pid_file = open(pid_name, 'w')
   except IOError:
      report("Unable to open \'" + pid_name + "\' file for writing.")
      exit(1)

   tmp = subprocess.Popen(
   [sys.executable, main_program],
   stdout=subprocess.PIPE,
   stderr=subprocess.PIPE,
   stdin=subprocess.PIPE
   )
   if tmp.poll() != 0:
      report("Couldn't start main program.")
      pid_file.close()
      exit(1)
   pid_file.write(tmp)
   pid_file.close()

elif sys.argv[1] == 'stop':
   config = read_config()

   pid_name = config[pid_loc]
   try:
      pid_file = open(pid_name, 'r')
   except IOError:
      report("Unable to open \'" + pid_name + "\' file for reading.")
      exit(1)

   pid = pid_file.readline().rstrip()
   pid_file.close()

   command = "ps -e | grep " + pid
   tmp = subprocess.Popen(["-c", command], stdout=subprocess.PIPE, shell=True)
   output = tmp.communicate()

   if not output[0]:
      report("Main program is not running.")
      exit(1)
   else:
      subprocess.Popen(["kill", pid], shell=True)

elif sys.argv[1] == 'install':
   config = read_config()

   ref = config[refresh_time]
   cron_path = config[cron_loc]
   user = getpass.getuser()

   command = sys.executable + "/" + program_prefix() + " download"

   if ref == 60:
      command = "0 */1 * * *" + user + command

   elif ref > 0 and ref < 60:
      command = "*/" + ref + " * * * *" + user + command

   else:
      report("Wrong update time specified")
      exit(1)

   try:
      cron_file = open(cron_path, 'r+')
   except IOError:
      report("Unable to open \'" + cron_file + "\' file for writing.")
      exit(1)

elif sys.argv[1] == 'download':
   subprocess.Popen(["-c", "kill -USR1 \'ps -e | grep " + main_program + "\'"], shell=True)

else:
   report("Bad arguments supplied.\n" + usage)
   exit(1)
