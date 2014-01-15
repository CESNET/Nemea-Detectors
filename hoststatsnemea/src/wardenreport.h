/*
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
 */

#ifndef _WARDEN_REPORT_H_
#define _WARDEN_REPORT_H_

#include <string>
#include <sstream>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <errno.h>
#include <unistd.h>
#include "aux_func.h"

using namespace std;

struct WardenReport
{
   string service;
   string time;
   string type;
   string source_type;
   string source;
   string target_proto;
   int target_port;
   int attack_scale;
   string note;

   WardenReport()
    : service("HostStats"), source_type("IP"), target_port(0), attack_scale(0), note("")
    {}

   void send(const string& script)
   {
      stringstream ss;
      ss << service << ',';
      ss << time << ',';
      ss << type << ',';
      ss << source_type << ',';
      ss << source << ',';
      ss << target_proto << ',';
      ss << target_port << ',';
      ss << attack_scale << ',';
      ss << note;

      // Call the warden script and check exit code
      int len = ss.str().length();
      char param_str[len+1];
      memcpy(param_str, ss.str().c_str(), len);
      param_str[len] = 0;

      char* const execargv[3] = {const_cast<char*>(script.c_str()), param_str, NULL};
      pid_t pid;
      int status;

      pid = fork();
      if (pid == 0) {
         // Child, exec warden script
         execvp(script.c_str(), execargv);
         log(LOG_ERR, "Can't send warden report. Failed to execute '%s'", script.c_str());
         return;
      } else if (pid != -1) {
         // Parent, wait until child ends
         if (waitpid(pid, &status, 0) == -1)
            log(LOG_ERR, "waitpid() error: %s", strerror(errno));
         else if (!WIFEXITED(status))
            log(LOG_ERR, "'%s' exited abnormally.", script.c_str());
         else if (WEXITSTATUS(status) != 0)
            log(LOG_ERR, "Can't send warden report. '%s' returned %i", script.c_str(), WEXITSTATUS(status));
         else
            log(LOG_INFO, "Warden report sent: %s", ss.str().c_str());
      } else {
         // Fork error
         log(LOG_ERR, "Can't send warden report. Fork error.");
      }
   }
};

#endif
