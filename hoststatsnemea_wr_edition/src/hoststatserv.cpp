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

#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <string>
#include <sstream>
#include "hoststats.h"
#include "profile.h"
#include "aux_func.h"
#include "processdata.h"
#include "config.h"
#include "detectionrules.h"

//TRAP
extern "C" {
   #include <libtrap/trap.h>
}

using namespace std;

////////////////////////////
// Global variables

string config_file = "";
bool background = false;   // Run in background
bool offline_mode = false; // Run in offline mode
int log_syslog = true;     // Log into syslog
int log_upto = LOG_ERR;    // Log up to level 
ur_template_t *tmpl_in = NULL;
ur_template_t *tmpl_out = NULL;
extern HostProfile *MainProfile;

///////////////////////////////////////////////////
// Struct with information about Nemea module
trap_module_info_t module_info = {
   (char *) "HostStatsNemea module", // Module name
   // Module description
   (char *)
      "This module calculates statistics for IP addresses and subprofiles(SSH,DNS,...)\n"
      "\n"
      "USAGE ./hoststatsnemea TRAP_INTERFACE [-c file] [-F]\n"
      "\n"
      "Parameters:\n"
      "   -c file  Load configuration from file.\n"
      "   -F       Run module in OFFLINE mode. It is used for analysis of already\n"
      "            captured flows. As a source can be used module such as nfreader,\n"
      "            trapreplay, etc.\n"
      "Note: Other parameters are taken from configuration file. If configuration file\n"
      "      is not specified, hoststats.conf is used by default.\n"
      "\n" 
      "Example of how to run this module:\n"
      "   Edit the configuration file \"hoststats.conf\" and especially the line\n"
      "   \"detection-log\" with the folder path to save the event log.\n"
      "   (optional) Use FlowDirection or DedupAggregator output as an input for \n"
      "              this module.\n"
      "   Run module: ./hoststatsnemea -i \"tt;localhost,12345;12346,5\"\n"
      "\n"
      "TRAP Interfaces:\n"
      "   Inputs: 1 \n"
      "      (port-flowdir = 0: \"<COLLECTOR_FLOW>,DIRECTION_FLAGS\")\n"
      "      (port-flowdir = 1: \"<COLLECTOR_FLOW>\")\n"
      "      Note: port-flowdir is a parameter in \"hoststats.conf\"\n"
      "             \n"
      "   Outputs: 1 (\"EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,\n"
      "                DST_PORT,PROTOCOL,EVENT_SCALE,NOTE\") \n",
   1, // Number of input TRAP interfaces
   1, // Number of output TRAP interfaces
};

/** \brief Parse arguments
 * \param[in] argc Argument count
 * \param[in] argv Argument values
 */
int arguments(int argc, char *argv[])
{
   char opt;
   
   while ((opt = getopt(argc, argv, "c:F")) != -1) {
      switch (opt) {
      case 'c':  // configuration file
         Configuration::setConfigPath(string(optarg));
         break;
      case 'F':
         offline_mode = true;
         break;
      default:  // invalid arguments
         return 0;
      }
   }
   return 1;
}

void parse_logmask(string &mask);

void terminate_daemon(int signal)
{
   Configuration *cf;
   string logmask;

   switch (signal) {
   case SIGHUP:
      syslog(LOG_NOTICE, "Cought HUP signal -> reload configuration...");
      cf = Configuration::getInstance();
      cf->reload();
      logmask = cf->getValue("log-upto-level");
      parse_logmask(logmask);
      break;
   case SIGTERM:
      trap_terminate();
      log(LOG_NOTICE, "Cought TERM signal...");
      break;
   case SIGINT:
      trap_terminate();
      log(LOG_NOTICE, "Cought INT signal...");
      break;
   default:
      break;
   }
}

void parse_logmask(string &mask)
{
   if (mask.compare("LOG_EMERG") == 0) {
      log_upto = LOG_EMERG;
   } else if (mask.compare("LOG_ALERT") == 0) {
      log_upto = LOG_ALERT;
   } else if (mask.compare("LOG_CRIT") == 0) {
      log_upto = LOG_CRIT;
   } else if (mask.compare("LOG_ERR") == 0) {
      log_upto = LOG_ERR;
   } else if (mask.compare("LOG_WARNING") ==0) {
      log_upto = LOG_WARNING;
   } else if (mask.compare("LOG_NOTICE") == 0) {
      log_upto = LOG_NOTICE;
   } else if (mask.compare("LOG_INFO") == 0) {
      log_upto = LOG_INFO;
   } else if (mask.compare("LOG_DEBUG") == 0) {
      log_upto = LOG_DEBUG;
   }
   setlogmask(LOG_UPTO(log_upto));
}

int main(int argc, char *argv[])
{
   /* Inicialization and processing arguments */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info)

   if (arguments(argc, argv) == 0) {
      fprintf(stderr, "ERROR: unrecognized parameter(s). Use \"-h\" for help\n");
      TRAP_DEFAULT_FINALIZATION();
      return 1;
   }

   // Initialize Configuration singleton
   Configuration *config = Configuration::getInstance();
   if (Configuration::getInitStatus() != INIT_OK) {
      Configuration::freeConfiguration();
      fprintf(stderr, "ERROR: failed to load configuration.\n");
      TRAP_DEFAULT_FINALIZATION();
      return 1;
   }

   openlog(NULL, LOG_NDELAY, 0);
   log(LOG_INFO, "HostStatsNemea started");
   
   // Load default configuration from config file
   config->lock();
      
   /* Set logmask if used */
   string logmask = config->getValue("log-upto-level");
   if (!logmask.empty()) {
      parse_logmask(logmask);
   }

   /* Create UniRec template */
   tmpl_out = ur_create_template("EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,"
      "DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE,NOTE");
   
   if (config->getValue("port-flowdir") == "0") {
      tmpl_in = ur_create_template("<COLLECTOR_FLOW>,DIRECTION_FLAGS");
   } else {
      tmpl_in = ur_create_template("<COLLECTOR_FLOW>");
   }
   
   if (tmpl_in == NULL || tmpl_out == NULL) {
      log(LOG_ERR, "Error when creating UniRec template.\n");
      if (tmpl_in != NULL) ur_free_template(tmpl_in);
      if (tmpl_out != NULL) ur_free_template(tmpl_out);
      config->unlock();
      return 1;
   }

   config->unlock();

   
   /* Create structure for storing flow records */
   MainProfile = new HostProfile();

   /* termination signals */
   signal(SIGTERM, terminate_daemon);
   signal(SIGINT, terminate_daemon);
   /* reload configuration signal: */
   signal(SIGHUP, terminate_daemon);

   if (!offline_mode) {
      // ONLINE MODE -----------------------------------------------------------
      log(LOG_INFO, "HostStatsNemea: ONLINE mode");
      pthread_t data_reader_thread;
      pthread_t data_process_thread;

      int rc = 0;
      bool failed = false;

      rc = pthread_create(&data_reader_thread, NULL, &data_reader_trap, NULL);
      if (rc) {
         trap_terminate();
         failed = true;
      }

      if (!failed) {
         rc = pthread_create(&data_process_thread, NULL, &data_process_trap, NULL);
         if (rc) {
            trap_terminate();
            failed = true;
         }
      }

      // Block signal SIGALRM
      sigset_t signal_mask;
      sigemptyset(&signal_mask);
      sigaddset(&signal_mask, SIGALRM);

      rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
      if (rc != 0) {
         trap_terminate();
         failed = true;
      }

      // Wait until end of TRAP threads
      pthread_join(data_process_thread, NULL);
      pthread_join(data_reader_thread, NULL);
   } else {
      // OFFLINE MODE ----------------------------------------------------------
      log(LOG_INFO, "HostStatsNemea: OFFLINE mode");
      offline_analyzer();
   }

   log(LOG_DEBUG, "Exiting... releasing memory");
   
   // Delete all records
   delete MainProfile;

   // Delete configuration
   Configuration::freeConfiguration();

   // Necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(tmpl_in);
   ur_free_template(tmpl_out);

   closelog();

   pthread_exit(NULL);
   return 0;
}
