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
#include "subprofiles.h"
#include "aux_func.h"
#include "processdata.h"
#include "config.h"
#include "detectionrules.h"

//TRAP
extern "C" {
   #include <libtrap/trap.h>
}

using namespace std;

// Defines section
#define DEF_PORT_FLOWDIR true        // source of flowdirection is this module
#define DEF_IN_IFC_TIMEOUT 1000000   // input TRAP interface timeout [ms]


////////////////////////////
// Global variables
int input_ifc_count = 0;

bool background = false;   // Run in background TODO: remove
bool offline_mode = false; // Run in offline mode
int log_syslog = true;     // Log into syslog
int log_upto = LOG_ERR;    // Log up to level 
ur_template_t *tmpl_out = NULL; // TODO: remove
extern HostProfile *MainProfile;

// Only for this file
static sp_list_ptr_v subprofiles_list;

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
      "   Use FlowDirection or DedupAggregator output as an input for this module.\n"
      "   Run module: ./hoststatsnemea -i \"tt;localhost,12345;12346,5\"\n"
      "\n"
      "TRAP Interfaces:\n"
      "   Inputs: 1 \n"
      "      (port-flowdir = 0: \"<COLLECTOR_FLOW>,DIRECTION_FLAGS\")\n"
      "      (port-flowdir = 1: \"<COLLECTOR_FLOW>\")\n"
      "      Note: port-flowdir is a parameter in \"hoststats.conf\"\n"
      "             \n"
      "   Outputs: 1 (\"EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,\n"
      "                DST_PORT,PROTOCOL,EVENT_SCALE\") \n",
   -1, // Number of input TRAP interfaces - variable
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
   switch (signal) {
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

/**
 * \brief 
 */
bool comp_by_ifc_count(subprofile_t *first, subprofile_t *second) {
   return first->interfaces_count > second->interfaces_count;
}

/**
 * \brief Initialize subprofiles list
 * Add all available subprofiles to list
 */
void init_subprofiles_list()
{
   // Fill vector of subprofiles
   // DNS
   subprofiles_list.push_back(new subprofile_t("dns", SUBPROFILE_POINTERS(dns)));
   
   // SSH
   subprofiles_list.push_back(new subprofile_t("ssh", SUBPROFILE_POINTERS(ssh)));
}

int main(int argc, char *argv[])
{
   int ret_code = 1;
   
   openlog(NULL, LOG_NDELAY, 0);
   
   std::vector<hs_in_ifc_spec_t> hs_ifc_list;
   string input_ifc_str;
   std::vector<string> input_ifc;
   bool generic_rules = false;
   
   /* Processing arguments */
   /* Parse TRAP library command-line arguments */
   trap_ifc_spec_t ifc_spec;
   int ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) {
         trap_print_help(&module_info);
         ret_code = 0;
         return ret_code;
      }
      trap_free_ifc_spec(ifc_spec);
      log(LOG_ERR, "ERROR: TRAP parameters parsing failed: %s\n", trap_last_error_msg);
      return ret_code;
   }

   /* Parse module command-line arguments */
   if (arguments(argc, argv) == 0) {
      log(LOG_ERR, "ERROR: Unrecognized parameter(s). Use \"-h\" for help.\n");
      trap_free_ifc_spec(ifc_spec);
      return ret_code;
   }
   
   /* Initialize Configuration singleton */
   Configuration *config = Configuration::getInstance();
   if (Configuration::getInitStatus() != INIT_OK) {
      log(LOG_ERR, "ERROR: Failed to load configuration.\n");
      Configuration::freeConfiguration();
      trap_free_ifc_spec(ifc_spec);
      return ret_code;
   }

   init_subprofiles_list();
   
   /* Load default configuration from config file */
   config->lock();
      
   /* Set logmask if used */
   string logmask = config->getValue("log-upto-level");
   if (!logmask.empty()) {
      parse_logmask(logmask);
   }
   
   /* Get a list of active rules for the detector */
   string rules_str = config->getValue("rules");
   std::vector<string> rules_str_vec = split(rules_str, ',');
   for (size_t i = 0; i < rules_str_vec.size(); ++i) {
      /* Get name of the rule (subprofile) */
      string name = rules_str_vec[i];
      Configuration::trimString(name);
      
      if (name.empty()) {
         log(LOG_ERR, "ERROR: Invalid specification of rules in the "
            "configuration file.");
         config->unlock();
         goto exitA;
      }
      
      if (name == "generic") {
         /* Generic is not subprofile name */
         generic_rules = true;
         continue;
      }
      
      /* Verify the existence of subprofile with this name */
      bool found = false;
      for (sp_list_ptr_iter it = subprofiles_list.begin(); 
         it != subprofiles_list.end(); ++it) {
         if ((*it)->name == name) {
            found = true;
            (*it)->rules_enabled = true;
            break;
         }
      }
      
      if (!found) {
         /* Unknown name of the rule (subprofile) */
         log(LOG_ERR, "ERROR: Unknown rule '%s' (subprofile name) in the "
            "configuration file.", name.c_str());
         config->unlock();
         goto exitA;
      }
   }
   
   /* Get input interfaces configuration */
   input_ifc_str = config->getValue("input_interfaces");
   input_ifc = split(input_ifc_str, ',');
   for (size_t i = 0; i < input_ifc.size(); ++i) {
      /* Get name of interface */
      string name = input_ifc[i];
      Configuration::trimString(name);
      
      if (name.empty()) {
         log(LOG_ERR, "ERROR: Invalid specification of input interface name in "
            "the configuration file.");
         config->unlock();
         goto exitA;
      }
      
      /* Get flow-dir status */
      string flow_dir_str = config->getValue(name + ":port_flowdir");
      Configuration::trimString(flow_dir_str);
      
      bool flow_dir = DEF_PORT_FLOWDIR;
      if (flow_dir_str.empty()) {
         log(LOG_WARNING, "WARNING: Source of flow direction is not specified "
            "for profile '%s'. Using custom generation as default.", name.c_str());
      } else if (flow_dir_str == "1" || flow_dir_str == "true" ) {
         flow_dir = true;
      } else {
         flow_dir = false;
      }
      
      /* Get list of subprofiles to update */
      sp_list_ptr_v ifc_subprofiles;
      
      string sp_str = config->getValue(name + ":subprofiles");
      std::vector<string> sp_str_vec = split(sp_str, ',');
      if (sp_str_vec.size() == 1 && sp_str_vec.front().empty()) {
         /* subprofiles specification missing */
         sp_str_vec.clear();
      }
      
      for (size_t i = 0; i < sp_str_vec.size(); ++i) {
         /* Get name of the subprofile */
         string sp_name = sp_str_vec[i];
         Configuration::trimString(sp_name);
         
         if (sp_name.empty()) {
            log(LOG_ERR, "ERROR: Invalid specification of '%s' subprofiles "
               "in the configuration file.", name.c_str(),
               name.c_str());
            config->unlock();
            goto exitA;
         }
         
         /* Verify the existence of the subprofile with this name */
         sp_list_ptr_iter it = subprofiles_list.begin();
         while (it != subprofiles_list.end()) {
            if ((*it)->name == sp_name) {
               break;
            }
            ++it;
         }
         
         if (it == subprofiles_list.end()) {
            /* Unknown name of the subprofile */
            log(LOG_ERR, "ERROR: Unknown subprofile '%s' of interface '%s' in "
               "the configuration file.", sp_name.c_str(), name.c_str());
            config->unlock();
            goto exitA;
         }
         
         /* Verify that the subprofile is not already in the ifc subprofiles 
          * list */
         sp_list_ptr_iter list_it = ifc_subprofiles.begin();
         while (list_it != ifc_subprofiles.end()) {
            if (*it == *list_it) {
               break;
            }
            ++list_it;
         }
         
         if (list_it != ifc_subprofiles.end()) {
            log(LOG_DEBUG, "DEBUG: The subprofile '%s' is multiple times in "
               "the specification of interface '%s'.", sp_name.c_str(), 
               name.c_str());
            continue;
         }
         
         (*it)->interfaces_count++;
         ifc_subprofiles.push_back(*it);
      }      
      
      /* Create Unirec template */      
      string tmpl_str = config->getValue(name + ":template");
      Configuration::trimString(tmpl_str);
      
      if (tmpl_str.empty()) {
         log(LOG_ERR, "ERROR: Template of interface '%s' is not specified.",
            name.c_str());
         config->unlock();
         goto exitA;
      }
            
            // OVERIT, ZE ROZHRANI OBSAHUJE POZADOVANE POLOZKY PODPROFILU
            // TODO: nacitat dalsi polozky z konfigurace podprofilu
            // NEZAPOMENOUT NA FLOWDIR!!!

      
      log(LOG_DEBUG, "DEBUG: Interface '%s' template: %s", name.c_str(),
         tmpl_str.c_str());
      ur_template_t *tmpl = ur_create_template(tmpl_str.c_str());
      if (tmpl == NULL) {
         log(LOG_ERR, "ERROR: Input UniRec template creation failed.");
         config->unlock();
         goto exitA;
      }
      
      hs_in_ifc_spec_t spec = {name, hs_ifc_list.size(), input_ifc.size(), 
         flow_dir, tmpl, ifc_subprofiles};
      hs_ifc_list.push_back(spec);
   }
   
   if (input_ifc.empty()) {
      log(LOG_ERR, "ERROR: 'Input_interfaces' not found in the configuration "
         "file.");
      config->unlock();
      goto exitA;
   }
   
   /* Set global veriable */
   input_ifc_count = hs_ifc_list.size();
   
   /* Create ouput UniRec template */
   tmpl_out = ur_create_template("EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE");
   if (tmpl_out == NULL) {
      log(LOG_ERR, "ERROR: output UniRec template creation failed.");
      config->unlock();
      goto exitA;
   }
   
   /* Sort subprofiles (subprofiles with more interfaces go to the forefront).
    * Because subprofiles without active interfaces are not necessary to search
    * for suspicious behavior, sorted vector can be used to determine end of 
    * active subprofiles.
    */
   std::sort(subprofiles_list.begin(), subprofiles_list.end(), comp_by_ifc_count);
   if (!subprofiles_list.empty() && !(subprofiles_list.front())->rules_enabled) {
      log(LOG_INFO, "INFO: Detection rules are not active. This module will "
         "not search for suspicious activity.");
   }
   
   /* Update TRAP module specification */
   module_info.num_ifc_in = hs_ifc_list.size();
   
   /* Configuration loaded, initialize TRAP interfaces */
   config->unlock();

   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      log(LOG_ERR, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      goto exitB;
   }
   
   /* Create class for storing flow records */
   MainProfile = new HostProfile(&subprofiles_list, generic_rules);

   /* termination signals */
   signal(SIGTERM, terminate_daemon);
   signal(SIGINT, terminate_daemon);
   
   if (!offline_mode) {
      // ONLINE MODE -----------------------------------------------------------
      log(LOG_INFO, "HostStatsNemea: ONLINE mode");
      int status = 0;

      /* Create data process thread */
      pthread_t data_process_thread;
      status = pthread_create(&data_process_thread, NULL, &data_process_trap, NULL);
      if (status != 0) {
         log(LOG_ERR, "ERROR: Failed to create data process thread.");
         trap_terminate();
         goto exitC;
      }
      
      start_alarm();
      
      // FIXME: if incialization of first data reader thread fail, data process
      //        thread is not terminated...
      
      /* Create data reader threads */
      bool failed = false;
      std::vector<pthread_t> hs_in_ifc_threads;
      for (std::vector<hs_in_ifc_spec_t>::iterator it = hs_ifc_list.begin();
         it != hs_ifc_list.end(); ++it) {
         /* Configure timeout on input interface */
         status = trap_ifcctl(TRAPIFC_INPUT, hs_in_ifc_threads.size(), 
            TRAPCTL_SETTIMEOUT, DEF_IN_IFC_TIMEOUT);
         if (status != TRAP_E_OK) {
            log(LOG_ERR, "ERROR: Failed to configure input interface timeout.");
            trap_terminate();
            failed = true;
            break;
         }
              
         /* Create new thread */
         pthread_t thread_id;
         status = pthread_create(&thread_id, NULL, &data_reader_trap, (void *)
            &(*it));
         if (status != 0) {
            log(LOG_ERR, "ERROR: Failed to create data reader thread.");
            trap_terminate();
            failed = true;
            break;
         }
         hs_in_ifc_threads.push_back(thread_id);
      }
      
      /* If creation of threads failed, wait until all threads are terminated */
      if (failed) {
         pthread_join(data_process_thread, NULL);
         
         for (std::vector<pthread_t>::iterator it = hs_in_ifc_threads.begin();
            it != hs_in_ifc_threads.end(); ++it) {
            pthread_join(*it, NULL);
         }
         
         goto exitC;
      }
      
      /* Block signal SIGALRM */
      sigset_t signal_mask;
      sigemptyset(&signal_mask);
      sigaddset(&signal_mask, SIGALRM);

      status = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
      if (status != 0) {
         log(LOG_ERR, "ERROR: masking signal SIGALRM failed.");
         trap_terminate();
         failed = true;
      }

      /* Wait until end of TRAP threads */
      pthread_join(data_process_thread, NULL);
         
      for (std::vector<pthread_t>::iterator it = hs_in_ifc_threads.begin();
         it != hs_in_ifc_threads.end(); ++it) {
         pthread_join(*it, NULL);
      }
      
      if (failed) {
         goto exitC;
      }
      
   } else {
      // OFFLINE MODE ----------------------------------------------------------
      log(LOG_INFO, "HostStatsNemea: OFFLINE mode");
      log(LOG_WARNING, "OFFLINE MODE IS NOT AVAILABLE IN THIS VERSION. WORK IN PROGRESS");
      // TODO: zprovoznit offline_analyzer - vyzaduje aby se cetlo ze vsech
      // vstupnich TRAP rozhrani
      //offline_analyzer();
   }

   log(LOG_DEBUG, "Exiting... releasing memory");
   ret_code = 0;

exitC:   
   // Delete all records
   delete MainProfile;

   // Necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

exitB:
   // Free output UniRec template
   ur_free_template(tmpl_out);

exitA:
   // Free input UniRec templates
   for (std::vector<hs_in_ifc_spec_t>::iterator it = hs_ifc_list.begin(); 
      it != hs_ifc_list.end(); ++it) {
      ur_free_template(it->tmpl);
   }

   // Delete configuration
   Configuration::freeConfiguration();
   
   // Delete TRAP interface specification
   trap_free_ifc_spec(ifc_spec);
   
   // Free subprofiles
   for (sp_list_ptr_iter rm_it = subprofiles_list.begin(); 
      rm_it != subprofiles_list.end(); ++rm_it) {
      delete (*rm_it);
   }
   
   closelog();
   return ret_code;
}
