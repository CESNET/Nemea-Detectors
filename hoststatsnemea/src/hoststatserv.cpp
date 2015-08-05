/**
 * \file hoststatserv.cpp
 * \brief Main module file
 * \author Lukas Hutak <xhutak01@stud.fit.vutbr.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2013-2015 CESNET
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string>
#include <csignal>
#include <pthread.h>
#include "hoststats.h"
#include "profile.h"
#include "aux_func.h"
#include "processdata.h"
#include "config.h"
#include <unistd.h>
#include <getopt.h>

//TRAP
extern "C" {
   #include <libtrap/trap.h>
}
using namespace std;

////////////////////////////
// Global variables
int log_upto = LOG_ERR;    // Log up to level
ur_template_t *tmpl_in = NULL;
ur_template_t *tmpl_out = NULL;

// Extern variables
extern HostProfile *MainProfile;
extern sp_list_ptr_v subprofile_list;

// Status information
static bool offline_mode = false; // Run in offline mode
static bool send_eos = true;

// Define section
#define DEF_REQUIRED_TMPL "<COLLECTOR_FLOW>"  // required input UniRec items

///////////////////////////////////////////////////
// Struct with information about Nemea module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("HostStatsNemea module","This module calculates statistics for IP addresses and subprofiles(SSH,DNS,...)",1,1)

#define MODULE_PARAMS(PARAM) \
  PARAM('c', "config", "Load configuration from file.", required_argument, "string") \
  PARAM('F', "offline", "Run module in OFFLINE mode. It is used for analysis of already captured flows. As a source can be used module such as nfreader, trapreplay, etc.", no_argument, "none") \
  PARAM('n', "no_message", "Don't send end-of-stream message.", no_argument, "none")

/** \brief Parse arguments
 * \param[in] argc Argument count
 * \param[in] argv Argument values
 */
int arguments(int argc, char *argv[], const char *module_getopt_string, const struct option *long_options)
{
   char opt;

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'c':  // configuration file
         Configuration::setConfigPath(string(optarg));
         break;
      case 'F':
         offline_mode = true;
         break;
      case 'n':
         send_eos = false;
         break;
      default:  // invalid arguments
         return 0;
      }
   }
   return 1;
}

/** \brief Default signal handler
 * \param[in] signal Signal ID
 */
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

/** \brief Check if UniRec template is subset of another UniRec template
 * Both templates must be initialized.
 * \param[in] main_tmpl Primary template
 * \param[in] subs_tmpl Tested template
 * \param[out] missing_items String with names of missing UniRec items
 * \return If subs_tmpl is subset of the main_tmpl returns true. Otherwise
 * retuns false and fill missing_items with names of missing UniRec items.
 */
bool is_template_subset(const ur_template_t *main_tmpl, const ur_template_t
   *subs_tmpl, string *missing_items = NULL)
{
   bool subset = true;
   string items;
   ur_field_id_t ur_set_id;
   ur_iter_t ur_set_iter = UR_ITER_BEGIN;

   /* Iterate over all required UniRec items */
   while ((ur_set_id = ur_iter_fields_tmplt(subs_tmpl, &ur_set_iter))
      != UR_INVALID_FIELD) {
      if (ur_is_present(main_tmpl, ur_set_id)) {
         continue;
      }

      subset = false;
      if (!items.empty()) {
         items += ",";
      }
      items += UR_FIELD_NAMES[ur_set_id];
   }

   /* Result check */
   if (!subset && missing_items != NULL) {
      *missing_items = items;
   }
   return subset;
}

/** \brief Main function
 */
int main(int argc, char *argv[])
{
   /* Inicialization and processing of TRAP arguments */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /* Configure output interface */
   if (trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT)
      != TRAP_E_OK) {
      fprintf(stderr, "ERROR: trap_ifcctl() failed.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   /* Parse command line arguments */
   if (arguments(argc, argv, module_getopt_string, long_options) == 0) {
      fprintf(stderr, "ERROR: Unrecognized parameter(s). Use \"-h\" for help\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   /* Initialize Configuration singleton */
   Configuration *config = Configuration::getInstance();
   if (Configuration::getInitStatus() != INIT_OK) {
      Configuration::freeConfiguration();
      fprintf(stderr, "ERROR: Failed to load configuration.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   openlog(NULL, LOG_NDELAY, 0);
   log(LOG_INFO, "HostStatsNemea started");

   /* Load module configuration from the config file */
   config->lock();

   /* Set logmask if used */
   string logmask = trim(config->getValue("log-upto-level"));
   if (!logmask.empty()) {
      parse_logmask(logmask);
   }

   /* Some variables initialization because of goto */
   ur_field_id_t dir_flag_id = UR_DIRECTION_FLAGS;
   ur_template_t *coll_tmpl = NULL;

   /* Create UniRec template */
   std::string input_tmpl_str = trim(config->getValue("input-template"));
   if (input_tmpl_str.empty()) {
      log(LOG_ERR, "ERROR: Input template 'input-template' is not specified "
         "the configuration file.");
      config->unlock();
      goto exitA;
   }

   tmpl_in = ur_create_template(input_tmpl_str.c_str());
   tmpl_out = ur_create_template("EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,"
      "DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE,NOTE");

   if (tmpl_in == NULL || tmpl_out == NULL) {
      if (tmpl_in == NULL) {
         log(LOG_ERR, "ERROR: Failed to create input UniRec template. Make "
            "sure that input template value 'input-template' in the "
            "configuration file is correct.");
      }
      if (tmpl_out == NULL) {
         log(LOG_ERR, "ERROR: Failed to create output UniRec template. "
            "Internal error.");
      }

      if (tmpl_in != NULL) ur_free_template(tmpl_in);
      if (tmpl_out != NULL) ur_free_template(tmpl_out);
      config->unlock();
      goto exitA;
   }

   /* Verify that common required UniRec items are in the input template */
   coll_tmpl = ur_create_template(DEF_REQUIRED_TMPL);
   if (coll_tmpl == NULL) {
      log(LOG_ERR, "ERROR: ur_create failed - internal error.");
      config->unlock();
      goto exitB;
   }

   if (!is_template_subset(tmpl_in, coll_tmpl)) {
      log(LOG_ERR, "ERROR: Generally required UniRec items (%s) are not "
         "in the input template.", DEF_REQUIRED_TMPL);
      ur_free_template(coll_tmpl);
      config->unlock();
      goto exitB;
   }
   ur_free_template(coll_tmpl);

   /* Verify that 'DIRECTION_FLAGS' item is present in the input template when
    * port-flowdir is deactivated */
   if (!config->get_cfg_val("port flowdirection", "port-flowdir") &&
      !ur_is_present(tmpl_in, dir_flag_id)) {
      log(LOG_ERR, "ERROR: Unirec item '%s' is missing in the input template.\n"
         "Hint: if you are using this module without flowdirection module "
         "change value 'port-flowdir' in the configuration file.",
         UR_FIELD_NAMES[dir_flag_id]);
      config->unlock();
      goto exitB;
   }

   /* Get configuration of all subprofiles */
   register_subprofiles();
   for (sp_list_ptr_iter it = subprofile_list.begin();
      it != subprofile_list.end(); ++it) {
      SubprofileBase *sbp_ptr = *it;
      std::string sp_name = "subprofile " + sbp_ptr->get_name();
      std::string param = "rules-" + sbp_ptr->get_name();
      if (config->get_cfg_val(sp_name, param)) {
         sbp_ptr->enable();
      } else {
         sbp_ptr->disable();
      }

      log(LOG_DEBUG, "Subprofile '%s' is '%s'.", sbp_ptr->get_name().c_str(),
         sbp_ptr->is_enabled() ? "enabled" : "disabled");

      if (!sbp_ptr->is_enabled()) {
         continue;
      }

      /* Active subprofile - check presence of required UniRec items
       * in the input template */
      ur_template_t *sbp_tmpl = ur_create_template(sbp_ptr->get_template().c_str());
      if (sbp_tmpl == NULL) {
         log(LOG_ERR, "ERROR: Creation of the subprofile '%s' UniRec "
            "template failed. Probably internal error in the subprofile "
            "template specification.", sbp_ptr->get_name().c_str());
         config->unlock();
         goto exitC;
      }

      /* Verify that subprofile's template is a subset of the input template */
      string missing_items;
      bool subset = is_template_subset(tmpl_in, sbp_tmpl, &missing_items);
      ur_free_template(sbp_tmpl);
      if (subset) {
         continue;
      }

      log(LOG_ERR, "ERROR: Missing UniRec item(s) '%s' in input template "
         "required by active subprofile '%s'. The subprofile's template is '%s'.",
         missing_items.c_str(), sbp_ptr->get_name().c_str(),
         sbp_ptr->get_template().c_str());
      config->unlock();
      goto exitC;
   }

   /* Configuration loaded */
   config->unlock();

   /* Create class for storing flow records */
   MainProfile = new HostProfile();

   /* Register termination signals */
   signal(SIGTERM, terminate_daemon);
   signal(SIGINT, terminate_daemon);

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

   if (send_eos) {
      char dummy[1] = {0};
      log(LOG_DEBUG, "Sending EOS message");
      trap_send(0, dummy, 1);
   }

   log(LOG_DEBUG, "Exiting... releasing memory");

   // Delete all records
   delete MainProfile;

exitC:
   unregister_subprofiles();

exitB:
   /* Free templates */
   ur_free_template(tmpl_in);
   ur_free_template(tmpl_out);

exitA:
   closelog();
   // Delete configuration
   Configuration::freeConfiguration();
   // Necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return 0;
}
