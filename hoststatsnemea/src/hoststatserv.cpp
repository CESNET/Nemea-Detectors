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
#include "detectionrules.h"
#include "hs_config.h"
#include <unistd.h>
#include <getopt.h>
//TRAP
extern "C" {
   #include <libtrap/trap.h>
   #include "fields.h"
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
#define DEF_REQUIRED_TMPL "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD"  // required input UniRec items

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint32 EVENT_SCALE,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 EVENT_TYPE,
   uint8 PROTOCOL,
   uint8 DIRECTION_FLAGS,
   string NOTE
)

///////////////////////////////////////////////////
// Struct with information about Nemea module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("hoststatsnemea","This module calculates statistics for IP addresses and subprofiles (SSH,DNS,...)",1,1)

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
   signed char opt;

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
   ur_field_id_t ur_set_id = UR_ITER_BEGIN;

   /* Iterate over all required UniRec items */
   while ((ur_set_id = ur_iter_fields(subs_tmpl, ur_set_id))
      != UR_ITER_END) {
      if (ur_is_present(main_tmpl, ur_set_id)) {
         continue;
      }

      subset = false;
      if (!items.empty()) {
         items += ",";
      }
      items += ur_get_name(ur_set_id);
   }

   /* Result check */
   if (!subset && missing_items != NULL) {
      *missing_items = items;
   }
   return subset;
}

/**
 * \brief Initializes detectors configuration.
 * \param [out] error Contains parameter name if an error occur.
 * \return True on success, false when invalid configuration value is found.
 */
void init_detectors_configuration() {

   Configuration *config = Configuration::getInstance();

   // Load general detector configuration.
   general_conf.syn_scan_threshold = config->get_cfg_val("syn-scan-threshold", "syn-scan-threshold", 200);
   general_conf.syn_scan_syn_to_ack_ratio = config->get_cfg_val("syn-scan-syn-to-ack-ratio", "syn-scan-syn-to-ack-ratio", 20);
   general_conf.syn_scan_request_to_response_ratio = config->get_cfg_val("syn-scan-request-to-response-ratio", "syn-scan-request-to-response-ratio", 5);
   general_conf.syn_scan_ips = config->get_cfg_val("syn-scan-ips", "syn-scan-ips", 200);

   general_conf.dos_detection_type = config->get_cfg_val("dos-detection-type", "dos-detection-type", 0);
   general_conf.dos_victim_connections_synflood = config->get_cfg_val("dos-victim-connections-synflood", "dos-victim-connections-synflood", 270000, 0);
   general_conf.dos_victim_connections_others = config->get_cfg_val("dos-victim-connections-others", "dos-victim-connections-others", 1000000, 0);
   general_conf.dos_victim_packet_ratio = config->get_cfg_val("dos-victim-packet-ratio", "dos-victim-packet-ratio", 2);
   general_conf.dos_victim_bytes_packets_ratio = config->get_cfg_val("dos-victim-bytes-packets-ratio", "dos-victim-bytes-packets-ratio", 100);
   general_conf.dos_victim_responsibility = config->get_cfg_val("dos-victim-responsibility", "dos-victim-responsibility", 0.8);

   general_conf.dos_attacker_connections_synflood = config->get_cfg_val("dos-attacker-connections-synflood", "dos-attacker-connections-synflood", 270000, 0);
   general_conf.dos_attacker_connections_others = config->get_cfg_val("dos-attacker-connections-others", "dos-attacker-connections-others", 1000000, 0);
   general_conf.dos_attacker_packet_ratio = config->get_cfg_val("dos-attacker-packet-ratio", "dos-attacker-packet-ratio", 2);
   general_conf.dos_attacker_bytes_packets_ratio = config->get_cfg_val("dos-attacker-bytes-packets-ratio", "dos-attacker-bytes-packets-ratio", 100);

   general_conf.dos_req_rsp_est_ratio = config->get_cfg_val("dos-req-rsp-est-ratio", "dos-req-rsp-est-ratio", 0.8);
   general_conf.dos_rsp_req_est_ratio = config->get_cfg_val("dos-rsp-req-est-ratio", "dos-rsp-req-est-ratio", 0.2);

   general_conf.dos_min_rsp_ratio = config->get_cfg_val("dos-min-rsp-ratio", "dos-min-rsp-ratio", 0.02);

   // Load ssh detector configuration.
   ssh_conf.scan_threshold = config->get_cfg_val("scan-threshold", "scan-threshold", 100);
   ssh_conf.scan_flag_ratio = config->get_cfg_val("scan-flag-ratio", "scan-flag-ratio", 5);
   ssh_conf.scan_packet_ratio = config->get_cfg_val("scan-packet-ratio", "scan-packet-ratio", 5);
   ssh_conf.scan_ip_ratio = config->get_cfg_val("scan-ip-ratio", "scan-ip-ratio", 0.5);

   ssh_conf.bruteforce_out_threshold = config->get_cfg_val("bruteforce-out-threshold", "bruteforce-out-threshold", 10);
   ssh_conf.bruteforce_ips = config->get_cfg_val("bruteforce-ips", "bruteforce-ips", 5);
   ssh_conf.bruteforce_ips_ratio = config->get_cfg_val("bruteforce-ips-ratio", "bruteforce-ips-ratio", 20);
   ssh_conf.bruteforce_req_threshold = config->get_cfg_val("bruteforce-req-threshold", "bruteforce-req-threshold", 60);
   ssh_conf.bruteforce_req_min_packet_ratio = config->get_cfg_val("bruteforce-req-min-packet-ratio", "bruteforce-req-min-packet-ratio", 5);
   ssh_conf.bruteforce_req_max_packet_ratio = config->get_cfg_val("bruteforce-req-max-packet-ratio", "bruteforce-req-max-packet-ratio", 20);
   ssh_conf.bruteforce_data_threshold = config->get_cfg_val("bruteforce-data-threshold", "bruteforce-data-threshold", 30);
   ssh_conf.bruteforce_data_min_packet_ratio = config->get_cfg_val("bruteforce-data-min-packet-ratio", "bruteforce-data-min-packet-ratio", 10);
   ssh_conf.bruteforce_data_max_packet_ratio = config->get_cfg_val("bruteforce-data-max-packet-ratio", "bruteforce-data-max-packet-ratio", 25);
   ssh_conf.bruteforce_server_ratio = config->get_cfg_val("bruteforce-server-ratio", "bruteforce-server-ratio", 3);

   // Load dns detector configuration.
   dns_conf.dns_amplif_threshold = config->get_cfg_val("dns-amplif-threshold", "dns-amplif-threshold", 10000);
}

/**
 * \brief Main function
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
   ur_field_id_t dir_flag_id = F_DIRECTION_FLAGS;

   tmpl_in = ur_create_input_template(0, DEF_REQUIRED_TMPL, NULL);
   tmpl_out = ur_create_output_template(0, "EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,"
      "DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE,NOTE", NULL);

   if (tmpl_in == NULL || tmpl_out == NULL) {
      if (tmpl_in == NULL) {
         log(LOG_ERR, "ERROR: Failed to create input UniRec template.");
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

   /* Verify that 'DIRECTION_FLAGS' item is present in the input template when
    * port-flowdir is deactivated */
   if (!config->get_cfg_val("port flowdirection", "port-flowdir") &&
      !ur_is_present(tmpl_in, dir_flag_id)) {
      log(LOG_ERR, "ERROR: Unirec item '%s' is missing in the input template.\n"
         "Hint: if you are using this module without flowdirection module "
         "change value 'port-flowdir' in the configuration file.",
         ur_get_name(dir_flag_id));
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
      ur_template_t *sbp_tmpl = ur_create_template(sbp_ptr->get_template().c_str(), NULL);
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


   /* Init detectors configuration. */
   init_detectors_configuration();

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
