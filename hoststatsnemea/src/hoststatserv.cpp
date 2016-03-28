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
#include <fstream>
#include <iostream>
#include "hoststats.h"
#include "profile.h"
#include "aux_func.h"
#include "processdata.h"
#include "detectionrules.h"
#include <configurator.h>
#include <unistd.h>
#include <getopt.h>
//TRAP
extern "C" {
   #include <libtrap/trap.h>
   #include "fields.h"
}
using namespace std;

#define INI_DEFAULT_FILENAME  "hoststats.conf.default"
#define INI_FILENAME          "hoststats.conf"

////////////////////////////
// Global variables
int log_upto = LOG_ERR;    // Log up to level
ur_template_t *tmpl_in = NULL;
ur_template_t *tmpl_out = NULL;
string configFilePath = "";

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
         configFilePath = string(optarg);
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
 */
void init_detectors_configuration() {

   // Load general detector configuration.
   general_conf.syn_scan_threshold = confPlainGetFloat("syn-scan-threshold", 200);
   general_conf.syn_scan_syn_to_ack_ratio = confPlainGetFloat("syn-scan-syn-to-ack-ratio", 20);
   general_conf.syn_scan_request_to_response_ratio = confPlainGetFloat("syn-scan-request-to-response-ratio", 5);
   general_conf.syn_scan_ips = confPlainGetFloat("syn-scan-ips", 200);

   general_conf.dos_victim_connections_synflood = confPlainGetUint32("dos-victim-connections-synflood", 270000);
   general_conf.dos_victim_connections_others = confPlainGetUint32("dos-victim-connections-others", 1000000);
   general_conf.dos_victim_packet_ratio = confPlainGetFloat("dos-victim-packet-ratio", 2);

   general_conf.dos_attacker_connections_synflood = confPlainGetUint32("dos-attacker-connections-synflood", 270000);
   general_conf.dos_attacker_connections_others = confPlainGetUint32("dos-attacker-connections-others", 1000000);
   general_conf.dos_attacker_packet_ratio = confPlainGetFloat("dos-attacker-packet-ratio", 2);

   general_conf.dos_req_rsp_est_ratio = confPlainGetFloat("dos-req-rsp-est-ratio", 0.8);
   general_conf.dos_rsp_req_est_ratio = confPlainGetFloat("dos-rsp-req-est-ratio", 0.2);

   general_conf.dos_min_rsp_ratio = confPlainGetFloat("dos-min-rsp-ratio", 0.02);

   // Load ssh detector configuration.
   ssh_conf.scan_threshold = confPlainGetFloat("scan-threshold", 100);
   ssh_conf.scan_flag_ratio = confPlainGetFloat("scan-flag-ratio", 5);
   ssh_conf.scan_packet_ratio = confPlainGetFloat("scan-packet-ratio", 5);
   ssh_conf.scan_ip_ratio = confPlainGetFloat("scan-ip-ratio", 0.5);

   ssh_conf.bruteforce_out_threshold = confPlainGetFloat("bruteforce-out-threshold", 10);
   ssh_conf.bruteforce_ips = confPlainGetFloat("bruteforce-ips", 5);
   ssh_conf.bruteforce_ips_ratio = confPlainGetFloat("bruteforce-ips-ratio", 20);
   ssh_conf.bruteforce_req_threshold = confPlainGetFloat("bruteforce-req-threshold", 60);
   ssh_conf.bruteforce_req_min_packet_ratio = confPlainGetFloat("bruteforce-req-min-packet-ratio", 5);
   ssh_conf.bruteforce_req_max_packet_ratio = confPlainGetFloat("bruteforce-req-max-packet-ratio", 20);
   ssh_conf.bruteforce_data_threshold = confPlainGetFloat("bruteforce-data-threshold", 30);
   ssh_conf.bruteforce_data_min_packet_ratio = confPlainGetFloat("bruteforce-data-min-packet-ratio", 10);
   ssh_conf.bruteforce_data_max_packet_ratio = confPlainGetFloat("bruteforce-data-max-packet-ratio", 25);
   ssh_conf.bruteforce_server_ratio = confPlainGetFloat("bruteforce-server-ratio", 3);

   // Load dns detector configuration.
   dns_conf.dns_amplif_threshold = confPlainGetFloat("dns-amplif-threshold", 10000);
}

/**
 * \brief Copy file.
 * \param [in] from Input file.
 * \param [int] to Output file.
 * \return True on success, false otherwise.
 */
bool copy_file(const char *from, const char *to)
{
   ifstream src(from);
   if (!src.good()) {
      src.close();
      return false;
   }
   ofstream dst(to);
   if (!dst.good()) {
      src.close();
      dst.close();
      return false;
   }
   dst << src.rdbuf();
   if (!dst.good()) {
      src.close();
      dst.close();
      return false;
   }
   src.close();
   dst.close();
   return true;
}

/**
 * \brief Find configuration file.
 * \return 0 on success, 1 otherwise.
 */
int set_configuration_filepath()
{
   ifstream file;
   // Load configuration from a path defined by Nemea directory
   configFilePath = SYSCONFDIR "/" INI_FILENAME;
   file.open(configFilePath.c_str(), ios_base::in);
   if (file.good()) {
      file.close();
      return 0;
   }

   // Load configuration from a file in the same directory as the binary file
   configFilePath = INI_FILENAME;
   file.open(configFilePath.c_str(), ios_base::in);
   if (file.good()) {
      file.close();
      return 0;
   }

   // Config file is not in current directory nor in Nemea directory, copy default config.
   log(LOG_NOTICE, INI_FILENAME " file not found, trying to load " INI_DEFAULT_FILENAME);

   // copy INI_DEFAULT_FILENAME to INI_FILENAME
   if (copy_file(SYSCONFDIR "/" INI_DEFAULT_FILENAME, SYSCONFDIR "/" INI_FILENAME)) {
      log(LOG_NOTICE, INI_DEFAULT_FILENAME " copied to " INI_FILENAME);
      configFilePath = SYSCONFDIR "/" INI_FILENAME;
   } else if (copy_file(INI_DEFAULT_FILENAME, INI_FILENAME)){
      log(LOG_NOTICE, INI_DEFAULT_FILENAME " copied to " INI_FILENAME);
      configFilePath = INI_FILENAME;
   } else {
      log(LOG_NOTICE, "Can't copy " INI_DEFAULT_FILENAME " to " INI_FILENAME
         ", using default file directly.");
      configFilePath = SYSCONFDIR "/" INI_DEFAULT_FILENAME;
   }

   file.open(configFilePath.c_str(), ios_base::in);
   if (file.good()) {
      file.close();
      return 0;
   }

   cerr << "Could not load configuration" << endl;
   log(LOG_ERR, "Could not load configuration");
   return 1;
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

   // Initialize configurator.
   if (confPlainCreateContext()) {
      fprintf(stderr, "ERROR: Configurator initialization failed.\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   if (confPlainAddElement("table-size", "uint32_t", "65536", 0, 0) ||
      confPlainAddElement("det-start-time", "uint32_t", "10", 0, 0) ||
      confPlainAddElement("timeout-active", "uint32_t", "300", 0, 0) ||
      confPlainAddElement("timeout-inactive", "uint32_t", "30", 0, 0) ||
      confPlainAddElement("rules-generic", "bool", "false", 0, 0) ||
      confPlainAddElement("rules-ssh", "bool", "false", 0, 0) ||
      confPlainAddElement("rules-dns", "bool", "false", 0, 0) ||
      confPlainAddElement("port-flowdir", "bool", "false", 0, 0) ||
      confPlainAddElement("input-template", "string", "", 512, 0) ||
      confPlainAddElement("detection-log", "string", "", 512, 0) ||
      confPlainAddElement("log-upto-level", "string", "", 32, 0) ||
      confPlainAddElement("syn-scan-threshold", "float", "200", 0, 0) ||
      confPlainAddElement("syn-scan-syn-to-ack-ratio", "float", "20", 0, 0) ||
      confPlainAddElement("syn-scan-request-to-response-ratio", "float", "5", 0, 0) ||
      confPlainAddElement("syn-scan-ips", "float", "200", 0, 0) ||
      confPlainAddElement("dos-victim-connections-synflood", "uint32_t", "270000", 0, 0) ||
      confPlainAddElement("dos-victim-connections-others", "uint32_t", "1000000", 0, 0) ||
      confPlainAddElement("dos-victim-packet-ratio", "float", "2", 0, 0) ||
      confPlainAddElement("dos-attacker-connections-synflood", "uint32_t", "270000", 0, 0) ||
      confPlainAddElement("dos-attacker-connections-others", "uint32_t", "1000000", 0, 0) ||
      confPlainAddElement("dos-attacker-packet-ratio", "float", "2", 0, 0) ||
      confPlainAddElement("dos-req-rsp-est-ratio", "float", "0.8", 0, 0) ||
      confPlainAddElement("dos-rsp-req-est-ratio", "float", "0.2", 0, 0) ||
      confPlainAddElement("dos-min-rsp-ratio", "float", "0.02", 0, 0) ||
      confPlainAddElement("scan-threshold", "float", "100", 0, 0) ||
      confPlainAddElement("scan-flag-ratio", "float", "5", 0, 0) ||
      confPlainAddElement("scan-packet-ratio", "float", "5", 0, 0) ||
      confPlainAddElement("scan-ip-ratio", "float", "0.5", 0, 0) ||
      confPlainAddElement("bruteforce-out-threshold", "float", "10", 0, 0) ||
      confPlainAddElement("bruteforce-ips", "float", "5", 0, 0) ||
      confPlainAddElement("bruteforce-ips-ratio", "float", "20", 0, 0) ||
      confPlainAddElement("bruteforce-req-threshold", "float", "60", 0, 0) ||
      confPlainAddElement("bruteforce-req-min-packet-ratio", "float", "5", 0, 0) ||
      confPlainAddElement("bruteforce-req-max-packet-ratio", "float", "20", 0, 0) ||
      confPlainAddElement("bruteforce-data-threshold", "float", "30", 0, 0) ||
      confPlainAddElement("bruteforce-data-min-packet-ratio", "float", "10", 0, 0) ||
      confPlainAddElement("bruteforce-data-max-packet-ratio", "float", "25", 0, 0) ||
      confPlainAddElement("bruteforce-server-ratio", "float", "3", 0, 0) ||
      confPlainAddElement("dns-amplif-threshold", "float", "10000", 0, 0)) {

      fprintf(stderr, "ERROR: Configurator initialization failed.\n");
      confPlainClearContext();
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }

   openlog(NULL, LOG_NDELAY, 0);
   log(LOG_INFO, "HostStatsNemea started");

   /* Set configuration path if user config-path was not specified. */
   if (configFilePath == "") {
      if (set_configuration_filepath()) {
         fprintf(stderr, "ERROR: Failed to open configuration file \"%s\"\n", configFilePath.c_str());
         log(LOG_ERR, "ERROR: Failed to open configuration file \"%s\"", configFilePath.c_str());
         closelog();
         confPlainClearContext();
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      }
   }

   /* Load module configuration from the config file */
   if (confPlainLoadConfiguration(configFilePath.c_str(), NULL)) {
      fprintf(stderr, "ERROR: Failed to open configuration file \"%s\"\n", configFilePath.c_str());
      log(LOG_ERR, "ERROR: Failed to open configuration file \"%s\"", configFilePath.c_str());
      closelog();
      confPlainClearContext();
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
   }


   /* Set logmask if used */
   string logmask = trim(string(confPlainGetString("log-upto-level", "")));
   if (!logmask.empty()) {
      parse_logmask(logmask);
   }

   /* Some variables initialization because of goto */
   ur_field_id_t dir_flag_id = F_DIRECTION_FLAGS;
   ur_template_t *coll_tmpl = NULL;

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
      goto exitA;
   }

   /* Verify that 'DIRECTION_FLAGS' item is present in the input template when
    * port-flowdir is deactivated */
   if (!confPlainGetBool("port-flowdir", 0) &&
      !ur_is_present(tmpl_in, dir_flag_id)) {
      log(LOG_ERR, "ERROR: Unirec item '%s' is missing in the input template.\n"
         "Hint: if you are using this module without flowdirection module "
         "change value 'port-flowdir' in the configuration file.",
         ur_get_name(dir_flag_id));
      goto exitB;
   }

   /* Get configuration of all subprofiles */
   register_subprofiles();
   for (sp_list_ptr_iter it = subprofile_list.begin();
      it != subprofile_list.end(); ++it) {
      SubprofileBase *sbp_ptr = *it;
      std::string sp_name = "subprofile " + sbp_ptr->get_name();
      std::string param = "rules-" + sbp_ptr->get_name();
      if (confPlainGetBool(param.c_str(), 0)) {
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
      goto exitC;
   }

   /* Init detectors configuration. */
   init_detectors_configuration();

   /* Configuration loaded */

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
   // Clear configuration.
   confPlainClearContext();
   // Necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return 0;
}
