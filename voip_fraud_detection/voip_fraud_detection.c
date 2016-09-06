/**
 * \file voip_fraud_detection.c
 * \brief VoIP fraud detection module - main
 * \author Lukas Truxa <truxaluk@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 CESNET
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

#include "voip_fraud_detection.h"
#include "fields.h"

UR_FIELDS (
   uint16 SIP_MSG_TYPE,
   uint16 SIP_STATUS_CODE,
   string SIP_REQUEST_URI,
   string SIP_CALLING_PARTY,
   string SIP_CALLED_PARTY,
   string SIP_CALL_ID,
   string SIP_USER_AGENT,
   string SIP_CSEQ,
   ipaddr SRC_IP,
   ipaddr DST_IP,
   time TIME_FIRST,
   uint64 LINK_BIT_FIELD,
   string VOIP_FRAUD_USER_AGENT,
   uint16 VOIP_FRAUD_PREFIX_LENGTH,
   uint32 VOIP_FRAUD_SUCCESSFUL_CALL_COUNT,
   uint32 VOIP_FRAUD_INVITE_COUNT,
   uint32 VOIP_FRAUD_PREFIX_EXAMINATION_COUNT,
   string VOIP_FRAUD_SIP_TO,
   string VOIP_FRAUD_SIP_FROM,
   string VOIP_FRAUD_COUNTRY_CODE,
   uint32 EVENT_ID,
   uint8 EVENT_TYPE,
   time DETECTION_TIME,
   uint64 INVITE_CNT
   uint64 CALLER_CNT
   uint64 CALLEE_CNT
)

/** \brief Struct with information about module. */
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("voip_fraud_detection module","This module detecting fraud in VoIP telephony - in SIP communication.",1,-1)

#define MODULE_PARAMS(PARAM) \
  PARAM('l', "log_file", "Path to a log file.", required_argument, "string") \
  PARAM('e', "event_id_file", "Event_ID file. (it can be 'disabled')", required_argument, "string") \
  PARAM('c', "countries_file", "Countries file. (it can be 'disabled')", required_argument, "string") \
  PARAM('m', "max_prefix_length", "Maximum prefix length.", required_argument, "uint32") \
  PARAM('d', "min_number_length", "Minimum length of called number.", required_argument, "uint32") \
  PARAM('s', "detection_interval", "Detection interval in seconds", required_argument, "uint32") \
  PARAM('t', "prefix_exam_limit", "Prefix examination detection threshold.", required_argument, "uint32") \
  PARAM('o', "countries_detection_mode", "Disable detection of calling to different country.", no_argument, "none") \
  PARAM('a', "learn_countries_period", "Set learning mode for detection of calling to different country for defined period in seconds.", required_argument, "uint32") \
  PARAM('w', "disable_country_save", "Disable saving new country after calling to different country (every new calling will be reported repeatedly).", no_argument, "none") \
  PARAM('p', "pause", "Detection pause after attack in seconds.", required_argument, "uint32") \
  PARAM('q', "max_item_prefix_tree", "Limit of maximum item in prefix tree for one IP address.", required_argument, "uint32") \
  PARAM('x', "clear_time", "Time in seconds after it will be clear data without communication.", required_argument, "uint32") \
  PARAM('n', "prefix_stat_file", "Path to prefix examination statistic file.", required_argument, "string")

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/** \brief Definition of modul_configuration (modul_configuration_struct). */
modul_configuration_t modul_configuration;

/** \brief Definition of detection_statistic (detection_prefix_examination_struct). */
detection_prefix_examination_t detection_prefix_examination;

/** \brief Definition of global_module_statistic (global_module_statistic_struct). */
global_module_statistic_t global_module_statistic;

#ifdef DEBUG
/** \brief Definition of global_sip_statistic (global_sip_statistic_struct). */
global_sip_statistic_t global_sip_statistic;
#endif

/** \brief Last used Event ID of attack detection. */
uint32_t last_event_id;

/** \brief UniRec input template. */
ur_template_t *ur_template_in;

/** \brief UniRec output template. */
ur_template_t *ur_template_out;

/** \brief Pointer to received data from trap_recv(). */
const void *in_rec;

/** \brief Detection record for sending detection events to output interface. */
void *detection_record;

/** \brief Indication of stopping of module. */
int stop = 0;

// Check and free memory, that wasn't used for long time or exceeds limit of items (memory management of module)
void check_and_free_module_memory(cc_hash_table_v2_t * hash_table)
{
   static ur_time_t time_last_check = 0;

   int i;
   ip_item_t * hash_table_item;

   // check if check memory interval was expired
   if ((current_time - time_last_check) > CHECK_MEMORY_INTERVAL) {
      // printf("Checking memory: %"PRIu64", %"PRIu64", %"PRIu64"\n", current_time, time_last_check, current_time - time_last_check);
      // iterate over items in hash table
      for (i = 0; i < hash_table->table_size; i++) {

         // check if item in hash table is valid
         if (hash_table->ind[i].valid) {

            // get item from hash_table
            hash_table_item = *(ip_item_t **) hash_table->data[hash_table->ind[i].index];

            // check for no SIP communication for defined time
            if ((current_time - hash_table_item->time_last_communication) > modul_configuration.clear_data_no_communication_after) {
               // free additional memory
               hash_table_item_free_inner_memory(hash_table_item);

               // remove item from hash table
               ht_remove_by_key_v2(hash_table, (char *) hash_table->keys[hash_table->ind[i].index]);

               // actual hash table item was removed, continue with next item
               continue;
            }

            // check if prefix_tree has more than max_item_prefix_tree items
            if ((hash_table_item->tree->root->count_of_string > modul_configuration.max_item_prefix_tree)) {
               // destroy prefix_tree
               prefix_tree_destroy(hash_table_item->tree);

               // initialize new prefix_tree
               hash_table_item->tree = prefix_tree_initialize(SUFFIX, 0, -1, DOMAIN_EXTENSION_NO, RELAXATION_AFTER_DELETE_YES);

               // check successful allocation memory
               if (hash_table_item->tree == NULL) {
                  PRINT_ERR("hash_table_item->renew_tree, prefix_tree_initialize: Error memory allocation\n");
               }

               // reset first_invite_request
               hash_table_item->first_invite_request = (ur_time_t) 0;

            }

         }
      }

      // save time of last check of module memory
      time_last_check = current_time;
   }
}

// Load Event ID counter from defined file

void event_id_load(char * file)
{
   last_event_id = 0;

   if (file != NULL) {
      FILE * io_event_id_file;

      // open event_id file (read, text mode)
      io_event_id_file = fopen(file, "rt");
      if (io_event_id_file == NULL) {
         PRINT_OUT_LOG("Warning: Can't open event_id file: \"", file, "\"! => last_event_id=0\n");
         return;
      }

      // read last_event_id
      if (fscanf(io_event_id_file, "%u", &last_event_id) != 1) {
         PRINT_OUT_LOG("Warning: Can't load event_id from file: \"", file, "\"! => last_event_id=0\n");
      }

      // close event_id file
      fclose(io_event_id_file);
   }
}

// Save Event ID counter to defined file

void event_id_save(char * file)
{
   if (file != NULL) {
      FILE * io_event_id_file;

      // open event_id file (write, text mode)
      io_event_id_file = fopen(file, "wt");
      if (io_event_id_file == NULL) {
         PRINT_ERR("Error open event_id file for writing: \"", file, "\"\n");
         return;
      }

      // write last_event_id to file
      fprintf(io_event_id_file, "%u\n", last_event_id);

      // close event_id file
      fclose(io_event_id_file);
   }
}

// Find if Call-ID exists in node_data
// Return 1 if Call-ID exists, 0 otherwise

int call_id_node_data_exists(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len)
{
   int i;
   int end_index = MAX_CALL_ID_STORAGE_SIZE;

   // if storage of Call-ID isn't full, set correct end index
   if (((node_data_t *) (prefix_tree_node->parent->value))->call_id_full == 0) {
      end_index = ((node_data_t *) (prefix_tree_node->parent->value))->call_id_insert_position;
   }

   uint32_t call_id_hash;

   for (i = 0; i < end_index; i++) {

      // calculation hash of call_id
      call_id_hash = SuperFastHash(call_id, sizeof (char) * call_id_len);

      // check if input call_id_hash is the same as node_data->call_id_hash[i]
      if (((node_data_t *) (prefix_tree_node->parent->value))->call_id_hash[i] == call_id_hash) {
         // Call-ID found
         return 1;
      }
   }
   return 0;
}

// Save Call-ID to node_data

void call_id_node_data_save(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len)
{
   // check if Call-ID doesn't exist in node data
   if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 0) {
      unsigned int call_id_insert_position = call_id_insert_position = ((node_data_t *) (prefix_tree_node->parent->value))->call_id_insert_position;

      // calculation hash of call_id
      uint32_t call_id_hash = SuperFastHash(call_id, sizeof (char) * call_id_len);

      // save hash to Call-ID storage
      ((node_data_t *) (prefix_tree_node->parent->value))->call_id_hash[call_id_insert_position] = call_id_hash;

      // increment insert position of Call-ID storage
      ((node_data_t *) (prefix_tree_node->parent->value))->call_id_insert_position += 1;
      if (((node_data_t *) (prefix_tree_node->parent->value))->call_id_insert_position >= MAX_CALL_ID_STORAGE_SIZE) {
         ((node_data_t *) (prefix_tree_node->parent->value))->call_id_insert_position = 0;
         ((node_data_t *) (prefix_tree_node->parent->value))->call_id_full = 1;
      }

   }
}

// Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' or '?' + string after it

int cut_sip_identifier(char ** output_str, char * input_str, int * str_len)
{
   if ((*str_len >= 4) && (strncmp(input_str, "sip:", 4) == 0)) {

      // input string beginning with "sip:"

      *output_str = input_str + 4 * sizeof (char);
      *str_len -= 4;

   } else {
      if ((*str_len >= 5) && (strncmp(input_str, "sips:", 5) == 0)) {

         // input string beginning with "sips:"

         *output_str = input_str + 5 * sizeof (char);
         *str_len -= 5;

      } else {
         return -1;
      }

   }

   // ignore ';' or '?' + string after it
   int i = 0;
   while (i < *str_len) {
      if (((*output_str)[i] == ';') || ((*output_str)[i] == '?')) {
         *str_len = i;
         break;
      }
      i++;
   }

   // set terminating null character
   (*output_str)[*str_len] = '\0';

   return 0;
}


// Check if input string is numeric with allowed special char ('+','*','#','-',':') or this text part before '@'
// + check of minimum numeric length

int is_numeric_participant(char * str, int str_len)
{
   int char_index;
   int is_numeric = 0;

   for (char_index = 0; char_index < str_len; char_index++) {

      // stop checking input string
      if (str[char_index] == '@') break;

      // ignore chars '+', '*', '#', '-', ':'
      if (str[char_index] == '+' || str[char_index] == '*' || str[char_index] == '#' \
              || str[char_index] == '-' || str[char_index] == ':') continue;

      // check if actual char is digit or not
      if (isdigit(str[char_index]) != 0) {
         is_numeric = 1;
      } else {
         return 0;
      }
   }

   // check of minimum length of called number
   if (char_index < modul_configuration.min_length_called_number) return 0;

   return is_numeric;
}

// Copy char array field from UniRec to defined string_output, update string_len and add terminating '\0' at the end of char array

void get_string_from_unirec(char * string_output, int * string_len, int unirec_field_id, int max_length)
{
   char * ur_string;
   *string_len = ur_get_var_len(ur_template_in, in_rec, unirec_field_id);
   ur_string = ur_get_ptr_by_id(ur_template_in, in_rec, unirec_field_id);
   if (*string_len > max_length) *string_len = max_length;
   memcpy(string_output, ur_string, sizeof (char) * (*string_len));
   string_output[*string_len] = '\0';
}

// Main

int main(int argc, char **argv)
{
   int ret;
   time_t time_last_stats = 0;
   uint64_t callee_count = 0, caller_count = 0;
   // ***** TRAP initialization *****

   // Let TRAP library parse command-line arguments and extract its parameters
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();


   // ***** Set default parameters of modul configuration *****

#ifdef ENABLE_GEOIP
   modul_configuration.countries_detection_mode = COUNTRIES_LEARNING_MODE;
   modul_configuration.learning_countries_period = DEFAULT_LEARNING_COUNTRIES_PERIOD;
   modul_configuration.countries_file = DEFAULT_COUNTRIES_FILE;
   modul_configuration.allowed_countries = NULL;
   modul_configuration.allowed_countries_count = 0;
   modul_configuration.disable_saving_new_country = 0;
#endif
   modul_configuration.min_length_called_number = DEFAULT_MIN_LENGTH_CALLED_NUMBER;
   modul_configuration.max_prefix_length = DEFAULT_MAX_PREFIX_LENGTH;
   modul_configuration.prefix_examination_detection_threshold = DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD;
   modul_configuration.detection_interval = DEFAULT_DETECTION_INTERVAL;
   modul_configuration.detection_pause_after_attack = DEFAULT_DETECTION_PAUSE_AFTER_ATTACK;
   modul_configuration.max_item_prefix_tree = DEFAULT_MAX_ITEM_PREFIX_TREE;
   modul_configuration.clear_data_no_communication_after = DEFAULT_CLEAR_DATA_NO_COMMUNICATION_AFTER;
   modul_configuration.event_id_file = DEFAULT_EVENT_ID_FILE;
   modul_configuration.log_file = NULL;
   modul_configuration.prefix_statistic_file = NULL;


   // ***** Parse remaining parameters and get configuration *****

   char opt;

   while ((opt = getopt(argc, argv, module_getopt_string)) != -1) {
      switch (opt) {
         case 'l':
            modul_configuration.log_file = optarg;
            break;
         case 'n':
            modul_configuration.prefix_statistic_file = optarg;
            break;
         case 'e':
            if (strcmp(optarg, "disabled") == 0) {
               modul_configuration.event_id_file = NULL;
            } else {
               modul_configuration.event_id_file = optarg;
            }
            break;
#ifdef ENABLE_GEOIP
         case 'c':
            if (strcmp(optarg, "disabled") == 0) {
               modul_configuration.countries_file = NULL;
            } else {
               modul_configuration.countries_file = optarg;
            }
            break;
         case 'a':
            modul_configuration.learning_countries_period = atoi(optarg);
            break;
         case 'w':
            modul_configuration.disable_saving_new_country = 1;
            break;
         case 'o':
            modul_configuration.countries_detection_mode = COUNTRIES_DETECTION_MODE_OFF;
            break;
#else
         case 'c':
         case 'a':
         case 'w':
         case 'o':
            PRINT_ERR("You must install GeoIP before you can use detection of calling to different countries!\n");
            break;
#endif
         case 'd':
            modul_configuration.min_length_called_number = atoi(optarg);
            break;
         case 'm':
            modul_configuration.max_prefix_length = atoi(optarg);
            break;
         case 's':
            modul_configuration.detection_interval = atoi(optarg);
            break;
         case 'p':
            modul_configuration.detection_pause_after_attack = atoi(optarg);
            break;
         case 't':
            modul_configuration.prefix_examination_detection_threshold = atoi(optarg);
            break;
         case 'q':
            modul_configuration.max_item_prefix_tree = atoi(optarg);
            break;
         case 'x':
            modul_configuration.clear_data_no_communication_after = atoi(optarg);
            break;
         default:
            PRINT_ERR("Error: Invalid arguments\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 1;
      }
   }


   // ***** Set correct mode of countries detection and set alarm *****

#ifdef ENABLE_GEOIP
   if (modul_configuration.countries_detection_mode == COUNTRIES_LEARNING_MODE) {
      if (modul_configuration.learning_countries_period == 0) {
         modul_configuration.countries_detection_mode = COUNTRIES_DETECTION_MODE_ON;
      } else {
         // set signal for power off detection after defined learning period
         signal(SIGALRM, countries_power_off_learning_mode);
         alarm(modul_configuration.learning_countries_period);
      }
   }
#endif


   // ***** Print module configuration *****

   PRINT_OUT_LOG("-----------------------------------------------------\n");
   PRINT_OUT_LOG("Start VoIP fraud detection module (version:", MODULE_VERSION, ") ...\n");
   PRINT_OUT_LOG("   Module configuration:\n");

#ifdef ENABLE_GEOIP
   switch (modul_configuration.countries_detection_mode) {
      case COUNTRIES_LEARNING_MODE:
      {
         PRINT_OUT_LOG("    - countries detection=LEARNING_MODE; detection will be started in learning_countries_period=", uint_to_str(modul_configuration.learning_countries_period), "\n");
         break;
      }
      case COUNTRIES_DETECTION_MODE_ON:
      {
         PRINT_OUT_LOG("    - countries detection=ON\n");
         break;
      }
      case COUNTRIES_DETECTION_MODE_OFF:
      {
         PRINT_OUT_LOG("    - countries detection=OFF\n");
         break;
      }
      default:
         PRINT_ERR("Undefined detection mode!\n");
         break;
   }
   if (modul_configuration.disable_saving_new_country == 1) {
      PRINT_OUT_LOG("    - disabled saving new country after calling to different country (every new calling will be reported repeatedly)\n");
   }
#endif

   PRINT_OUT_LOG("    - max_prefix_length=", uint_to_str(modul_configuration.max_prefix_length), "\n");
   PRINT_OUT_LOG("    - min_length_called_number=", uint_to_str(modul_configuration.min_length_called_number), "\n");
   PRINT_OUT_LOG("    - prefix_examination_detection_threshold=", uint_to_str(modul_configuration.prefix_examination_detection_threshold), "\n");
   PRINT_OUT_LOG("    - detection_interval=", uint_to_str(modul_configuration.detection_interval), "\n");
   PRINT_OUT_LOG("    - detection_pause_after_attack=", uint_to_str(modul_configuration.detection_pause_after_attack), "\n");
   PRINT_OUT_LOG("    - max_item_prefix_tree=", uint_to_str(modul_configuration.max_item_prefix_tree), "\n");
   PRINT_OUT_LOG("    - clear_data_no_communication_after=", uint_to_str(modul_configuration.clear_data_no_communication_after), "\n");

#ifdef ENABLE_GEOIP
   // print countries file settings
   PRINT_OUT_LOG("    - countries file=");
   if (modul_configuration.countries_file == NULL) {
      PRINT_OUT_LOG_NOTDATETIME("disabled\n");
   } else {
      PRINT_OUT_LOG_NOTDATETIME("\"", modul_configuration.countries_file, "\"\n");
   }
#endif

   // print event_id file settings
   PRINT_OUT_LOG("    - event_id file=");
   if (modul_configuration.event_id_file == NULL) {
      PRINT_OUT_LOG_NOTDATETIME("disabled\n");
   } else {
      PRINT_OUT_LOG_NOTDATETIME("\"", modul_configuration.event_id_file, "\"\n");
   }

   // print log filename (if is set)
   if (modul_configuration.log_file != NULL) {
      PRINT_OUT_LOG("    - log file:\"", modul_configuration.log_file, "\"\n");
   }

   // print prefix statistic filename (if is set)
   if (modul_configuration.prefix_statistic_file != NULL) {
      PRINT_OUT_LOG("    - prefix statistic file:\"", modul_configuration.prefix_statistic_file, "\"\n");
   }
   PRINT_OUT_LOG("-----------------------------------------------------\n");


   // ***** Create UniRec templates *****

   ur_template_in = ur_create_input_template(0, UNIREC_INPUT_TEMPLATE, NULL);
   ur_template_out = ur_create_output_template(0, UNIREC_OUTPUT_TEMPLATE, NULL);

   // check of template creation
   if (ur_template_in == NULL || ur_template_out == NULL) {
      PRINT_ERR("Error: Invalid UniRec specifier!\n");
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return RETURN_ERROR;
   }

   // prepare detection record
   detection_record = ur_create_record(ur_template_out, UR_MAX_SIZE);

   // check of detection record
   if (detection_record == NULL) {
      PRINT_ERR("Error: No memory available for detection record!\n");
   }

   // set TIMEOUT for TRAP library
   int ret_set_timeout = trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_TIMEOUT_MICROSECONDS);
   if (ret_set_timeout != TRAP_E_OK) {
      PRINT_ERR("Error: Can't set timeout for TRAP library!\n");
   }


#ifdef ENABLE_GEOIP
   // ***** Load GeoIP databases to memory *****

   geoip_databases_load();
#endif


   // ***** Defining, initialization data structures, variables *****

   statistics_initialize();

   // initialize hash tables
   cc_hash_table_v2_t hash_table_ip, hash_table_user_agent;
   int ret_ht_init;
   if ((ret_ht_init = ht_init_v2(&hash_table_ip, HASH_TABLE_IP_SIZE, sizeof (ip_item_t *), sizeof (ip_addr_t))) != 0) {
      PRINT_ERR("Error: Initialize hash table for IP addresses!\n");
   }
   if ((ret_ht_init = ht_init_v2(&hash_table_user_agent, HASH_TABLE_USER_AGENT_SIZE, sizeof (char **), sizeof (uint32_t))) != 0) {
      PRINT_ERR("Error: Initialize hash table for User-Agents!\n");
   }

   if (detection_record == NULL || ret_set_timeout != TRAP_E_OK || ret_ht_init != 0) {
      // fatal error, module exits
      ur_free_template(ur_template_in);
      ur_free_template(ur_template_out);
      ur_free_record(detection_record);
      TRAP_DEFAULT_FINALIZATION();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return RETURN_ERROR;
   }

#ifdef ENABLE_GEOIP
   if (countries_load_all_from_file(modul_configuration.countries_file, &hash_table_ip) == -1) {
      PRINT_ERR_LOG("Error loading countries file!\n");
   }
#endif

   // definition of required variables
   char ip_src_str[INET6_ADDRSTRLEN + 1], ip_dst_str[INET6_ADDRSTRLEN + 1];
   ip_addr_t *ip_src, *ip_dst;
   char sip_target_orig[MAX_LENGTH_SIP_TO + 1];
   char sip_from_orig[MAX_LENGTH_SIP_FROM + 1];
   char call_id[MAX_LENGTH_CALL_ID + 1];
   char user_agent[MAX_LENGTH_USER_AGENT + 1];
   char sip_cseq[MAX_LENGTH_SIP_CSEQ + 1];
   int call_id_len, user_agent_len;
   char *sip_target, *sip_from;
   int sip_from_len, sip_target_len, sip_cseq_len;

   // load Event ID from file
   event_id_load(modul_configuration.event_id_file);

   ur_template_t *sdmout_tmpl = ur_create_output_template(1, "INVITE_CNT,CALLER_CNT,CALLEE_CNT", NULL);
   void *smdout_rec = ur_create_record(sdmout_tmpl, 0);

   // ***** Main processing loop of module *****
   while (!stop) {
      uint16_t in_rec_size;
      prefix_tree_domain_t *prefix_tree_node;
      ip_item_t *hash_table_item;

      // Receive data from input interface 0.
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, ur_template_in);

      // Handle possible errors
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(ur_template_in)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            PRINT_ERR("Error: data with wrong size received (expected size: >= ", ushortint_to_str(ur_rec_fixlen_size(ur_template_in)), ", received size: ", ushortint_to_str(in_rec_size), ")\n");
            break;
         }
      }

      // PROCESS THE DATA

      // memory management of module: check and free memory
      check_and_free_module_memory(&hash_table_ip);

      // get type of packet
      uint16_t sip_msg_type;
      uint16_t status_code;
      sip_msg_type = ur_get(ur_template_in, in_rec, F_SIP_MSG_TYPE);
      status_code = ur_get(ur_template_in, in_rec, F_SIP_STATUS_CODE);
      current_time = ur_time_get_sec((ur_time_t *) ur_get(ur_template_in, in_rec, F_TIME_FIRST));
      get_string_from_unirec(sip_cseq, &sip_cseq_len, F_SIP_CSEQ, MAX_LENGTH_SIP_CSEQ);

      if (sip_msg_type == SIP_MSG_TYPE_INVITE) {
         get_string_from_unirec(sip_target_orig, &sip_target_len, F_SIP_REQUEST_URI, MAX_LENGTH_SIP_TO);
         int valid = cut_sip_identifier(&sip_target, sip_target_orig, &sip_target_len);
         if (valid == -1) {
            get_string_from_unirec(sip_target_orig, &sip_target_len, F_SIP_CALLED_PARTY, MAX_LENGTH_SIP_TO);
            valid = cut_sip_identifier(&sip_target, sip_target_orig, &sip_target_len);
            if (valid == -1) {
               global_module_statistic.invalid_sip_identifier_count++;
               continue;
            }
         }

         get_string_from_unirec(sip_from_orig, &sip_from_len, F_SIP_CALLING_PARTY, MAX_LENGTH_SIP_FROM);
         valid = cut_sip_identifier(&sip_from, sip_from_orig, &sip_from_len);
         if (valid == -1) {
            sip_from = NULL;
         }

         global_module_statistic.received_invite_flow_count++;
         get_string_from_unirec(call_id, &call_id_len, F_SIP_CALL_ID, MAX_LENGTH_CALL_ID);
         get_string_from_unirec(user_agent, &user_agent_len, F_SIP_USER_AGENT, MAX_LENGTH_USER_AGENT);
         ip_src = &ur_get(ur_template_in, in_rec, F_SRC_IP);
         ip_to_str(ip_src, ip_src_str);
         ip_dst = &ur_get(ur_template_in, in_rec, F_DST_IP);
         ip_to_str(ip_dst, ip_dst_str);

         // is source IP in hash table?
         if ((hash_table_item = (ip_item_t *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) == NULL) {
            /* IP address not found in hash table */
            // create hash_table_item
            hash_table_item = (ip_item_t *) malloc(sizeof (ip_item_t));
            caller_count++;

            // check successful allocation memory
            if (hash_table_item == NULL) {
               PRINT_ERR("hash_table_item: Error memory allocation\n");
               continue;
            }

            //  initialize hash_table_item, if error occurs continue
            if (hash_table_item_initialize(hash_table_item) == -1) continue;

            // set time correct time to hash_table_item
            hash_table_item->first_invite_request = current_time;
            hash_table_item->time_last_check_prefix_examination = current_time;
            hash_table_item->time_last_communication = current_time;

            // insert into hash table
            ip_item_t * kicked_hash_table_item;
            if ((kicked_hash_table_item = (ip_item_t *) ht_insert_v2(&hash_table_ip, (char *) ip_src->bytes, (void *) &hash_table_item)) != NULL) {
               // free memory of kicked item from hash table
               hash_table_item_free_inner_memory(*(ip_item_t **) kicked_hash_table_item);
               free(*(ip_item_t **) kicked_hash_table_item);
               kicked_hash_table_item = NULL;
            }

         } else {
            // IP is in hash_table

             hash_table_item = *(ip_item_t **) hash_table_item;

            // save time of first INVITE request for the IP address
            if ((int) hash_table_item->first_invite_request == 0) {
               hash_table_item->first_invite_request = current_time;
            }
         }

         // DETECTION of prefix examination
         prefix_examination_detection(&hash_table_user_agent, hash_table_item, ip_src);

         /* >>>>>>>>>> SAVE RECEIVED DATA >>>>>>>>>> */

         // add sip_to to prefix tree
         prefix_tree_node = prefix_tree_insert(hash_table_item->tree, sip_target, sip_target_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_target_len);
         // check successful prefix_tree_insert
         if (prefix_tree_node == NULL) {
            PRINT_ERR("prefix_tree_insert: Error memory allocation\n");
            continue;
         } else if (prefix_tree_node->count_of_insert == 1) {
            //new callee
            callee_count++;
         }

         // check of successful initialization of node data
         if (node_data_check_initialize(prefix_tree_node) == -1) continue;
         // save Call-ID to node_data
         call_id_node_data_save(prefix_tree_node, call_id, call_id_len);

         // compute hash of User-Agent
         ((node_data_t *) (prefix_tree_node->parent->value))->user_agent_hash = SuperFastHash(user_agent, sizeof (char) * user_agent_len);

         // check if hash of User-Agent exists in hash table
         if (ht_get_v2(&hash_table_user_agent, (char *) &(((node_data_t *) (prefix_tree_node->parent->value))->user_agent_hash)) == NULL) {

            // save User-Agent to hash table
            char *user_agent_item = (char *) malloc(sizeof (char) * (user_agent_len + 1));

            // check successful allocation memory
            if (user_agent_item == NULL) {
               PRINT_ERR("user_agent_item: Error memory allocation\n");
               continue;
            }

            strncpy(user_agent_item, user_agent, user_agent_len + 1);

            char * kicked_hash_table_item;
            if ((kicked_hash_table_item = (char *) ht_insert_v2(&hash_table_user_agent, (char *) &(((node_data_t *) (prefix_tree_node->parent->value))->user_agent_hash), (void *) &user_agent_item)) != NULL) {
               free(*(char **) kicked_hash_table_item);
               kicked_hash_table_item = NULL;
            }
         }

         ((node_data_t *) (prefix_tree_node->parent->value))->invite_count++;

         // save last communication time
         hash_table_item->time_last_communication = current_time;

      } else if (sip_msg_type == SIP_MSG_TYPE_STATUS && status_code == SIP_STATUS_OK && sip_cseq_len > 2 && strstr(sip_cseq, "INV")) {
         get_string_from_unirec(sip_target_orig, &sip_target_len, F_SIP_CALLED_PARTY, MAX_LENGTH_SIP_TO);
         int valid = cut_sip_identifier(&sip_target, sip_target_orig, &sip_target_len);
         if (valid == -1) {
            continue;
         }

         cut_sip_identifier(&sip_from, sip_from_orig, &sip_from_len);
         get_string_from_unirec(call_id, &call_id_len, F_SIP_CALL_ID, MAX_LENGTH_CALL_ID);
         get_string_from_unirec(call_id, &call_id_len, F_SIP_CALL_ID, MAX_LENGTH_CALL_ID);
         ip_src = &ur_get(ur_template_in, in_rec, F_SRC_IP);
         ip_to_str(ip_src, ip_src_str);
         ip_dst = &ur_get(ur_template_in, in_rec, F_DST_IP);
         ip_to_str(ip_dst, ip_dst_str);

         // is destination IP in hash table?
         if ((hash_table_item = (ip_item_t *) ht_get_v2(&hash_table_ip, (char *) (ip_dst->bytes))) != NULL) {
            hash_table_item = *(ip_item_t **) hash_table_item;

            // search sip_to in prefix tree
            prefix_tree_node = prefix_tree_search(hash_table_item->tree, sip_target, sip_target_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_target_len);

            // if node isn't found, ignore it
            if (prefix_tree_node == NULL) continue;

            // check of successful initialization of node data
            if (node_data_check_initialize(prefix_tree_node) == -1) continue;

            // check if Call-ID is saved in node_data
            if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {
               ((node_data_t *) (prefix_tree_node->parent->value))->ok_count++;
#ifdef ENABLE_GEOIP
               if (modul_configuration.countries_detection_mode != COUNTRIES_DETECTION_MODE_OFF) {
                  // DETECTION of calling to different country
                  // Actual SIP message is response! Exchanged source and destination IP!
                  country_different_call_detection(&hash_table_ip, hash_table_item, sip_target, sip_target_len, sip_from, user_agent, ip_dst, ip_src);
                }
#endif
            }
            // save last communication time
            hash_table_item->time_last_communication = current_time;
         }
      }

      if (module_info->num_ifc_out == 2) {
         if (time(NULL) - time_last_stats > STATS_TIME_INTERVAL) {
            /*
             * Retrieve and send statistics via statistics interface.
             * This is used for visualisation in SDM demo.
             */
            ur_set(sdmout_tmpl, smdout_rec, F_INVITE_CNT, global_module_statistic.received_invite_flow_count);
            /* caller_count from hash table?*/
            ur_set(sdmout_tmpl, smdout_rec, F_CALLER_CNT, caller_count);
            /* sum of callee from every suffix tree?*/
            ur_set(sdmout_tmpl, smdout_rec, F_CALLEE_CNT, callee_count);
            trap_send(1, smdout_rec, ur_rec_size(sdmout_tmpl, smdout_rec));
            time(&time_last_stats);
         }
      }

   }
   if (module_info->num_ifc_out == 2) {
      /*
       * Retrieve and send statistics via statistics interface.
       * This is used for visualisation in SDM demo.
       */
      ur_set(sdmout_tmpl, smdout_rec, F_INVITE_CNT, global_module_statistic.received_invite_flow_count);
      /* caller_count from hash table?*/
      ur_set(sdmout_tmpl, smdout_rec, F_CALLER_CNT, caller_count);
      /* sum of callee from every suffix tree?*/
      ur_set(sdmout_tmpl, smdout_rec, F_CALLEE_CNT, callee_count);
      trap_send(1, smdout_rec, ur_rec_size(sdmout_tmpl, smdout_rec));
   }

   // print statistics of module
   PRINT_OUT_LOG("-----------------------------------------------------\n");
   PRINT_OUT_LOG("Total module statistics:\n");
   PRINT_OUT_LOG(" # Prefix examination:\n");
   PRINT_OUT_LOG("   - detection_event=", uint_to_str(global_module_statistic.prefix_examination_detection_event_count), "\n");
   PRINT_OUT_LOG("   - attack_detected=", uint_to_str(global_module_statistic.prefix_examination_attack_detected_count), "\n");
   PRINT_OUT_LOG(" # Calling to different country:\n");
   PRINT_OUT_LOG("   - detection_event=", uint_to_str(global_module_statistic.call_different_country_detection_event_count), "\n");
   PRINT_OUT_LOG("   - attack_detected=", uint_to_str(global_module_statistic.call_different_country_attack_detected_count), "\n");
   PRINT_OUT_LOG(" # Total number of attacks:\n");
   PRINT_OUT_LOG("   - detection_event=", uint_to_str(global_module_statistic.prefix_examination_detection_event_count + global_module_statistic.call_different_country_detection_event_count), "\n");
   PRINT_OUT_LOG("   - attack_detected=", uint_to_str(global_module_statistic.prefix_examination_attack_detected_count + global_module_statistic.call_different_country_attack_detected_count), "\n");
   PRINT_OUT_LOG(" # Other statistics:\n");
   PRINT_OUT_LOG("   - received_invite_flow=", uint_to_str(global_module_statistic.received_invite_flow_count), "\n");
   PRINT_OUT_LOG("   - invalid_sip_identifier=", uint_to_str(global_module_statistic.invalid_sip_identifier_count), "\n");

#ifdef ENABLE_GEOIP
   countries_save_all_to_file(modul_configuration.countries_file, &hash_table_ip);
#endif

   // ***** Cleanup *****

   // destroy hash tables (free memory)
   ip_item_t * hash_table_item;
   for (int i = 0; i < hash_table_ip.table_size; i++) {
      if (hash_table_ip.ind[i].valid) {
         hash_table_item = *(ip_item_t **) hash_table_ip.data[hash_table_ip.ind[i].index];
         hash_table_item_free_inner_memory(hash_table_item);
      }
   }

   ht_destroy_v2(&hash_table_ip);
   ht_destroy_v2(&hash_table_user_agent);

#ifdef ENABLE_GEOIP
   // free GeoIP databases and other memory allocated for countries
   geoip_databases_free();
   countries_free();
#endif

   // destroy templates (free memory)
   ur_free_template(ur_template_in);
   ur_free_template(ur_template_out);
   ur_free_template(sdmout_tmpl);
   ur_free_record(detection_record);
   ur_free_record(smdout_rec);

   PRINT_OUT_LOG("... VoIP fraud detection module exit! (version:", MODULE_VERSION, ")\n");
   PRINT_OUT_LOG("-----------------------------------------------------\n");

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return RETURN_OK;
}
