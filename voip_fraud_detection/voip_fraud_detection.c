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
   string INVEA_SIP_CALLING_PARTY,
   string INVEA_SIP_CALLED_PARTY,
   string INVEA_SIP_CALL_ID,
   string INVEA_SIP_USER_AGENT,
   uint8 INVEA_VOIP_PACKET_TYPE,
   ipaddr SRC_IP,
   ipaddr DST_IP,
   uint64 LINK_BIT_FIELD,
   uint16 SRC_PORT,
   uint16 DST_PORT,
   string INVEA_SIP_REQUEST_URI,
   string VOIP_FRAUD_USER_AGENT,
   uint16 VOIP_FRAUD_PREFIX_LENGTH,
   uint32 VOIP_FRAUD_SUCCESSFUL_CALL_COUNT,
   uint32 VOIP_FRAUD_INVITE_COUNT,
   uint32 VOIP_FRAUD_PREFIX_EXAMINATION_COUNT,
   string VOIP_FRAUD_SIP_TO,
   string VOIP_FRAUD_SIP_FROM,
   string VOIP_FRAUD_COUNTRY_CODE,
   uint64 INVEA_SIP_STATS,
   uint64 INVEA_RTCP_PACKETS,
   uint64 INVEA_RTCP_OCTETS,
   string INVEA_SIP_VIA,
   uint32 EVENT_ID,
   uint8 EVENT_TYPE,
   time DETECTION_TIME,
   time TIME_FIRST
)

/** \brief Struct with information about module. */
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("voip_fraud_detection module","This module detecting fraud in VoIP telephony - in SIP communication.",1,1)

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

// Check and free memory, that wasn't used for long time or exceeds limit of items (memory management of module)

void check_and_free_module_memory(cc_hash_table_v2_t * hash_table)
{
   static time_t time_actual;
   static time_t time_last_check;

   int i;
   ip_item_t * hash_table_item;

   // get actual time
   time(&time_actual);

   // check if check memory interval was expired
   if (difftime(time_actual, time_last_check) > CHECK_MEMORY_INTERVAL) {

      // iterate over items in hash table
      for (i = 0; i < hash_table->table_size; i++) {

         // check if item in hash table is valid
         if (hash_table->ind[i].valid) {

            // get item from hash_table
            hash_table_item = *(ip_item_t **) hash_table->data[hash_table->ind[i].index];

            // check for no SIP communication for defined time
            if (difftime(time_actual, hash_table_item->time_last_communication) > modul_configuration.clear_data_no_communication_after) {

#ifdef DEBUG
               PRINT_OUT("check_and_free_module_memory():remove TIME_LAST_COMMUNICATION\n");
#endif

               // free additional memory
               hash_table_item_free_inner_memory(hash_table_item);

               // remove item from hash table
               ht_remove_by_key_v2(hash_table, (char *) hash_table->keys[hash_table->ind[i].index]);

               // actual hash table item was removed, continue with next item
               continue;
            }

            // check if prefix_tree has more than max_item_prefix_tree items
            if ((hash_table_item->tree->root->count_of_string > modul_configuration.max_item_prefix_tree)) {

#ifdef DEBUG
               PRINT_OUT("check_and_free_module_memory():remove MAX_ITEM_PREFIX_TREE (", uint_to_str(hash_table_item->tree->root->count_of_string), ")\n");
#endif

               // destroy prefix_tree
               prefix_tree_destroy(hash_table_item->tree);

               // initialize new prefix_tree
               hash_table_item->tree = prefix_tree_initialize(SUFFIX, 0, -1, DOMAIN_EXTENSION_NO, RELAXATION_AFTER_DELETE_YES);

               // check successful allocation memory
               if (hash_table_item->tree == NULL) {
                  PRINT_ERR("hash_table_item->renew_tree, prefix_tree_initialize: Error memory allocation\n");
               }

               // reset first_invite_request
               hash_table_item->first_invite_request = (time_t) 0;

            }

         }
      }

      // save time of last check of module memory
      time(&time_last_check);
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

         // not valid sip identifier, add one to statistic
         global_module_statistic.invalid_sip_identifier_count++;

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

   // save start time module
   time_t time_start_module;
   time(&time_start_module);

   // definition of required variables
   char ip_src_str[INET6_ADDRSTRLEN + 1], ip_dst_str[INET6_ADDRSTRLEN + 1];
   ip_addr_t * ip_src, * ip_dst;
   char sip_request_uri_orig[MAX_LENGTH_SIP_TO + 1];
   char sip_to_orig[MAX_LENGTH_SIP_TO + 1];
   char sip_from_orig[MAX_LENGTH_SIP_FROM + 1];
   char call_id[MAX_LENGTH_CALL_ID + 1];
   char user_agent[MAX_LENGTH_USER_AGENT + 1];
   unsigned int call_id_len, user_agent_len;
   char * sip_to, * sip_from, * sip_request_uri;
   int sip_from_len, sip_to_len, sip_request_uri_len;

   // load Event ID from file
   event_id_load(modul_configuration.event_id_file);


   // ***** Main processing loop of module *****

   while (!stop) {

      uint16_t in_rec_size;

      // Receive data from input interface 0.
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, ur_template_in);

      // Handle possible errors
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TIMEOUT) {
            continue; // timeout
         } else if (ret == TRAP_E_TERMINATED) {
            break; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
         } else {
            // Some error has occured
            PRINT_ERR("Error: trap_recv() returned ", uint_to_str(ret), " (", trap_last_error_msg, ")\n");
            break;
         }
      }

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
      uint8_t voip_packet_type;
      voip_packet_type = ur_get(ur_template_in, in_rec, F_INVEA_VOIP_PACKET_TYPE);

      // if voip_packet_type is monitored
      if (voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED \
           || voip_packet_type == VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED \
           || voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_CALL_ORIENTED) {

         prefix_tree_domain_t * prefix_tree_node;
         ip_item_t * hash_table_item;

         // get actual time
         time_t time_actual;
         time(&time_actual);

         // get source IP (unirec)
         ip_src = &ur_get(ur_template_in, in_rec, F_SRC_IP);
         ip_to_str(ip_src, ip_src_str);

         // get destination IP (unirec)
         ip_dst = &ur_get(ur_template_in, in_rec, F_DST_IP);
         ip_to_str(ip_dst, ip_dst_str);

         // get SIP_REQUEST_URI from UniRec
         get_string_from_unirec(sip_request_uri_orig, &sip_request_uri_len, F_INVEA_SIP_REQUEST_URI, MAX_LENGTH_SIP_TO);

         // get SIP_FROM from UniRec
         get_string_from_unirec(sip_from_orig, &sip_from_len, F_INVEA_SIP_CALLING_PARTY, MAX_LENGTH_SIP_FROM);

         // get SIP_TO from UniRec
         get_string_from_unirec(sip_to_orig, &sip_to_len, F_INVEA_SIP_CALLED_PARTY, MAX_LENGTH_SIP_TO);

         // get Call-ID from UniRec
         get_string_from_unirec(call_id, &call_id_len, F_INVEA_SIP_CALL_ID, MAX_LENGTH_CALL_ID);

         // get User-Agent from UniRec
         get_string_from_unirec(user_agent, &user_agent_len, F_INVEA_SIP_USER_AGENT, MAX_LENGTH_USER_AGENT);

         // cut "sip:" or "sips:" from sip_request_uri, sip_to and sip_from
         int invalid_request_uri = cut_sip_identifier(&sip_request_uri, sip_request_uri_orig, &sip_request_uri_len);
         int invalid_sipto = cut_sip_identifier(&sip_to, sip_to_orig, &sip_to_len);
         int invalid_sipfrom = cut_sip_identifier(&sip_from, sip_from_orig, &sip_from_len);

#ifdef PRINT_DETAIL_INVALID_SIPURI
         if (invalid_sipto == -1 || invalid_sipfrom == -1 || \
             (invalid_request_uri == -1 && voip_packet_type == VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED)) {

            if (invalid_sipto == -1) {
               PRINT_OUT("SIP_To header is invalid:\"", sip_to_orig, "\"; ");
            }

            if (invalid_sipfrom == -1) {
               PRINT_OUT("SIP_From header is invalid:\"", sip_from_orig, "\"; ");
            }

            if (invalid_request_uri == -1 && voip_packet_type == VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED) {
               PRINT_OUT("SIP_RequestURI header is invalid:\"", sip_request_uri_orig, "\"; ");
            }

            // get id of monitoring probes
            uint64_t link_bit_field;
            link_bit_field = ur_get(ur_template_in, in_rec, F_LINK_BIT_FIELD);

            PRINT_OUT_NOTDATETIME(" LINK_BIT_FIELD: ", uint_to_str(link_bit_field), "; ");
            PRINT_OUT_NOTDATETIME("SRC_IP: ", ip_src_str, "; DST_IP: ", ip_dst_str, "; voip_packet_type: ", uint_to_str(voip_packet_type), "; ");

            uint16_t src_port, dst_port;
            src_port = ur_get(ur_template_in, in_rec, F_SRC_PORT);
            dst_port = ur_get(ur_template_in, in_rec, F_DST_PORT);

            PRINT_OUT_NOTDATETIME("SRC_PORT: ", uint_to_str(src_port), "; ");
            PRINT_OUT_NOTDATETIME("DST_PORT: ", uint_to_str(dst_port), "\n");
         }
#endif

         // if not valid sip_to, not process it
         if (invalid_sipto == -1) continue;


         // get SIP_STATS from UniRec
         uint64_t sip_stats;
         sip_stats = ur_get(ur_template_in, in_rec, F_INVEA_SIP_STATS);

         uint32_t invite_stats;
         uint16_t bye_stats;
         uint8_t ack_stats, cancel_stats;
         uint8_t forbidden_stats, unauthorized_stats;
         uint8_t ok_stats, ringing_stats, proxy_auth_req_stats, trying_stats;

         // get number of requests/responses from SIP_STATS
         switch (voip_packet_type) {

            case VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED:
            {
               // get number of INVITE requests in the flow record
               // same as: invite_stats = (uint32_t) (sip_stats & 0x00000000ffffffff);
               invite_stats = (uint32_t) sip_stats;

               // get number of CANCEL, ACK and BYE requests in the flow record (other_stats = sip_stats>>32;)
               cancel_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
               ack_stats = (uint8_t) ((sip_stats & 0x00ff000000000000) >> 48);
               bye_stats = (uint16_t) ((sip_stats & 0x0000ffff00000000) >> 32);

               break;
            }

            case VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED:
            {
               // get number of forbidden, unauthorized responses in the flow record
               forbidden_stats = (uint8_t) ((sip_stats & 0x0000ff0000000000) >> 40);
               unauthorized_stats = (uint8_t) ((sip_stats & 0x000000000000ff00) >> 8);

               break;
            }

            case VOIP_PACKET_TYPE_RESPONSE_CALL_ORIENTED:
            {
               // get number of OK, RINGING, TRYING and PROXY AUTH REQUEST responses in the flow record
               ok_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
               ringing_stats = (uint8_t) ((sip_stats & 0x0000ff0000000000) >> 40);
               proxy_auth_req_stats = (uint8_t) ((sip_stats & 0x000000000000ff00) >> 8);
               trying_stats = (uint8_t) (sip_stats & 0x00000000000000ff);

               break;
            }

         }

         // check if sip_to is numeric with allowed special char ('+','*','#') or this text part before '@' + check of minimum numeric length
         if (!is_numeric_participant(sip_to, sip_to_len)) {

#ifdef ENABLE_GEOIP
            if (voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_CALL_ORIENTED) {

               if (ok_stats > 0 && modul_configuration.countries_detection_mode != COUNTRIES_DETECTION_MODE_OFF) {

                  // check calling to diferrent country for non-numeric calling party

                  // is destination IP in hash table?
                  if ((hash_table_item = (ip_item_t *) ht_get_v2(&hash_table_ip, (char *) (ip_dst->bytes))) != NULL) {

                     hash_table_item = *(ip_item_t **) hash_table_item;

                  } else {

                     // create hash_table_item
                     hash_table_item = (ip_item_t *) malloc(sizeof (ip_item_t));

                     // check successful allocation memory
                     if (hash_table_item == NULL) {
                        PRINT_ERR("hash_table_item: Error memory allocation\n");
                        continue;
                     }

                     //  initialize hash_table_item, if error occurs continue
                     if (hash_table_item_initialize(hash_table_item) == -1) continue;

                     // set time correct time to hash_table_item
                     time(&(hash_table_item->first_invite_request));
                     hash_table_item->time_last_check_prefix_examination = time_start_module;
                     hash_table_item->time_last_communication = time_start_module;

                     // insert into hash table
                     ip_item_t * kicked_hash_table_item;
                     if ((kicked_hash_table_item = (ip_item_t *) ht_insert_v2(&hash_table_ip, (char *) ip_dst->bytes, (void *) &hash_table_item)) != NULL) {
                        // free memory of kicked item from hash table
                        hash_table_item_free_inner_memory(*(ip_item_t **) kicked_hash_table_item);
                        free(*(ip_item_t **) kicked_hash_table_item);
                        kicked_hash_table_item = NULL;
#ifdef DEBUG
                        PRINT_OUT("Hash table for IP addresses reaches size limit\n");
#endif
                     }

                  }

                  // DETECTION of calling to different country
                  // Actual SIP message is response! Exchanged source and destination IP!
                  country_different_call_detection(&hash_table_ip, hash_table_item, sip_to, sip_to_len, sip_from, user_agent, ip_dst, ip_src);

               }

            }
#endif
            continue;
         }

         // RTP data
         if ((hash_table_item = (ip_item_t *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) != NULL) {

            hash_table_item = *(ip_item_t **) hash_table_item;

            // search sip_to in prefix tree
            prefix_tree_node = prefix_tree_search(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

            // check if node exists
            if (prefix_tree_node != NULL) {

               // check of successful initialization of node data
               if (node_data_check_initialize(prefix_tree_node) == -1) continue;

               if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {
                  // set rtp_data=1, if some packets are in the flow record
                  if (ur_get(ur_template_in, in_rec, F_INVEA_RTCP_PACKETS) > 0 && ur_get(ur_template_in, in_rec, F_INVEA_RTCP_OCTETS) > 0) {
                     ((node_data_t *) (prefix_tree_node->parent->value))->rtp_data = 1;
                  }
               }
            }
         }

         // do action according to voip_packet_type
         switch (voip_packet_type) {

            case VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED:
            {
               /* --------------------------------
                * request type: call oriented
                * -------------------------------- */

               // if at least one INVITE requests is in flow record
               if (invite_stats > 0) {
                  // add one to statistics of number invite flow
                  global_module_statistic.received_invite_flow_count++;
               }

               // is source IP in hash table?
               if ((hash_table_item = (ip_item_t *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) == NULL) {

                  /* IP address not found in hash table */

                  // if it isn't INVITE request, don't create item in hash table
                  if (invite_stats == 0) continue;

                  // create hash_table_item
                  hash_table_item = (ip_item_t *) malloc(sizeof (ip_item_t));

                  // check successful allocation memory
                  if (hash_table_item == NULL) {
                     PRINT_ERR("hash_table_item: Error memory allocation\n");
                     continue;
                  }

                  //  initialize hash_table_item, if error occurs continue
                  if (hash_table_item_initialize(hash_table_item) == -1) continue;

                  // set time correct time to hash_table_item
                  time(&(hash_table_item->first_invite_request));
                  hash_table_item->time_last_check_prefix_examination = time_start_module;
                  hash_table_item->time_last_communication = time_start_module;

                  // insert into hash table
                  ip_item_t * kicked_hash_table_item;
                  if ((kicked_hash_table_item = (ip_item_t *) ht_insert_v2(&hash_table_ip, (char *) ip_src->bytes, (void *) &hash_table_item)) != NULL) {
                     // free memory of kicked item from hash table
                     hash_table_item_free_inner_memory(*(ip_item_t **) kicked_hash_table_item);
                     free(*(ip_item_t **) kicked_hash_table_item);
                     kicked_hash_table_item = NULL;
#ifdef DEBUG
                     PRINT_OUT("Hash table for IP addresses reaches size limit\n");
#endif
                  }

               } else {
                  // IP is in hash_table

                  hash_table_item = *(ip_item_t **) hash_table_item;

                  // save time of first INVITE request for the IP address
                  if ((int) hash_table_item->first_invite_request == 0) {
                     time(&(hash_table_item->first_invite_request));
                  }
               }

               // DETECTION of prefix examination
               prefix_examination_detection(&hash_table_user_agent, hash_table_item, ip_src);

#ifdef DEBUG
               // if at least one INVITE requests is in flow record
               if (invite_stats > 0) {
                  // print debug information about INVITE request
                  int sip_via_len = ur_get_var_len(ur_template_in, in_rec, F_INVEA_SIP_VIA);
                  char *sip_via = ur_get_ptr_by_id(ur_template_in, in_rec, F_INVEA_SIP_VIA);
                  uint64_t link_bit_field = ur_get(ur_template_in, in_rec, F_LINK_BIT_FIELD);
                  printf("%s;INVITE;IP_SRC:%s;IP_DST:%s;LINK_BIT_FIELD:%u;\n", get_actual_time_string(), ip_src_str, ip_dst_str, link_bit_field);
                  printf("From:\"%.*s\";\n", sip_from_len, sip_from);
                  printf("To:\"%.*s\";\n", sip_to_len, sip_to);
                  printf("Via:\"%.*s\";\n", sip_via_len, sip_via);
                  printf("UserAgent:\"%.*s\";\n", user_agent_len, user_agent);
                  printf("RequestURI:\"%.*s\";\n", sip_request_uri_len, sip_request_uri);
               }
#endif

#ifdef CHECK_DIFFERENT_REQUEST_URI
               // if at least one INVITE requests is in flow record
               if (invite_stats > 0) {

                  // check if To header and Request-URI isn't identical
                  if (strncmp(sip_to, sip_request_uri, MAX_LENGTH_SIP_TO) != 0) {

                     char * at_position_request_uri = strpbrk(sip_request_uri, "@");
                     char * at_position_sip_to = strpbrk(sip_to, "@");

                     // check if To header and Reuqest-URI has the same number before '@'
                     if (at_position_request_uri == NULL || at_position_sip_to == NULL \
                             || ((at_position_request_uri - sip_request_uri) != (at_position_sip_to - sip_to)) \
                             || (strncmp(sip_to, sip_request_uri, at_position_sip_to - sip_to) != 0)) {
                        PRINT_OUT("OtherRequestURI:\"", sip_request_uri, "\";", "ToHeader:\"", sip_to, "\";\n");
                     }
                  }
               }
#endif

               /* >>>>>>>>>> SAVE RECEIVED DATA >>>>>>>>>> */

               if (invite_stats > 0) {
                  // add sip_to to prefix tree
                  prefix_tree_node = prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

                  // check successful prefix_tree_insert
                  if (prefix_tree_node == NULL) {
                     PRINT_ERR("prefix_tree_insert: Error memory allocation\n");
                     continue;
                  }
               } else {
                  // search sip_to in prefix tree
                  prefix_tree_node = prefix_tree_search(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

                  // if node isn't found, ignore it
                  if (prefix_tree_node == NULL) continue;
               }

               // check of successful initialization of node data
               if (node_data_check_initialize(prefix_tree_node) == -1) continue;


               if (invite_stats > 0) {
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
#ifdef DEBUG
                        PRINT_OUT("Hash table for User-Agent reaches size limit\n");
#endif
                     }
#ifdef DEBUG
                     global_sip_statistic.unique_user_agent_count++;
#endif
                  }

                  // sum stats
                  ((node_data_t *) (prefix_tree_node->parent->value))->invite_count += invite_stats;
                  ((node_data_t *) (prefix_tree_node->parent->value))->cancel_count += cancel_stats;
                  ((node_data_t *) (prefix_tree_node->parent->value))->ack_count += ack_stats;
                  ((node_data_t *) (prefix_tree_node->parent->value))->bye_count += bye_stats;
               } else {
                  if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {
                     // sum stats
                     ((node_data_t *) (prefix_tree_node->parent->value))->cancel_count += cancel_stats;
                     ((node_data_t *) (prefix_tree_node->parent->value))->ack_count += ack_stats;
                     ((node_data_t *) (prefix_tree_node->parent->value))->bye_count += bye_stats;
                  }
               }

#ifdef DEBUG
               global_sip_statistic.invite_count += invite_stats;
               global_sip_statistic.ack_count += ack_stats;
               global_sip_statistic.bye_count += bye_stats;
               global_sip_statistic.cancel_count += cancel_stats;
#endif

               // save last communication time
               time(&(hash_table_item->time_last_communication));

               /* <<<<<<<<<< SAVE RECEIVED DATA <<<<<<<<<< */

               break;
            }


            case VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED:
            case VOIP_PACKET_TYPE_RESPONSE_CALL_ORIENTED:
            {

               // is destination IP in hash table?
               if ((hash_table_item = (ip_item_t *) ht_get_v2(&hash_table_ip, (char *) (ip_dst->bytes))) != NULL) {

                  hash_table_item = *(ip_item_t **) hash_table_item;

                  // search sip_to in prefix tree
                  prefix_tree_node = prefix_tree_search(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

                  // if node isn't found, ignore it
                  if (prefix_tree_node == NULL) continue;

                  // check of successful initialization of node data
                  if (node_data_check_initialize(prefix_tree_node) == -1) continue;

                  // check if Call-ID is saved in node_data
                  if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {

                     if (voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED) {

                        /* --------------------------------
                         * response type: service oriented
                         * -------------------------------- */

                        // sum stats
                        ((node_data_t *) (prefix_tree_node->parent->value))->forbidden_count += forbidden_stats;
                        ((node_data_t *) (prefix_tree_node->parent->value))->unauthorized_count += unauthorized_stats;

#ifdef DEBUG
                        global_sip_statistic.forbidden_count += forbidden_stats;
                        global_sip_statistic.unauthorized_count += unauthorized_stats;
#endif
                     } else {

                        /* --------------------------------
                         * response type: call oriented
                         * -------------------------------- */

                        // sum stats
                        ((node_data_t *) (prefix_tree_node->parent->value))->ok_count += ok_stats;
                        ((node_data_t *) (prefix_tree_node->parent->value))->ringing_count += ringing_stats;
                        ((node_data_t *) (prefix_tree_node->parent->value))->proxy_auth_req_count += proxy_auth_req_stats;
                        ((node_data_t *) (prefix_tree_node->parent->value))->trying_count += trying_stats;

#ifdef DEBUG
                        global_sip_statistic.ok_count += ok_stats;
                        global_sip_statistic.ringing_count += ringing_stats;
                        global_sip_statistic.proxy_auth_req_count += proxy_auth_req_stats;
                        global_sip_statistic.trying_count += trying_stats;
#endif

#ifdef ENABLE_GEOIP
                        if (ok_stats > 0 && modul_configuration.countries_detection_mode != COUNTRIES_DETECTION_MODE_OFF) {

                           // DETECTION of calling to different country
                           // Actual SIP message is response! Exchanged source and destination IP!
                           country_different_call_detection(&hash_table_ip, hash_table_item, sip_to, sip_to_len, sip_from, user_agent, ip_dst, ip_src);

                        }
#endif
                     }

                  }

                  // save last communication time
                  time(&(hash_table_item->time_last_communication));
               }

               break;
            }

         }

      }

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

#ifdef DEBUG
   // print total SIP statistics
   PRINT_OUT_LOG("Total SIP statistics:\n");
   PRINT_OUT_LOG("   - ok_count=", uint_to_str(global_sip_statistic.ok_count), "\n");
   PRINT_OUT_LOG("   - invite_count=", uint_to_str(global_sip_statistic.invite_count), "\n");
   PRINT_OUT_LOG("   - ack_count=", uint_to_str(global_sip_statistic.ack_count), "\n");
   PRINT_OUT_LOG("   - bye_count=", uint_to_str(global_sip_statistic.bye_count), "\n");
   PRINT_OUT_LOG("   - cancel_count=", uint_to_str(global_sip_statistic.cancel_count), "\n");
   PRINT_OUT_LOG("   - trying_count=", uint_to_str(global_sip_statistic.trying_count), "\n");
   PRINT_OUT_LOG("   - ringing_count=", uint_to_str(global_sip_statistic.ringing_count), "\n");
   PRINT_OUT_LOG("   - forbidden_count=", uint_to_str(global_sip_statistic.forbidden_count), "\n");
   PRINT_OUT_LOG("   - unauthorized_count=", uint_to_str(global_sip_statistic.unauthorized_count), "\n");
   PRINT_OUT_LOG("   - proxy_auth_req_count=", uint_to_str(global_sip_statistic.proxy_auth_req_count), "\n");
   PRINT_OUT_LOG("   - unique_user_agent_count=", uint_to_str(global_sip_statistic.unique_user_agent_count), "\n");
#endif

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
   ur_free_record(detection_record);

   PRINT_OUT_LOG("... VoIP fraud detection module exit! (version:", MODULE_VERSION, ")\n");
   PRINT_OUT_LOG("-----------------------------------------------------\n");

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return RETURN_OK;
}
