/**
 * \file voip_fraud_detection.c
 * \brief VoIP fraud detection module
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


// Struct with information about module
trap_module_info_t module_info = {
   "VoIP_fraud_detection module", // Module name
   // Module description
   "This module detecting fraud in VoIP telephony - in SIP communication.\n"
   "It detects testing prefix enumeration and following successful call initiation.\n"
   "\n"
   "Optional parameters:\n"
   "   -l  : path to log file\n"
   "   -e  : event_id_file (it can be \"disabled\")\n"
   "   -m  : max_prefix_length\n"
   "   -d  : minimum length of called number\n"
   "   -s  : detection interval in seconds\n"
   "   -t  : prefix_examination_detection_threshold\n"
   "   -p  : detection_pause_after_attack in seconds\n"
   "   -q  : limit of maximum item in prefix tree for one IP address\n"
   "   -x  : time in seconds after it will be clear data without communication\n"
   "\n"
   "Interfaces:\n"
   "   Inputs: 1 (UniRec template: "UNIREC_INPUT_TEMPLATE")\n"
   "   Outputs: 1 (UniRec template: "UNIREC_OUTPUT_TEMPLATE")\n",
   1, // Number of input interfaces
   1, // Number of output interfaces
};


static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

// for testing only
unsigned int test_call_id_node_data_exists = 0;
unsigned int test_call_id_node_data_not_exists = 0;
unsigned int test_call_id_node_data_save = 0;


// Load Event ID counter from defined file

void load_event_id(char * file)
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

void save_event_id(char * file)
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
   int end_index = CALL_ID_STORAGE_SIZE;

   // if storage of Call-ID isn't full, set correct end index
   if (((node_data *) (prefix_tree_node->parent->value))->call_id_full == 0) {
      end_index = ((node_data *) (prefix_tree_node->parent->value))->call_id_insert_position;
   }

   for (i = 0; i < end_index; i++) {
      // has input call_id and call_id in node_data the same length?
      if (strlen(((node_data *) (prefix_tree_node->parent->value))->call_id[i]) == call_id_len) {
         // check if input call_id contain the same text as node_data->call_id[i] up to call_id_len position
         if (strncmp(((node_data *) (prefix_tree_node->parent->value))->call_id[i], call_id, call_id_len) == 0) {
            // Call-ID found
            test_call_id_node_data_exists++;
            return 1;
         }
      }
   }
   test_call_id_node_data_not_exists++;
   return 0;
}

// Save Call-ID to node_data

void call_id_node_data_save(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len)
{
   // testing
   if (call_id_len < 6) {
      printf("call-id: data_saved: %.*s\n", call_id_len, call_id);
   }

   // check if Call-ID doesn't exist in node data
   if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 0) {
      unsigned int call_id_insert_position = call_id_insert_position = ((node_data *) (prefix_tree_node->parent->value))->call_id_insert_position;
      memcpy(((node_data *) (prefix_tree_node->parent->value))->call_id[call_id_insert_position], call_id, sizeof (char) * call_id_len);
      ((node_data *) (prefix_tree_node->parent->value))->call_id[call_id_insert_position][call_id_len] = '\0';

      // increment insert position of Call-ID storage
      ((node_data *) (prefix_tree_node->parent->value))->call_id_insert_position += 1;
      if (((node_data *) (prefix_tree_node->parent->value))->call_id_insert_position >= CALL_ID_STORAGE_SIZE) {

         if (((node_data *) (prefix_tree_node->parent->value))->call_id_full == 0) printf("call-id: full storage (grep limit count)!!!\n");

         ((node_data *) (prefix_tree_node->parent->value))->call_id_insert_position = 0;
         ((node_data *) (prefix_tree_node->parent->value))->call_id_full = 1;
      }

      test_call_id_node_data_save++;
   }
}

// Check and free memory, that wasn't used for long time or exceeds limit of items (memory management of module)

void check_and_free_module_memory(cc_hash_table_v2_t * hash_table)
{
   static time_t time_actual;
   static time_t time_last_check;

   int i;
   ip_item * hash_table_item;

   // get actual time
   time(&time_actual);

   // check if check memory interval was expired
   if (difftime(time_actual, time_last_check) > CHECK_MEMORY_INTERVAL) {

      // iterate over items in hash table
      for (i = 0; i < hash_table->table_size; i++) {

         // check if item in hash table is valid
         if (hash_table->ind[i].valid) {

            // get item from hash_table
            hash_table_item = (ip_item *) hash_table->data[hash_table->ind[i].index];

            // check for no SIP communication for defined time
            if (difftime(time_actual, hash_table_item->time_last_communication) > modul_configuration.clear_data_no_communication_after) {

#ifdef DEBUG
               PRINT_OUT("check_and_free_module_memory():remove TIME_LAST_COMMUNICATION\n");
#endif

               // destroy prefix_tree
               prefix_tree_destroy(hash_table_item->tree);

               // free attack_sip_to
               if (hash_table_item->attack_sip_to != NULL) free(hash_table_item->attack_sip_to);

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

// Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' + string after it

int cut_sip_identifier_from_string(char ** output_str, char * input_str, int * str_len)
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

   // ignore ';' + string after it
   int i = 0;
   while (i < *str_len) {
      if ((*output_str)[i] == ';') {
         *str_len = i;
         break;
      }
      i++;
   }

   return 0;
}


// Check if input string is numeric with allowed special char ('+','*','#') or this text part before '@'
// + check of minimum numeric length

int is_numeric_participant(char * str, int str_len)
{
   int char_index;
   int is_numeric = 0;

   for (char_index = 0; char_index < str_len; char_index++) {

      // stop checking input string
      if (str[char_index] == '@') break;

      // ignore chars '+', '*', '#'
      if (str[char_index] == '+' || str[char_index] == '*' || str[char_index] == '#') continue;

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

// Initialize node_data defined by input parameter

int check_initialize_node_data(prefix_tree_domain_t * prefix_tree_node)
{
   // check if input prefix_tree_node has not allocate memory

   if (prefix_tree_node->parent == NULL) {
      PRINT_OUT("DEBUG: parent of prefix_tree_domain_t is NULL!\n");
      return -1;
   }

   if (prefix_tree_node->parent->value == NULL) {

      // allocate memory for node data
      prefix_tree_node->parent->value = (void *) malloc(sizeof (node_data));

      // check successful allocation memory
      if (prefix_tree_node->parent->value == NULL) {
         PRINT_ERR("initialize_node_data: Error memory allocation\n");
         return -1;
      }

      // initialize values of node_data
      ((node_data *) (prefix_tree_node->parent->value))->invite_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->cancel_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->ack_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->bye_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->ok_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->trying_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->ringing_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->service_ok_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->forbidden_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->unauthorized_count = 0;
      ((node_data *) (prefix_tree_node->parent->value))->proxy_auth_req_count = 0;

      ((node_data *) (prefix_tree_node->parent->value))->rtp_data = 0;

      // Call-ID storage
      ((node_data *) (prefix_tree_node->parent->value))->call_id_full = 0;
      ((node_data *) (prefix_tree_node->parent->value))->call_id_insert_position = 0;
   }

   return 0;
}

// Reset detection statistics

void reset_detection_statistics()
{
   detection.invite = 0;
   detection.ack = 0;
   detection.cancel = 0;
   detection.bye = 0;
   detection.ok = 0;
   detection.unique_ok = 0;
   detection.trying = 0;
   detection.ringing = 0;
   detection.service_ok = 0;
   detection.rtcp_data = 0;
   detection.forbidden = 0;
   detection.unauthorized = 0;
   detection.proxy_auth_req = 0;
   detection.report_node = NULL;
   detection.report_prefix_length = 0;
   strcpy(detection.sip_to, "");
   detection.prefix_examination_count = 0;

   // set actual time
   time(&(detection.time));
}

// Function to thorough count of prefix detection minus value and save information about attack to detection_struct

unsigned int count_minus_detection_value(prefix_tree_t * tree, prefix_tree_inner_node_t * node, unsigned int sum_prefix_down)
{
   unsigned int result = 0;

   // checking of max_prefix_length
   char str [MAX_STRING_PREFIX_TREE_NODE + 1];
   prefix_tree_read_inner_node(tree, node, str);
   sum_prefix_down += strlen(str);

   if (sum_prefix_down > modul_configuration.max_prefix_length) {

      result += node->count_of_string + 1;

   } else {
      // node belongs to detection

      // checking if node has data
      if (node->value != NULL) {

         if (((node_data *) (node->value))->ok_count > 0) {

            // incrementation result by one
            result += 1;

            // incrementation of unique_ok
            detection.unique_ok += 1;

         } else {

            // node is in prefix examination attack

            if (detection.report_prefix_length < sum_prefix_down) {
               // save node of prefix examination for reporting
               detection.report_node = node;
               detection.report_prefix_length = sum_prefix_down;
            }

         }

         detection.invite += ((node_data *) (node->value))->invite_count;
         detection.cancel += ((node_data *) (node->value))->cancel_count;
         detection.ack += ((node_data *) (node->value))->ack_count;
         detection.bye += ((node_data *) (node->value))->bye_count;
         detection.ok += ((node_data *) (node->value))->ok_count;
         detection.trying += ((node_data *) (node->value))->trying_count;
         detection.ringing += ((node_data *) (node->value))->ringing_count;
         detection.service_ok += ((node_data *) (node->value))->service_ok_count;
         detection.forbidden += ((node_data *) (node->value))->forbidden_count;
         detection.unauthorized += ((node_data *) (node->value))->unauthorized_count;
         detection.proxy_auth_req += ((node_data *) (node->value))->proxy_auth_req_count;
         detection.rtcp_data += ((node_data *) (node->value))->rtp_data;
      }

      if (node->child != NULL) {
         // node isn't leaf

         // node is an inner node
         int i;
         for (i = 0; i < COUNT_OF_LETTERS_IN_DOMAIN; i++) {
            if (node->child[i] != NULL) {

               // recursive call
               result += count_minus_detection_value(tree, node->child[i], sum_prefix_down);
            }
         }
      }
   }

   return result;
}

// Detection prefix examination in input prefix tree,
// if attack is detected delete node and his descendants

int detect_prefix_examination(prefix_tree_t * tree, prefix_tree_inner_node_t * node)
{
   // check if node is in cache_no_attack
   if (cache_node_no_attack_exists(node)) {
      test_cache_hit++;
      return STATE_NO_ATTACK;
   }

   int i;

   if (node->child == NULL) {
      // node is a leaf

      unsigned int prefix_sum_length = 0;
      unsigned int prefix_sum_count = 0;
      unsigned int prefix_last_count = 0;
      char str [MAX_STRING_PREFIX_TREE_NODE + 1];

      prefix_tree_inner_node_t * predecessor_node;
      prefix_tree_inner_node_t * last_predecessor_node;
      predecessor_node = node;

      // basic first quick count of prefix_sum_count

      while (prefix_sum_length <= modul_configuration.max_prefix_length) {

         prefix_tree_read_inner_node(tree, predecessor_node, str);

         // check if not node string contains '@' prior max_prefix_length position
         char * at_pointer = strstr(str, "@");
         if (at_pointer != NULL) {
            if (!(prefix_sum_length + (at_pointer - str) <= modul_configuration.max_prefix_length)) break;
         }

         // count length and number of descendants
         prefix_sum_length += strlen(str);
         prefix_sum_count += predecessor_node->count_of_string - prefix_last_count;
         prefix_last_count = predecessor_node->count_of_string;

         // save actual node
         last_predecessor_node = predecessor_node;

         // move to predecessor of node
         predecessor_node = predecessor_node->parent;

         // check if predecessor exists
         if (predecessor_node == NULL) break;
      }

      // check if prefix_sum_count exceeds threshold
      if (prefix_sum_count > modul_configuration.prefix_examination_detection_threshold) {

         // check if node is not in cache
         if (cache_node_no_attack_exists(predecessor_node) == 1) {
            test_cache_hit++;
            return STATE_NO_ATTACK;
         } else {
            test_cache_not_hit++;
         }

         // reset detection statistics
         reset_detection_statistics();

         // thorough count of prefix detection
         unsigned int minus_detection_value = count_minus_detection_value(tree, last_predecessor_node, 0);

         // decrement prefix_sum_count by minus detection value
         if (prefix_sum_count <= minus_detection_value) {
            prefix_sum_count = 0;
         } else {
            prefix_sum_count -= minus_detection_value;
         }

         // check if prefix_sum_count exceeds threshold after recalculation
         if (prefix_sum_count > modul_configuration.prefix_examination_detection_threshold) {

            // attack detected

#ifdef TEST_DEBUG
            // testing
            printf("count_minus %i; prefix_sum_count_original: %i; total_sum_after_descrease: %i;\n", minus_detection_value, prefix_sum_count + minus_detection_value, prefix_sum_count);
#endif

            // initialize sip_to string
            detection.sip_to[0] = '\0';

            // set predecessor_node as leaf node of prefix examination attack
            predecessor_node = detection.report_node;

            // compose one of sip_to uri from prefix attack
            while (predecessor_node != NULL) {
               prefix_tree_read_inner_node(tree, predecessor_node, str);
               // strcat(detection.sip_to, "|");
               strcat(detection.sip_to, str);
               predecessor_node = predecessor_node->parent;
            }

            detection.prefix_examination_count = prefix_sum_count;


#ifdef TEST_DEBUG
            // testing
            PRINT_OUT_NOTDATETIME(" before delete:", uint_to_str(tree->root->count_of_string));
#endif

            // delete node and his descendants from prefix tree
            prefix_tree_delete_inner_node(tree, last_predecessor_node);


#ifdef TEST_DEBUG
            // testing
            PRINT_OUT_NOTDATETIME("; after delete:", uint_to_str(tree->root->count_of_string), ";");
#endif

            return STATE_ATTACK_DETECTED;

         } else {
            // attack not detected, save node to cache
            cache_node_no_attack_save(last_predecessor_node);
            test_cache_save++;
         }
      }

   } else {
      // node is an inner node

      int state_detection;

      for (i = 0; i < COUNT_OF_LETTERS_IN_DOMAIN; i++) {
         if (node->child[i] != NULL) {

            // recursive call
            state_detection = detect_prefix_examination(tree, node->child[i]);
            if (state_detection == STATE_ATTACK_DETECTED) return STATE_ATTACK_DETECTED;
         }
      }

   }

   return STATE_NO_ATTACK;

}

// Copy char array field from UniRec to defined string_output, update string_len and add terminating '\0' at the end of char array

void get_string_from_unirec(char * string_output, int * string_len, int unirec_field_id, int max_length)
{
   char * ur_string;
   *string_len = ur_get_dyn_size(ur_template_in, in_rec, unirec_field_id);
   ur_string = ur_get_dyn(ur_template_in, in_rec, unirec_field_id);
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
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // Set default parameters of modul configuration
   modul_configuration.min_length_called_number = DEFAULT_MIN_LENGTH_CALLED_NUMBER;
   modul_configuration.max_prefix_length = DEFAULT_MAX_PREFIX_LENGTH;
   modul_configuration.prefix_examination_detection_threshold = DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD;
   modul_configuration.detection_interval = DEFAULT_DETECTION_INTERVAL;
   modul_configuration.detection_pause_after_attack = DEFAULT_DETECTION_PAUSE_AFTER_ATTACK;
   modul_configuration.max_item_prefix_tree = DEFAULT_MAX_ITEM_PREFIX_TREE;
   modul_configuration.clear_data_no_communication_after = DEFAULT_CLEAR_DATA_NO_COMMUNICATION_AFTER;
   modul_configuration.event_id_file = DEFAULT_EVENT_ID_FILE;
   modul_configuration.log_file = NULL;

   // Parse remaining parameters and get configuration
   char opt;

   while ((opt = getopt(argc, argv, "l:d:m:s:p:t:q:x:e:")) != -1) {
      switch (opt) {
         case 'l':
            modul_configuration.log_file = optarg;
            break;
         case 'e':
            if (strcmp(optarg, "disabled") == 0) {
               modul_configuration.event_id_file = NULL;
            } else {
               modul_configuration.event_id_file = optarg;
            }
            break;
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
            return 1;
      }
   }

   PRINT_OUT_LOG("-----------------------------------------------------\n");
   PRINT_OUT_LOG("Start VoIP fraud detection module (version:", MODULE_VERSION, ") ...\n");
   PRINT_OUT_LOG("   Module configuration:\n");
   PRINT_OUT_LOG("    - max_prefix_length=", uint_to_str(modul_configuration.max_prefix_length), "\n");
   PRINT_OUT_LOG("    - min_length_called_number=", uint_to_str(modul_configuration.min_length_called_number), "\n");
   PRINT_OUT_LOG("    - prefix_examination_detection_threshold=", uint_to_str(modul_configuration.prefix_examination_detection_threshold), "\n");
   PRINT_OUT_LOG("    - detection_interval=", uint_to_str(modul_configuration.detection_interval), "\n");
   PRINT_OUT_LOG("    - detection_pause_after_attack=", uint_to_str(modul_configuration.detection_pause_after_attack), "\n");
   PRINT_OUT_LOG("    - max_item_prefix_tree=", uint_to_str(modul_configuration.max_item_prefix_tree), "\n");
   PRINT_OUT_LOG("    - clear_data_no_communication_after=", uint_to_str(modul_configuration.clear_data_no_communication_after), "\n");

   // print event_id file settings
   PRINT_OUT_LOG("    - event_id file=");
   if (modul_configuration.event_id_file == NULL) {
      PRINT_OUT_LOG_NOTDATETIME("disabled\n");
   } else {
      PRINT_OUT_LOG_NOTDATETIME("\"", modul_configuration.event_id_file, "\"\n");
   }

   // print log filename, if is set
   if (modul_configuration.log_file != NULL) {
      PRINT_OUT_LOG("    - log file:\"", modul_configuration.log_file, "\"\n");
   }
   PRINT_OUT_LOG("-----------------------------------------------------\n");

   // ***** Create UniRec templates *****

   ur_template_in = ur_create_template(UNIREC_INPUT_TEMPLATE);
   ur_template_out = ur_create_template(UNIREC_OUTPUT_TEMPLATE);

   // check of template creation
   if (ur_template_in == NULL || ur_template_out == NULL) {
      PRINT_ERR("Error: Invalid UniRec specifier!\n");
      TRAP_DEFAULT_FINALIZATION();
      return RETURN_ERROR;
   }

   // prepare detection record
   detection_record = ur_create(ur_template_out, 0);

   // check of detection record
   if (detection_record == NULL) {
      PRINT_ERR("Error: No memory available for detection record!\n");
      ur_free_template(ur_template_in);
      ur_free_template(ur_template_out);
      ur_free(detection_record);
      TRAP_DEFAULT_FINALIZATION();
      return RETURN_ERROR;
   }

   // ***** Main processing loop *****

   // initialize hash table for IP addresses
   cc_hash_table_v2_t hash_table_ip;
   ht_init_v2(&hash_table_ip, HASH_TABLE_IP_SIZE, sizeof (ip_item), sizeof (ip_addr_t));

   // save start time module
   time_t time_start_module;
   time(&time_start_module);

   // definition of required variables
   char ip_src_str[20], ip_dst_str[20];
   ip_addr_t * ip_src;
   ip_addr_t * ip_dst;
   char sip_to_orig[MAX_LENGTH_SIP_TO + 1];
   char sip_from_orig[MAX_LENGTH_SIP_FROM + 1];
   char call_id[MAX_LENGTH_CALL_ID + 1];
   int call_id_len;
   char * sip_to, * sip_from;
   int sip_from_len, sip_to_len;

   // load Event ID from file
   load_event_id(modul_configuration.event_id_file);

   // Read data from input, process them and write to output
   while (!stop) {

      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = trap_recv(0, &in_rec, &in_rec_size);
      // Handle possible errors

      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TIMEOUT) {
            continue; // This cannot happen if timeout is not set (it's there just to show what the macro contains)
         } else if (ret == TRAP_E_TERMINATED) {
            break; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
         } else {
            // Some error has occured
            PRINT_ERR("Error: trap_recv() returned ", uint_to_str(ret), " (", trap_last_error_msg, ")\n");
            break;
         }
      }

      // Check size of received data
      if (in_rec_size < ur_rec_static_size(ur_template_in)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            PRINT_ERR("Error: data with wrong size received (expected size: >= ", ushortint_to_str(ur_rec_static_size(ur_template_in)), ", received size: ", ushortint_to_str(in_rec_size), ")\n");
            break;
         }
      }

      // PROCESS THE DATA

      // memory management of module: check and free memory
      check_and_free_module_memory(&hash_table_ip);

      // get type of packet
      uint8_t voip_packet_type;
      voip_packet_type = ur_get(ur_template_in, in_rec, UR_INVEA_VOIP_PACKET_TYPE);

      // if voip_packet_type is monitored
      if (voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED \
           || voip_packet_type == VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED \
           || voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_CALL_ORIENTED) {

         prefix_tree_domain_t * prefix_tree_node;
         ip_item * hash_table_item;

         // get source IP (unirec)
         ip_src = &ur_get(ur_template_in, in_rec, UR_SRC_IP);
         ip_to_str(ip_src, ip_src_str);

         // get destination IP (unirec)
         ip_dst = &ur_get(ur_template_in, in_rec, UR_DST_IP);
         ip_to_str(ip_dst, ip_dst_str);

         // get SIP_FROM from UniRec
         get_string_from_unirec(sip_from_orig, &sip_from_len, UR_INVEA_SIP_CALLING_PARTY, MAX_LENGTH_SIP_FROM);

         // get SIP_TO from UniRec
         get_string_from_unirec(sip_to_orig, &sip_to_len, UR_INVEA_SIP_CALLED_PARTY, MAX_LENGTH_SIP_TO);

         // get Call-ID from UniRec
         get_string_from_unirec(call_id, &call_id_len, UR_INVEA_SIP_CALL_ID, MAX_LENGTH_CALL_ID);

         // ?
         uint16_t src_port, dst_port;
         src_port = ur_get(ur_template_in, in_rec, UR_SRC_PORT);
         dst_port = ur_get(ur_template_in, in_rec, UR_DST_PORT);

         // cut "sip:" or "sips:" from sip_to and sip_from
         int invalid_sipto = cut_sip_identifier_from_string(&sip_to, sip_to_orig, &sip_to_len);
         int invalid_sipfrom = cut_sip_identifier_from_string(&sip_from, sip_from_orig, &sip_from_len);

#ifdef PRINT_DETAIL_INVALID_SIPURI
         if (invalid_sipto == -1 || invalid_sipfrom == -1) {

            if (invalid_sipto == -1) {
               PRINT_OUT("SIP_TO header is invalid:\"", sip_to_orig, "\"; ");
            }

            if (invalid_sipfrom == -1) {
               PRINT_OUT("SIP_FROM header is invalid:\"", sip_from_orig, "\"; ");
            }

            // get id of monitoring probes
            uint64_t link_bit_field;
            link_bit_field = ur_get(ur_template_in, in_rec, UR_LINK_BIT_FIELD);

            PRINT_OUT_NOTDATETIME(" LINK_BIT_FIELD: ", uint_to_str(link_bit_field), "; ");
            PRINT_OUT_NOTDATETIME("SRC_IP: ", ip_src_str, "; DST_IP: ", ip_dst_str, "; voip_packet_type: ", uint_to_str(voip_packet_type), "; ");
            PRINT_OUT_NOTDATETIME("SRC_PORT: ", uint_to_str(src_port), "; ");
            PRINT_OUT_NOTDATETIME("DST_PORT: ", uint_to_str(dst_port), "\n");
         }
#endif

         // RTP data
         if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) != NULL) {

            // search sip_to in prefix tree
            prefix_tree_node = prefix_tree_search(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

            // check if node exists
            if (prefix_tree_node != NULL) {

               // check of successful initialization of node data
               if (check_initialize_node_data(prefix_tree_node) == -1) continue;

               if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {
                  // set rtp_data=1, if some packets are in the flow record
                  if (ur_get(ur_template_in, in_rec, UR_INVEA_RTCP_PACKETS) > 0 && ur_get(ur_template_in, in_rec, UR_INVEA_RTCP_OCTETS) > 0) {
                     ((node_data *) (prefix_tree_node->parent->value))->rtp_data = 1;
                  }
               }
            }
         }

         // check if sip_to is numeric with allowed special char ('+','*','#') or this text part before '@' + check of minimum numeric length
         if (!is_numeric_participant(sip_to, sip_to_len)) continue;

         // do action according to voip_packet_type
         switch (voip_packet_type) {

            case VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED:
            {
               /* --------------------------------
                * request type: call oriented
                * -------------------------------- */

               // get SIP_STATS from UniRec
               uint64_t sip_stats;
               sip_stats = ur_get(ur_template_in, in_rec, UR_INVEA_SIP_STATS);

               uint32_t invite_stats;
               uint16_t bye_stats;
               uint8_t ack_stats, cancel_stats;

               // get number of INVITE requests in the flow record
               // same as: invite_stats = (uint32_t) (sip_stats & 0x00000000ffffffff);
               invite_stats = (uint32_t) sip_stats;

               // get number of CANCEL, ACK and BYE requests in the flow record (other_stats = sip_stats>>32;)
               cancel_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
               ack_stats = (uint8_t) ((sip_stats & 0x00ff000000000000) >> 48);
               bye_stats = (uint16_t) ((sip_stats & 0x0000ffff00000000) >> 32);

               // if at least one INVITE requests is in flow record
               if (invite_stats > 0) {
                  // add one to statistics of number invite flow
                  global_module_statistic.received_invite_flow_count++;
               }

               // is source IP in hash table?
               if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) == NULL) {

                  /* IP address not found in hash table */

                  // if it isn't INVITE request, don't create item in hash table
                  if (invite_stats == 0) continue;

                  // create and initialize hash_table_item
                  hash_table_item = (ip_item *) malloc(sizeof (ip_item));

                  // check successful allocation memory
                  if (hash_table_item == NULL) {
                     PRINT_ERR("hash_table_item: Error memory allocation\n");
                     continue;
                  }

                  // initialize prefix_tree
                  hash_table_item->tree = prefix_tree_initialize(SUFFIX, 0, -1, DOMAIN_EXTENSION_NO, RELAXATION_AFTER_DELETE_YES);

                  // check successful allocation memory
                  if (hash_table_item->tree == NULL) {
                     PRINT_ERR("hash_table_item->tree: prefix_tree_initialize: Error memory allocation\n");
                     continue;
                  }

                  // initialize other variables of hash_table_item
                  time(&(hash_table_item->first_invite_request));
                  hash_table_item->time_last_check = time_start_module;
                  hash_table_item->time_last_communication = time_start_module;
                  hash_table_item->time_attack_detected_prefix_examination = 0;
                  hash_table_item->detection_event_count = 0;
                  hash_table_item->attack_detected_count = 0;
                  hash_table_item->attack_event_id = 0;
                  hash_table_item->attack_prefix_length = 0;
                  hash_table_item->attack_sip_to = NULL;

                  // insert into hash table
                  if (ht_insert_v2(&hash_table_ip, (char *) ip_src->bytes, (void *) hash_table_item) != NULL) {
#ifdef TEST_DEBUG
                     PRINT_OUT("Hash table reaches size limit\n");
#endif
                  }

                  // free temporary hash_table_item
                  free(hash_table_item);

                  // get new pointer of hash_table_item from hash table
                  hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes));

               } else {
                  // IP is in hash_table

                  // save time of first INVITE request for the IP address
                  if ((int) hash_table_item->first_invite_request == 0) {
                     time(&(hash_table_item->first_invite_request));
                  }
               }

               // get actual time
               time_t time_actual;
               time(&time_actual);

               // check if detection interval was expired
               if (difftime(time_actual, hash_table_item->time_last_check) >= modul_configuration.detection_interval) {

                  // check if detection_pause_after_attack was expired
                  if (difftime(time_actual, hash_table_item->time_attack_detected_prefix_examination) >= modul_configuration.detection_pause_after_attack) {

                     /* >>>>>>>>>> DETECTION PART >>>>>>>>>> */

                     // clear cache_node_no_attack
                     cache_node_no_attack_clear();

                     int status_detection;

                     // call detection of prefix examination attack
                     status_detection = detect_prefix_examination(hash_table_item->tree, hash_table_item->tree->root);

                     if (status_detection == STATE_ATTACK_DETECTED) {

                        uint32_t event_id;

                        // Write attack information to stdout and log ...
                        PRINT_OUT_LOG("==> Detected Prefix Examination");

                        // check if attack continue or the new attack will be reported
                        if (hash_table_item->attack_event_id != 0 \
                             && hash_table_item->attack_sip_to != NULL \
                             && strcmp(detection.sip_to + detection.report_prefix_length, \
                                       hash_table_item->attack_sip_to + hash_table_item->attack_prefix_length) == 0) {
                           // last attack continues

                           event_id = hash_table_item->attack_event_id;

                           PRINT_OUT_LOG_NOTDATETIME(" (continuation)");

                        } else {
                           // new attack

                           // increment event_id
                           last_event_id++;

                           event_id = last_event_id;

                           // save attack detection prefix_examination
                           hash_table_item->attack_detected_count++;

                           // add one to statistics of number attacks
                           global_module_statistic.attack_detected_count++;
                        }

                        // save attack detection prefix_examination
                        hash_table_item->detection_event_count++;

                        // add one to statistics of number detection events
                        global_module_statistic.detection_event_count++;

                        // ... next attack information to stdout and log ...
                        PRINT_OUT_LOG_NOTDATETIME("!; event_id=", uint_to_str(event_id), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("detection_time=\"", time_t_to_str(detection.time), "\"; ");
                        PRINT_OUT_LOG_NOTDATETIME("timeslot=\"", time_t_to_str(hash_table_item->first_invite_request), "\"; ");
                        PRINT_OUT_LOG_NOTDATETIME("SRC_IP=", ip_src_str, "; ");
                        PRINT_OUT_LOG_NOTDATETIME("SIP_TO=\"", detection.sip_to, "\"; ");
                        PRINT_OUT_LOG_NOTDATETIME("prefix_length=", uint_to_str(detection.report_prefix_length), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("prefix_examination_count=", uint_to_str(detection.prefix_examination_count), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("successful_call_count=", uint_to_str(detection.unique_ok), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("invite_count=", uint_to_str(detection.invite), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("IP_detection_event_count=", uint_to_str(hash_table_item->detection_event_count), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("IP_attack_detected_count=", uint_to_str(hash_table_item->attack_detected_count), " <== # ");

                        // test output ...
                        PRINT_OUT_LOG_NOTDATETIME("count_rtcp_data=", uint_to_str(detection.rtcp_data), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("count_ack=", uint_to_str(detection.ack), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("count_cancel=", uint_to_str(detection.cancel), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("count_bye=", uint_to_str(detection.bye), "; ");
                        PRINT_OUT_LOG_NOTDATETIME("count_trying=", uint_to_str(detection.trying), "; ");

                        if (detection.ok > 0) {
                           PRINT_OUT_LOG_NOTDATETIME("alert! count_detection_value_ok=", uint_to_str(detection.ok), "; ");
                           PRINT_OUT_LOG_NOTDATETIME("unique_ok=", uint_to_str(detection.unique_ok), "; ");
                        }

                        if (detection.ringing > 0) {
                           PRINT_OUT_LOG_NOTDATETIME("count_detection_value_ringing=", uint_to_str(detection.ringing), "; ");
                        }

                        if (detection.service_ok > 0) {
                           PRINT_OUT_LOG_NOTDATETIME("alert! count_detection_value_service_ok=", uint_to_str(detection.service_ok), "; ");
                        }

                        if (detection.forbidden > 0) {
                           PRINT_OUT_LOG_NOTDATETIME("count_detection_value_forbidden=", uint_to_str(detection.forbidden), "; ");
                        }

                        if (detection.unauthorized > 0) {
                           PRINT_OUT_LOG_NOTDATETIME("count_detection_value_unauthorized=", uint_to_str(detection.unauthorized), "; ");
                        }

                        if (detection.proxy_auth_req > 0) {
                           PRINT_OUT_LOG_NOTDATETIME("count_detection_value_proxy_auth_req=", uint_to_str(detection.proxy_auth_req), "; ");
                        }

                        PRINT_OUT_LOG_NOTDATETIME("\n");

                        // Send attack information to output interface

                        // fill in fields of detection event
                        ur_set(ur_template_out, detection_record, UR_EVENT_ID, event_id);
                        ur_set(ur_template_out, detection_record, UR_EVENT_TYPE, UR_EVT_T_VOIP_PREFIX_GUESS);
                        ur_set(ur_template_out, detection_record, UR_SRC_IP, *ip_src);
                        ur_set(ur_template_out, detection_record, UR_DETECTION_TIME, ur_time_from_sec_msec(detection.time, 0));
                        ur_set(ur_template_out, detection_record, UR_TIME_FIRST, ur_time_from_sec_msec(hash_table_item->first_invite_request, 0));
                        ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_SIP_TO, detection.sip_to, sizeof (char) * (strlen(detection.sip_to) + 1)); // '\0' at the end of dynamic field is recommended
                        ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_PREFIX_LENGTH, detection.report_prefix_length);
                        ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_PREFIX_EXAMINATION_COUNT, detection.prefix_examination_count);
                        ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_SUCCESSFUL_CALL_COUNT, detection.unique_ok);
                        ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_INVITE_COUNT, detection.invite);

                        // send alert to output interface
                        int return_code = trap_send(0, detection_record, ur_rec_size(ur_template_out, detection_record));
                        TRAP_DEFAULT_SEND_ERROR_HANDLING(return_code,;, PRINT_ERR("Error during sending", UNIREC_OUTPUT_TEMPLATE, " to output interface!\n"););

                        // save attack information to hash_table_item
                        hash_table_item->attack_event_id = event_id;
                        hash_table_item->attack_prefix_length = detection.report_prefix_length;

                        // check allocation of attack_sip_to
                        if (hash_table_item->attack_sip_to == NULL) {
                           hash_table_item->attack_sip_to = (char *) malloc(sizeof (char) * (MAX_STRING_PREFIX_TREE_NODE + 1));
                        }

                        // check of successful allocation memory
                        if (hash_table_item->attack_sip_to == NULL) {
                           PRINT_ERR("hash_table_item->attack_sip_to: Error memory allocation\n");
                        } else {
                           strncpy(hash_table_item->attack_sip_to, detection.sip_to, MAX_STRING_PREFIX_TREE_NODE);
                        }

                        // save event_id to file
                        save_event_id(modul_configuration.event_id_file);

                        // update time of last attack
                        time(&(hash_table_item->time_attack_detected_prefix_examination));

                     }

                     // save last detection time
                     time(&(hash_table_item->time_last_check));

#ifdef TEST_DEBUG
                     if (hash_table_item->tree->root->count_of_string > 5000) printf("count_of_root: %i; IP: %s; cache_size: %i;\n", hash_table_item->tree->root->count_of_string, ip_src_str, cache_node_no_attack_size);
#endif

                     /* <<<<<<<<<< DETECTION PART <<<<<<<<<< */

                  }

               }



#ifdef DEBUG
               // if at least one INVITE requests is in flow record
               if (invite_stats > 0) {

                  char *sip_via;
                  int sip_via_len;

                  sip_via_len = ur_get_dyn_size(ur_template_in, in_rec, UR_INVEA_SIP_VIA);
                  sip_via = ur_get_dyn(ur_template_in, in_rec, UR_INVEA_SIP_VIA);

                  uint64_t link_bit_field;
                  link_bit_field = ur_get(ur_template_in, in_rec, UR_LINK_BIT_FIELD);

                  printf("Via: %.*s\n", sip_via_len, sip_via);

                  printf("%s;IP_SRC:%s;IP_DST:%s;LINK_BIT_FIELD: %u; INVITE: SIP_FROM:\"%.*s\";\n", get_actual_time_string(), ip_src_str, ip_dst_str, link_bit_field, sip_from_len, sip_from);
                  printf("%s;IP_SRC:%s;IP_DST:%s;LINK_BIT_FIELD: %u; INVITE: SIP_TO:\"%.*s\"; ", get_actual_time_string(), ip_src_str, ip_dst_str, link_bit_field, sip_to_len, sip_to);

                  char tmp_sip_to[200];
                  strncpy(tmp_sip_to, sip_to, sip_to_len);
                  tmp_sip_to[sip_to_len] = '\0';
                  if (strstr(tmp_sip_to, ip_dst_str) == NULL) {
                     printf("otherIPMark");
                  }
                  printf("\n");

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
               if (check_initialize_node_data(prefix_tree_node) == -1) continue;

               if (invite_stats > 0) {
                  // save Call-ID to node_data
                  call_id_node_data_save(prefix_tree_node, call_id, call_id_len);

                  // sum stats
                  ((node_data *) (prefix_tree_node->parent->value))->invite_count += invite_stats;
                  ((node_data *) (prefix_tree_node->parent->value))->cancel_count += cancel_stats;
                  ((node_data *) (prefix_tree_node->parent->value))->ack_count += ack_stats;
                  ((node_data *) (prefix_tree_node->parent->value))->bye_count += bye_stats;
               } else {
                  if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {
                     // sum stats
                     ((node_data *) (prefix_tree_node->parent->value))->cancel_count += cancel_stats;
                     ((node_data *) (prefix_tree_node->parent->value))->ack_count += ack_stats;
                     ((node_data *) (prefix_tree_node->parent->value))->bye_count += bye_stats;
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
               if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_dst->bytes))) != NULL) {

                  // search sip_to in prefix tree
                  prefix_tree_node = prefix_tree_search(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

                  // if node isn't found, ignore it
                  if (prefix_tree_node == NULL) continue;

                  // check of successful initialization of node data
                  if (check_initialize_node_data(prefix_tree_node) == -1) continue;

                  // check if Call-ID is saved in node_data
                  if (call_id_node_data_exists(prefix_tree_node, call_id, call_id_len) == 1) {

                     // get SIP_STATS from UniRec
                     uint64_t sip_stats;
                     sip_stats = ur_get(ur_template_in, in_rec, UR_INVEA_SIP_STATS);

                     if (voip_packet_type == VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED) {

                        /* --------------------------------
                         * response type: service oriented
                         * -------------------------------- */

                        // get number of service_ok responses in the flow record
                        uint8_t service_ok_stats, forbidden_stats, unauthorized_stats;
                        service_ok_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
                        forbidden_stats = (uint8_t) ((sip_stats & 0x0000ff0000000000) >> 40);
                        unauthorized_stats = (uint8_t) ((sip_stats & 0x000000000000ff00) >> 8);

                        // sum stats
                        ((node_data *) (prefix_tree_node->parent->value))->service_ok_count += service_ok_stats;

#ifdef DEBUG
                        global_sip_statistic.service_ok_count += service_ok_stats;
                        global_sip_statistic.forbidden_count += forbidden_stats;
                        global_sip_statistic.unauthorized_count += unauthorized_stats;
#endif
                     } else {

                        /* --------------------------------
                         * response type: call oriented
                         * -------------------------------- */

                        // get number of OK, RINGING, TRYING and PROXY AUTH REQUEST responses in the flow record
                        uint8_t ok_stats, ringing_stats, proxy_auth_req_stats, trying_stats;
                        ok_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
                        ringing_stats = (uint8_t) ((sip_stats & 0x0000ff0000000000) >> 40);
                        proxy_auth_req_stats = (uint8_t) ((sip_stats & 0x000000000000ff00) >> 8);
                        trying_stats = (uint8_t) (sip_stats & 0x00000000000000ff);

                        // sum stats
                        ((node_data *) (prefix_tree_node->parent->value))->ok_count += ok_stats;
                        ((node_data *) (prefix_tree_node->parent->value))->ringing_count += ringing_stats;
                        ((node_data *) (prefix_tree_node->parent->value))->proxy_auth_req_count += proxy_auth_req_stats;
                        ((node_data *) (prefix_tree_node->parent->value))->trying_count += trying_stats;

#ifdef DEBUG
                        global_sip_statistic.ok_count += ok_stats;
                        global_sip_statistic.ringing_count += ringing_stats;
                        global_sip_statistic.proxy_auth_req_count += proxy_auth_req_stats;
                        global_sip_statistic.trying_count += trying_stats;
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

   // print statistics
   PRINT_OUT_LOG("-----------------------------------------------------\n");
   PRINT_OUT_LOG("Total module statistics:\n");
   PRINT_OUT_LOG("   - detection_event=", uint_to_str(global_module_statistic.detection_event_count), "\n");
   PRINT_OUT_LOG("   - attack_detected=", uint_to_str(global_module_statistic.attack_detected_count), "\n");
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
   PRINT_OUT_LOG("   - service_ok_count=", uint_to_str(global_sip_statistic.service_ok_count), "\n");
   PRINT_OUT_LOG("   - forbidden_count=", uint_to_str(global_sip_statistic.forbidden_count), "\n");
   PRINT_OUT_LOG("   - unauthorized_count=", uint_to_str(global_sip_statistic.unauthorized_count), "\n");
   PRINT_OUT_LOG("   - proxy_auth_req_count=", uint_to_str(global_sip_statistic.proxy_auth_req_count), "\n");
#endif

#ifdef TEST_DEBUG
   // only for testing
   printf(" | count_cache_hit: %i\n", test_cache_hit);
   printf(" | count_cache_not_hit: %i\n", test_cache_not_hit);
   printf(" | count_cache_save: %i\n", test_cache_save);
   printf(" | count_cache_delete_successor: %i\n", test_cache_delete_successor);

   printf(" | count:test_call_id_node_data_exists: %i\n", test_call_id_node_data_exists);
   printf(" | count:test_call_id_node_data_not_exists: %i\n", test_call_id_node_data_not_exists);
   printf(" | count:test_call_id_node_data_save: %i\n", test_call_id_node_data_save);
#endif

   // ***** Cleanup *****

   PRINT_OUT_LOG("Module cleanup-1!\n");

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   PRINT_OUT_LOG("Module cleanup-2!\n");

   // free memory - destroy tree for all IP addresses
   ip_item * hash_table_item;
   for (int i = 0; i < hash_table_ip.table_size; i++) {
      if (hash_table_ip.ind[i].valid) {
         hash_table_item = (ip_item *) hash_table_ip.data[hash_table_ip.ind[i].index];
         prefix_tree_destroy(hash_table_item->tree);
         if (hash_table_item->attack_sip_to != NULL) free(hash_table_item->attack_sip_to);
      }
   }

   PRINT_OUT_LOG("Module cleanup-3!\n");

   // destroy hash table (free memory)
   ht_destroy_v2(&hash_table_ip);

   PRINT_OUT_LOG("Module cleanup-4!\n");

   // destroy templates (free memory)
   ur_free_template(ur_template_in);
   ur_free_template(ur_template_out);
   ur_free(detection_record);

   PRINT_OUT_LOG("... VoIP fraud detection module exit! (version:", MODULE_VERSION, ")\n");
   PRINT_OUT_LOG("-----------------------------------------------------\n");

   return RETURN_OK;
}
