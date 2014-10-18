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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <signal.h>
#include <ctype.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <unistd.h>

#include <prefix_tree.h>
#include <nemea-common.h>

#include "voip_fraud_detection.h"

// Struct with information about module
trap_module_info_t module_info = {
   "VoIP-fraud-detection module", // Module name
   // Module description
   "This module detecting fraud in VoIP telephony, especially in SIP communication.\n"
   "It detects:\n"
   " - prefix enumeration\n"
   "\n"
   "Optional parameters:\n"
   "   -l  : path to log file\n"
   "   -m  : max_prefix_length\n"
   "   -d  : minimum length of called number\n"
   "   -s  : detection interval in seconds\n"
   "   -t  : prefix_examination_detection_threshold\n"
   "   -p  : detection_pause_after_attack in seconds\n"
   "\n"
   "Interfaces:\n"
   "   Inputs: 1 (SIP records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};


static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);


// variables for saving modul configuration
unsigned int max_prefix_length;
unsigned int min_length_called_number;
unsigned int prefix_examination_detection_threshold;
unsigned int detection_interval;
unsigned int detection_pause_after_attack;
char * log_file = NULL;

// global statistics
unsigned int statistic_num_attack_detected = 0;
unsigned long long statistic_num_invite_flow = 0;
unsigned int statistic_num_invalid_sip_identifier = 0;

// detection statistics
int detection_value_invite;
int detection_value_ack;
int detection_value_cancel;
int detection_value_bye;
int detection_value_ok;
int detection_value_trying;
int detection_value_ringing;
int detection_value_service_ok;
int detection_value_rtcp_data;

// only for testing variables
int testvar_ok_count = 0;
int testvar_ack_count = 0;
int testvar_cancel_count = 0;
int testvar_bye_count = 0;
int testvar_invite_count = 0;

// UniRec template
ur_template_t *template;
const void *in_rec;

// Return actual date and time in system default format

char * get_actual_time_string()
{
   time_t actual_time;
   struct tm *local_time;

   // get actual local time
   time(&actual_time);
   local_time = localtime(&actual_time);
   char * result = asctime(local_time);

   // remove newline from end of string
   result[strlen(result) - 1] = '\0';

   return result;
}

// Convert integer to char array (string)

char * inttostr(int integer)
{
   static char string [LENGTH_BUFFER_INTTOSTR];
   sprintf(string, "%d", integer);
   return string;
}

// Print error information on error output

void print_error(int error_number, char * error_description)
{
   fprintf(stderr, LOG_ERROR_PREFIX);
   fprintf(stderr, "%i:%s", error_number, error_description);
   fprintf(stderr, "\n");
}

// Write input strings to log file (variadic funtion)

void write_to_log(char * str, ...)
{

   // check if log_file is set (configuration of module)
   if (log_file != NULL) {

      va_list parameters;
      char * parameter;

      static FILE * io_log_file;

      // open log file (append, text mode)
      io_log_file = fopen(log_file, "at");
      if (io_log_file == NULL) {
         fprintf(stderr, "Error open log file: %s!\n", log_file);
         return;
      }

      // set first parameter
      parameter = str;

      // initialization of parameters list
      va_start(parameters, str);

      // write parameters to log file
      while (parameter != NULL) {
         fprintf(io_log_file, "%s", parameter);
         parameter = va_arg(parameters, char*);
      }

      // close log file
      fclose(io_log_file);

      // end using variable parameters list
      va_end(parameters);
   }
}

// Write input strings to standard output (variadic function)

void write_std(char * str, ...)
{
   va_list parameters;
   char * parameter;

   // set first parameter
   parameter = str;

   // initialization of parametres list
   va_start(parameters, str);

   // write parameters to standard output
   while (parameter != NULL) {
      printf("%s", parameter);
      parameter = va_arg(parameters, char*);
   }

   // end using variable parameters list
   va_end(parameters);
}

// cache_no_attack
prefix_tree_inner_node_t * cache_no_attack_data[MAX_CACHE_NO_ATTACK_SIZE];
int cache_no_attack_size = 0;

// testing variables
int write_cache_limit_info = 0;
int test_cache_hit = 0;
int test_cache_not_hit = 0;
int test_cache_save = 0;
int test_cache_delete_successor = 0;

// Find if node is verified for no attack by cache
// Return 1 if node exists in cache, 0 otherwise

int cache_no_attack_exists(prefix_tree_inner_node_t * node)
{
   // try to find node in cache
   int i;
   for (i = 0; i < cache_no_attack_size; i++) {
      if (cache_no_attack_data[i] == node) return 1;
   }

   // try to find predecessor of node in cache
   if (node != NULL) {
      if (node->parent != NULL) return cache_no_attack_exists(node->parent);
   }

   // node not found => return 0
   return 0;
}

// Save pointer of node into cache

void cache_no_attack_save(prefix_tree_inner_node_t * node)
{
   static int full_index = 0;

   // clear successors of the node in cache
   int i;
   prefix_tree_inner_node_t * predecessor_node;

   for (i = 0; i < cache_no_attack_size; i++) {
      predecessor_node = cache_no_attack_data[i]->parent;

      while (predecessor_node != NULL) {
         if (predecessor_node == node) {

            // delete cache_no_attack_data[i] from cache
            cache_no_attack_size--;
            if (cache_no_attack_size > 0) {
               cache_no_attack_data[i] = cache_no_attack_data[cache_no_attack_size];
            }

            test_cache_delete_successor++;
         }
         predecessor_node = predecessor_node->parent;
      }

   }

   // save the node to cache
   if (cache_no_attack_size >= MAX_CACHE_NO_ATTACK_SIZE) {
      cache_no_attack_data[full_index] = node;
      full_index++;
      if (full_index >= MAX_CACHE_NO_ATTACK_SIZE) full_index = 0;

      // only testing info
      if (write_cache_limit_info == 0) {
         printf("cache limit!!!\n");
         write_cache_limit_info = 1;
      }

   } else {
      cache_no_attack_data[cache_no_attack_size] = node;
      cache_no_attack_size++;
   }

}

// Clear cache

void cache_no_attack_clear()
{
   cache_no_attack_size = 0;
}

// Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' + string after it

int cut_sip_identifier_from_string(char ** output_str, char * input_str, int * str_len, char * input_description)
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

         // not valid sip identifier

#ifdef DEBUG
         uint64_t link_bit_field;
         link_bit_field = ur_get(template, in_rec, UR_LINK_BIT_FIELD);

         PRINT_STD_LOG(input_description, " is invalid:\"");
         PRINT_STD_LOG_NOTDATETIME(input_str, "\";");
         PRINT_STD_LOG_NOTDATETIME("LINK_BIT_FIELD:", inttostr(link_bit_field), ";");
#endif

         statistic_num_invalid_sip_identifier++;

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
   if (char_index < min_length_called_number) return 0;

   return is_numeric;
}


// Initialize node_data defined by input parameter

int check_initialize_node_data(prefix_tree_domain_t * prefix_tree_node, uint8_t voip_packet_type)
{
   // check if input prefix_tree_node has not allocate memory
   if (prefix_tree_node->parent->value == NULL) {

      // allocate memory for node data
      prefix_tree_node->parent->value = (void *) malloc(sizeof (node_data));

      // check successful allocation memory
      if (prefix_tree_node->parent->value == NULL) {
         PRINT_STD_LOG("initialize_node_data(voip_packet_type:", inttostr(voip_packet_type), "): error memory allocation\n");
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

      ((node_data *) (prefix_tree_node->parent->value))->rtp_data = 0;
   }

   return 0;
}

// Function to thorough count of prefix detection minus value

unsigned int count_minus_detection_value(prefix_tree_t * tree, prefix_tree_inner_node_t * node, int sum_prefix_down)
{
   unsigned int result = 0;
   int stop_tree_walk = 0;

   // checking if node has data
   if (node->value != NULL) {
      if (((node_data *) (node->value))->invite_count <= ((node_data *) (node->value))->ok_count) {
         // incrementation result by one
         result += 1;
      }

      detection_value_invite += ((node_data *) (node->value))->invite_count;
      detection_value_cancel += ((node_data *) (node->value))->cancel_count;
      detection_value_ack += ((node_data *) (node->value))->ack_count;
      detection_value_bye += ((node_data *) (node->value))->bye_count;
      detection_value_ok += ((node_data *) (node->value))->ok_count;
      detection_value_trying += ((node_data *) (node->value))->trying_count;
      detection_value_ringing += ((node_data *) (node->value))->ringing_count;
      detection_value_service_ok += ((node_data *) (node->value))->service_ok_count;

      detection_value_rtcp_data += ((node_data *) (node->value))->rtp_data;
   }

   // checking of max_prefix_length
   char str [MAX_STRING_PREFIX_TREE_NODE + 1];
   prefix_tree_read_inner_node(tree, node, str);
   sum_prefix_down += strlen(str);

   if (sum_prefix_down > max_prefix_length) {
      result += node->count_of_string;
      stop_tree_walk = 1;
   }

   if (node->child != NULL && stop_tree_walk != 1) {

      // node is an inner node
      int i;
      for (i = 0; i < COUNT_OF_LETTERS_IN_DOMAIN; i++) {
         if (node->child[i] != NULL) {

            // recursive call
            result += count_minus_detection_value(tree, node->child[i], sum_prefix_down);
         }
      }
   }

   return result;
}

// Detection prefix examination in input prefix tree,
// if attack is detected delete node and his descendants

int detect_prefix_examination(prefix_tree_t * tree, prefix_tree_inner_node_t * node)
{
   // check if node is in cache
   if (cache_no_attack_exists(node)) {
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

      while (prefix_sum_length <= max_prefix_length) {

         prefix_tree_read_inner_node(tree, predecessor_node, str);

         // check if not node string contains '@' prior max_prefix_length position
         char * at_pointer = strstr(str, "@");
         if (at_pointer != NULL) {
            if (!(prefix_sum_length + (at_pointer - str) <= max_prefix_length)) break;
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
      if (prefix_sum_count > prefix_examination_detection_threshold) {

         // check if node is not in cache
         if (cache_no_attack_exists(predecessor_node) == 1) {
            test_cache_hit++;
            return STATE_NO_ATTACK;
         } else {
            test_cache_not_hit++;
         }

         // reset detection statistics
         detection_value_invite = 0;
         detection_value_ack = 0;
         detection_value_cancel = 0;
         detection_value_bye = 0;
         detection_value_ok = 0;
         detection_value_trying = 0;
         detection_value_ringing = 0;
         detection_value_service_ok = 0;
         detection_value_rtcp_data = 0;

         // thorough count of prefix detection
         unsigned int minus_detection_value = count_minus_detection_value(tree, last_predecessor_node, 0);

         // decrement prefix_sum_count by minus detection value
         if (prefix_sum_count <= minus_detection_value) {
            prefix_sum_count = 0;
         } else {
            prefix_sum_count -= minus_detection_value;
         }

         // check if prefix_sum_count exceeds threshold after recalculation
         if (prefix_sum_count > prefix_examination_detection_threshold) {

            // attack detected

#ifdef DEBUG
            // testing
            printf("count_minus %i; prefix_sum_count_original: %i; total_sum_after_descrease: %i;\n", minus_detection_value, prefix_sum_count + minus_detection_value, prefix_sum_count);
#endif

            char sip_to[MAX_STRING_PREFIX_TREE_NODE + 1];

            // initialize sip_to string
            sip_to[0] = '\0';

            // set predecessor_node as leaf node
            predecessor_node = node;

            // compose one of sip_to uri from prefix attack
            while (predecessor_node != NULL) {
               prefix_tree_read_inner_node(tree, predecessor_node, str);
               strcat(sip_to, "|");
               strcat(sip_to, str);
               predecessor_node = predecessor_node->parent;
            }

            PRINT_STD_LOG("==> Detected Prefix Examination (sip_to:\"", sip_to, "\")");
            PRINT_STD_LOG_NOTDATETIME("(prefix_sum_count=", inttostr(prefix_sum_count), " (>) ");
            PRINT_STD_LOG_NOTDATETIME("threshold=", inttostr(prefix_examination_detection_threshold), ")!!!");

            PRINT_STD_LOG_NOTDATETIME(" count_rtcp_data=", inttostr(detection_value_rtcp_data), ";");
            PRINT_STD_LOG_NOTDATETIME(" count_invite=", inttostr(detection_value_invite), ";");
            PRINT_STD_LOG_NOTDATETIME(" count_ack=", inttostr(detection_value_ack), ";");
            PRINT_STD_LOG_NOTDATETIME(" count_cancel=", inttostr(detection_value_cancel), ";");
            PRINT_STD_LOG_NOTDATETIME(" count_bye= ", inttostr(detection_value_bye), ";");

            if (detection_value_ok > 0) {
               PRINT_STD_LOG_NOTDATETIME("alert! count_detection_value_ok: ", inttostr(detection_value_ok), ";");
            }

            if (detection_value_trying > 0) {
               PRINT_STD_LOG_NOTDATETIME("alert! count_detection_value_trying: ", inttostr(detection_value_trying), ";");
            }

            if (detection_value_ringing > 0) {
               PRINT_STD_LOG_NOTDATETIME("alert! count_detection_value_ringing: ", inttostr(detection_value_ringing), ";");
            }

            if (detection_value_service_ok > 0) {
               PRINT_STD_LOG_NOTDATETIME("alert! count_detection_value_service_ok: ", inttostr(detection_value_service_ok), ";");
            }

#ifdef DEBUG
            // testing
            PRINT_STD_LOG_NOTDATETIME(" before delete:", inttostr(tree->root->count_of_string));
#endif

            // delete node and his descendants from prefix tree
            prefix_tree_delete_inner_node(tree, last_predecessor_node);

#ifdef DEBUG
            // testing
            PRINT_STD_LOG_NOTDATETIME("; after delete:", inttostr(tree->root->count_of_string), ";");
#endif

            return STATE_ATTACK_DETECTED;

         } else {
            // attack not detected, save node to cache
            cache_no_attack_save(last_predecessor_node);
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

// Main

int main(int argc, char **argv)
{
   int ret;

   // ***** TRAP initialization *****

   // Let TRAP library parse command-line arguments and extract its parameters
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // Set default parameters
   min_length_called_number = DEFAULT_MIN_LENGTH_CALLED_NUMBER;
   max_prefix_length = DEFAULT_MAX_PREFIX_LENGTH;
   prefix_examination_detection_threshold = DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD;
   detection_interval = DEFAULT_DETECTION_INTERVAL;
   detection_pause_after_attack = DEFAULT_DETECTION_PAUSE_AFTER_ATTACK;

   // Parse remaining parameters and get configuration
   char opt;

   while ((opt = getopt(argc, argv, "l:d:m:s:p:t:")) != -1) {
      switch (opt) {
         case 'l':
            log_file = optarg;
            break;
         case 'd':
            min_length_called_number = atoi(optarg);
            break;
         case 'm':
            max_prefix_length = atoi(optarg);
            break;
         case 's':
            detection_interval = atoi(optarg);
            break;
         case 'p':
            detection_pause_after_attack = atoi(optarg);
            break;
         case 't':
            prefix_examination_detection_threshold = atoi(optarg);
            break;
         default:
            fprintf(stderr, "Error: Invalid arguments.\n");
            return 1;
      }
   }

   PRINT_STD_LOG("-----------------------------------------------------\n");
   PRINT_STD_LOG("Start VoIP fraud detection module (version:", MODULE_VERSION, ") ...\n");
   PRINT_STD_LOG("   Module configuration:\n");
   PRINT_STD_LOG("    - max_prefix_length=", inttostr(max_prefix_length), "\n");
   PRINT_STD_LOG("    - min_length_called_number=", inttostr(min_length_called_number), "\n");
   PRINT_STD_LOG("    - prefix_examination_detection_threshold=", inttostr(prefix_examination_detection_threshold), "\n");
   PRINT_STD_LOG("    - detection_interval=", inttostr(detection_interval), "\n");
   PRINT_STD_LOG("    - detection_pause_after_attack=", inttostr(detection_pause_after_attack), "\n");
   if (log_file != NULL) {
      PRINT_STD_LOG("    - log file:", log_file, "\n");
   }
   PRINT_STD_LOG("-----------------------------------------------------\n");


   // ***** Create UniRec templates *****

   char *ur_template_specifier = UNIREC_INPUT_TEMPLATE;

   template = ur_create_template(ur_template_specifier);


   // ***** Main processing loop

   // initialize hash table for IP addresses
   cc_hash_table_v2_t hash_table_ip;
   ht_init_v2(&hash_table_ip, HASH_TABLE_IP_SIZE, sizeof (ip_item), sizeof (ip_addr_t));

   // save start time module
   time_t time_start_module;
   time(&time_start_module);

   char sip_to_orig[MAX_LENGTH_SIP_TO + 1];
   char sip_from_orig[MAX_LENGTH_SIP_FROM + 1];
   char * ur_sip_to, * ur_sip_from;
   char * sip_to, * sip_from;
   int sip_from_len, sip_to_len;

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
            fprintf(stderr, "Error: trap_recv() returned %i (%s)\n", ret, trap_last_error_msg);
            break;
         }
      }

      // Check size of received data
      if (in_rec_size < ur_rec_static_size(template)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(template), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA


      // get type of packet
      uint8_t voip_packet_type;
      voip_packet_type = ur_get(template, in_rec, UR_INVEA_VOIP_PACKET_TYPE);

      char ip_src_str[20], ip_dst_str[20];
      ip_addr_t * ip_src;
      ip_addr_t * ip_dst;

      prefix_tree_domain_t * prefix_tree_node;
      ip_item * hash_table_item;


      // if voip_packet_type is monitored
      if (voip_packet_type >= 2 && voip_packet_type <= 4) {

         // get source IP (unirec)
         ip_src = &ur_get(template, in_rec, UR_SRC_IP);
         ip_to_str(ip_src, ip_src_str);

         // get destination IP (unirec)
         ip_dst = &ur_get(template, in_rec, UR_DST_IP);
         ip_to_str(ip_dst, ip_dst_str);

         // get SIP_FROM from UniRec
         sip_from_len = ur_get_dyn_size(template, in_rec, UR_INVEA_SIP_CALLING_PARTY);
         ur_sip_from = ur_get_dyn(template, in_rec, UR_INVEA_SIP_CALLING_PARTY);
         if (sip_from_len > MAX_LENGTH_SIP_FROM) sip_from_len = MAX_LENGTH_SIP_FROM;
         memcpy(sip_from_orig, ur_sip_from, sizeof (char) * sip_from_len);
         sip_from_orig[sip_from_len] = '\0';

         // get SIP_TO from UniRec
         sip_to_len = ur_get_dyn_size(template, in_rec, UR_INVEA_SIP_CALLED_PARTY);
         ur_sip_to = ur_get_dyn(template, in_rec, UR_INVEA_SIP_CALLED_PARTY);
         if (sip_to_len > MAX_LENGTH_SIP_TO) sip_to_len = MAX_LENGTH_SIP_TO;
         memcpy(sip_to_orig, ur_sip_to, sizeof (char) * sip_to_len);
         sip_to_orig [sip_to_len] = '\0';

         uint16_t src_port, dst_port;
         src_port = ur_get(template, in_rec, UR_SRC_PORT);
         dst_port = ur_get(template, in_rec, UR_DST_PORT);

         // cut "sip:" or "sips:" from sip_to and sip_from
         if (cut_sip_identifier_from_string(&sip_to, sip_to_orig, &sip_to_len, "SIP_TO header") == -1) {

#ifdef TEST_DEBUG
            // temporary testing output ...

            PRINT_STD_LOG_NOTDATETIME("Invalid src_ip(sip_to):", ip_src_str, "; dst_ip: ", ip_dst_str, "; voip_packet_type: ", inttostr(voip_packet_type));
            printf("src_port: %u, dst_port: %u", src_port, dst_port);

            if (voip_packet_type == 3) {
               uint64_t sip_stats;
               uint32_t invite_stats;
               uint16_t bye_stats;
               uint8_t ack_stats, cancel_stats;
               sip_stats = ur_get(template, in_rec, UR_INVEA_SIP_STATS);
               invite_stats = (uint32_t) sip_stats;
               cancel_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
               ack_stats = (uint8_t) ((sip_stats & 0x00ff000000000000) >> 48);
               bye_stats = (uint16_t) ((sip_stats & 0x0000ffff00000000) >> 32);
               printf("; Invite stats: %u ; ack_stats: %u; cancel_stats: %u; bye_stats: %u; ", invite_stats, ack_stats, cancel_stats, bye_stats);
            }
            PRINT_STD_LOG_NOTDATETIME("\n");
#endif
         }


         if (cut_sip_identifier_from_string(&sip_from, sip_from_orig, &sip_from_len, "SIP_FROM header") == -1) {

#ifdef TEST_DEBUG
            // temporary testing output ...

            PRINT_STD_LOG_NOTDATETIME("Invalid src_ip(sip_from):", ip_src_str, ";dst_ip: ", ip_dst_str, "; voip_packet_type: ", inttostr(voip_packet_type));
            printf("src_port: %u, dst_port: %u", src_port, dst_port);

            if (voip_packet_type == 3) {
               uint64_t sip_stats;
               uint32_t invite_stats;
               uint16_t bye_stats;
               uint8_t ack_stats, cancel_stats;
               sip_stats = ur_get(template, in_rec, UR_INVEA_SIP_STATS);
               invite_stats = (uint32_t) sip_stats;
               cancel_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
               ack_stats = (uint8_t) ((sip_stats & 0x00ff000000000000) >> 48);
               bye_stats = (uint16_t) ((sip_stats & 0x0000ffff00000000) >> 32);
               printf("; Invite stats: %u ; ack_stats: %u; cancel_stats: %u; bye_stats: %u; ", invite_stats, ack_stats, cancel_stats, bye_stats);
            }
            PRINT_STD_LOG_NOTDATETIME("\n");
#endif
         }

         // RTP data
         if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) != NULL) {

            // add sip_to to prefix tree
            prefix_tree_node = prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

            // check of successful initialization of node data
            if (check_initialize_node_data(prefix_tree_node, voip_packet_type) == -1) continue;

            // set rtp_data=1, if some packets are in the flow record
            if (ur_get(template, in_rec, UR_INVEA_RTCP_PACKETS) > 0 && ur_get(template, in_rec, UR_INVEA_RTCP_OCTETS) > 0) {
               ((node_data *) (prefix_tree_node->parent->value))->rtp_data = 1;
            }
         }

         // check if sip_to is numeric with allowed special char ('+','*','#') or this text part before '@' + check of minimum numeric length
         if (!is_numeric_participant(sip_to, sip_to_len)) continue;

         // do action against according to voip_packet_type
         switch (voip_packet_type) {

            case 3:
            {
               /* --------------------------------
                * request type: call oriented
                * -------------------------------- */


               // is source IP in hash table?
               if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_src->bytes))) == NULL) {

                  /* IP address not found in hash table */

                  // create and initialize hash_table_item
                  hash_table_item = (ip_item *) malloc(sizeof (ip_item));

                  // check successful allocation memory
                  if (hash_table_item == NULL) {
                     PRINT_STD_LOG("hash_table_item(voip_packet_type:", inttostr(voip_packet_type), "): error memory allocation\n");
                     continue;
                  }

                  // initialize prefix_tree
                  hash_table_item->tree = prefix_tree_initialize(SUFFIX, 0, -1);

                  // check successful allocation memory
                  if (hash_table_item->tree == NULL) {
                     PRINT_STD_LOG("hash_table_item->tree(voip_packet_type:", inttostr(voip_packet_type), "), prefix_tree_initialize: error memory allocation\n");
                     continue;
                  }

                  // initialize other variables of hash_table_item
                  hash_table_item->time_last_check = time_start_module;
                  hash_table_item->time_attack_detected_prefix_examination = 0;
                  hash_table_item->attack_count = 0;


                  // insert into hash table
                  if (ht_insert_v2(&hash_table_ip, (char *) ip_src->bytes, (void *) hash_table_item) != NULL) {
#ifdef TEST_DEBUG
                     PRINT_STD_LOG("(voip_packet_type:", inttostr(voip_packet_type), ") hash table reaches size limit!\n");
#endif
                  }
               }

               // get actual time
               time_t time_actual;
               time(&time_actual);

               // check if detection interval was expired
               if (difftime(time_actual, hash_table_item->time_last_check) >= detection_interval) {

                  // check if detection_pause_after_attack was expired
                  if (difftime(time_actual, hash_table_item->time_attack_detected_prefix_examination) >= detection_pause_after_attack) {

                     // clear cache
                     cache_no_attack_clear();

                     int status_detection;

                     // call detection of prefix examination
                     status_detection = detect_prefix_examination(hash_table_item->tree, hash_table_item->tree->root);

                     if (status_detection == STATE_ATTACK_DETECTED) {

                        PRINT_STD_LOG_NOTDATETIME("Detail: SRC_IP:", ip_src_str);

                        // save attack detection prefix_examination
                        hash_table_item->attack_count++;

                        PRINT_STD_LOG_NOTDATETIME("; attack_count: ", inttostr(hash_table_item->attack_count), " <==\n");

                        // add one to statistics of number attacks
                        statistic_num_attack_detected++;

                        // update time of last attack
                        time(&(hash_table_item->time_attack_detected_prefix_examination));
                     }

                     // save last detection time
                     time(&(hash_table_item->time_last_check));

#ifdef TEST_DEBUG
                     if (hash_table_item->tree->root->count_of_string > 5000) printf("count_of_root: %i; IP: %s; cache_size: %i;\n", hash_table_item->tree->root->count_of_string, ip_src_str, cache_no_attack_size);
#endif

                  }

               }


               // get number of INVITE messages in the flow record
               uint64_t sip_stats;
               uint32_t invite_stats;
               uint16_t bye_stats;
               uint8_t ack_stats, cancel_stats;

               sip_stats = ur_get(template, in_rec, UR_INVEA_SIP_STATS);

               // INVITE stats
               // same as: invite_stats = (uint32_t) (sip_stats & 0x00000000ffffffff);
               invite_stats = (uint32_t) sip_stats;

               // CANCEL, ACK, BYE stats (other_stats = sip_stats>>32;)
               cancel_stats = (uint8_t) ((sip_stats & 0xff00000000000000) >> 56);
               ack_stats = (uint8_t) ((sip_stats & 0x00ff000000000000) >> 48);
               bye_stats = (uint16_t) ((sip_stats & 0x0000ffff00000000) >> 32);

               // is at least one INVITE message
               if (invite_stats > 0) {

                  // add one to statistics of number invite flow
                  statistic_num_invite_flow++;

#ifdef TEST_DEBUG
                  char *sip_via;
                  int sip_via_len;

                  sip_via_len = ur_get_dyn_size(template, in_rec, UR_INVEA_SIP_VIA);
                  sip_via = ur_get_dyn(template, in_rec, UR_INVEA_SIP_VIA);

                  uint64_t link_bit_field;
                  link_bit_field = ur_get(template, in_rec, UR_LINK_BIT_FIELD);

                  printf("Via: %.*s\n", sip_via_len, sip_via);

                  printf("%s;IP:%s;LINK_BIT_FIELD: %u; INVITE: SIP_FROM:\"%.*s\";\n", get_actual_time_string(), ip_src_str, link_bit_field, sip_from_len, sip_from);
                  printf("%s;IP:%s;LINK_BIT_FIELD: %u; INVITE: SIP_TO:\"%.*s\";\n", get_actual_time_string(), ip_src_str, link_bit_field, sip_to_len, sip_to);
#endif

               }


               /*  PRINT_STD_LOG("DEBUG: src_ip(sip_from):", ip_src_str, ";dst_ip: ", ip_dst_str, "; voip_packet_type: ", inttostr(voip_packet_type));
                 printf("; Invite stats: %u ; ack_stats: %u; cancel_stats: %u; bye_stats: %u; ", invite_stats, ack_stats, cancel_stats, bye_stats);

                 uint64_t link_bit_field;
                 link_bit_field = ur_get(template, in_rec, UR_LINK_BIT_FIELD);

                 PRINT_STD_LOG_NOTDATETIME(" LINK_BIT_FIELD:", inttostr(link_bit_field), ";\n");
                */


               // add sip_to to prefix tree
               prefix_tree_node = prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

               // check successful prefix_tree_insert
               if (prefix_tree_node == NULL) {
                  PRINT_STD_LOG("prefix_tree_insert(voip_packet_type:", inttostr(voip_packet_type), "): error\n");
                  continue;
               }

               // check of successful initialization of node data
               if (check_initialize_node_data(prefix_tree_node, voip_packet_type) == -1) continue;

               // sum stats
               ((node_data *) (prefix_tree_node->parent->value))->invite_count += invite_stats;
               ((node_data *) (prefix_tree_node->parent->value))->cancel_count += cancel_stats;
               ((node_data *) (prefix_tree_node->parent->value))->ack_count += ack_stats;
               ((node_data *) (prefix_tree_node->parent->value))->bye_count += bye_stats;

               testvar_invite_count += invite_stats;
               testvar_ack_count += ack_stats;
               testvar_bye_count += bye_stats;
               testvar_cancel_count += cancel_stats;

               break;
            }


            case 2:
            {
               /* --------------------------------
                * response type: service oriented
                * -------------------------------- */

               // is destination IP in hash table?
               if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_dst->bytes))) != NULL) {

                  uint64_t sip_stats;

                  sip_stats = ur_get(template, in_rec, UR_INVEA_SIP_STATS);

                  // add sip_to to prefix tree
                  prefix_tree_node = prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

                  // check successful prefix_tree_insert
                  if (prefix_tree_node == NULL) {
                     PRINT_STD_LOG("prefix_tree_insert(voip_packet_type:", inttostr(voip_packet_type), "): error memory allocation\n");
                     continue;
                  }

                  // check of successful initialization of node data
                  if (check_initialize_node_data(prefix_tree_node, voip_packet_type) == -1) continue;

                  // sum stats
                  ((node_data *) (prefix_tree_node->parent->value))->trying_count += sip_stats & 0x00000000000000ff;
                  ((node_data *) (prefix_tree_node->parent->value))->ringing_count += (sip_stats & 0x0000ff0000000000) >> 40;
                  ((node_data *) (prefix_tree_node->parent->value))->service_ok_count += (sip_stats & 0xff00000000000000) >> 56;

               }

               break;
            }


            case 4:
            {
               /* --------------------------------
                * response type: call oriented
                * -------------------------------- */

               // is destination IP in hash table?
               if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip_dst->bytes))) != NULL) {

                  uint64_t sip_stats;

                  sip_stats = ur_get(template, in_rec, UR_INVEA_SIP_STATS);

                  // add sip_to to prefix tree
                  prefix_tree_node = prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

                  // check successful prefix_tree_insert
                  if (prefix_tree_node == NULL) {
                     PRINT_STD_LOG("prefix_tree_insert(voip_packet_type:", inttostr(voip_packet_type), "): error\n");
                     continue;
                  }

                  // check of successful initialization of node data
                  if (check_initialize_node_data(prefix_tree_node, voip_packet_type) == -1) continue;

                  // sum stats
                  ((node_data *) (prefix_tree_node->parent->value))->ok_count += (sip_stats & 0xff00000000000000) >> 56;

                  /*
                              PRINT_STD_LOG("DEBUG: src_ip(sip_from):", ip_src_str, ";dst_ip: ", ip_dst_str, "; voip_packet_type: ", inttostr(voip_packet_type));

                              if (((sip_stats & 0xff00000000000000) >> 56) > 0) {
                                 printf("; OK: %u; ", ((sip_stats & 0xff00000000000000) >> 56));
                              }
                              uint64_t link_bit_field;
                              link_bit_field = ur_get(template, in_rec, UR_LINK_BIT_FIELD);
                              PRINT_STD_LOG_NOTDATETIME(" LINK_BIT_FIELD:", inttostr(link_bit_field), ";\n");
                   */

                  testvar_ok_count += (sip_stats & 0xff00000000000000) >> 56;

               }

               break;
            }
         }

      }

   }

   // print statistics
   PRINT_STD_LOG("-----------------------------------------------------\n");
   PRINT_STD_LOG("Total module statistics:\n");
   PRINT_STD_LOG("   - num_attack_detected=", inttostr(statistic_num_attack_detected), "\n");
   PRINT_STD_LOG("   - num_invite_flow=", inttostr(statistic_num_invite_flow), "\n");
   PRINT_STD_LOG("   - num_invalid_sip_identifier=", inttostr(statistic_num_invalid_sip_identifier), "\n");
   PRINT_STD_LOG("   - num_warden_alert=", "not implemented", "\n");


#ifdef TEST_DEBUG
   // only for testing
   printf(" | count_cache_hit: %i\n", test_cache_hit);
   printf(" | count_cache_not_hit: %i\n", test_cache_not_hit);
   printf(" | count_cache_save: %i\n", test_cache_save);
   printf(" | count_cache_delete_successor: %i\n", test_cache_delete_successor);
   printf(" | testvar_ok_count: %i\n", testvar_ok_count);
   printf(" | testvar_invite_count: %i\n", testvar_invite_count);
   printf(" | testvar_ack_count: %i\n", testvar_ack_count);
   printf(" | testvar_bye_count: %i\n", testvar_bye_count);
   printf(" | testvar_cancel_count: %i\n", testvar_cancel_count);
#endif

   // ***** Cleanup *****

   PRINT_STD_LOG("Module cleanup-1!\n");

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   PRINT_STD_LOG("Module cleanup-2!\n");

   // free memory - destroy tree for all IP addresses
   ip_item * hash_table_item;
   for (int i = 0; i < hash_table_ip.table_size; i++) {
      if (hash_table_ip.ind[i].valid) {
         hash_table_item = (ip_item *) hash_table_ip.data[i];
         prefix_tree_destroy(hash_table_item->tree);
      }
   }

   PRINT_STD_LOG("Module cleanup-3!\n");

   // destroy hash table (free memory)
   ht_destroy_v2(&hash_table_ip);

   PRINT_STD_LOG("Module cleanup-4!\n");

   // destroy template (free memory)
   ur_free_template(template);

   PRINT_STD_LOG("... VoIP fraud detection module exit! (version:", MODULE_VERSION, ")\n");
   PRINT_STD_LOG("-----------------------------------------------------\n");

   return 0;
}
