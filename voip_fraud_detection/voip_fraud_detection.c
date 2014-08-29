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
#include <sys/param.h>
#include <byteswap.h>

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
   " - ...\n"
   "\n"
   "Optional parameters:\n"
   "   -l  : path to log file\n"
   "   -m  : max_prefix_length\n"
   "   -s  : detection interval in seconds\n"
   "   -t  : prefix_examination_detection_threshold\n"
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
unsigned int prefix_examination_detection_threshold;
unsigned int detection_interval;
char * log_file = NULL;

// statistics
unsigned int statistic_num_attack_detected = 0;
unsigned long long statistic_num_invite_flow = 0;
#ifdef SIP_HEADER_ISPECTION
unsigned int statistic_num_invalid_sip_to = 0;
#endif

// Return actual time

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

// Write input strings to standard output (variadic funtion)

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

// Cut first 4 chars ("sip:") from input string and ignore ';' + string after it

void cut_sip_identifier_from_string(char ** str, int * str_len)
{
   const int sip_identifier_len = 4;
   *str += sip_identifier_len * sizeof (char);
   *str_len -= sip_identifier_len;

   int i = 0;
   while (i < *str_len) {
      if ((*str)[i] == ';') {
         *str_len = i;
         break;
      }
      i++;
   }
}


// Check if input string is numeric with allowed special char ('+','*','#') or this text part before '@'

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

   return is_numeric;
}

// Detection prefix examination in input prefix tree

int detect_prefix_examination(prefix_tree_t * tree, prefix_tree_inner_node_t * node)
{
   int i;

   if (node->child == NULL) {
      // node is a leaf

      unsigned int prefix_sum_length = 0;
      unsigned int prefix_sum_count = 0;
      unsigned int prefix_last_count = 0;
      char str [MAX_STRING_PREFIX_TREE_NODE + 1];

      prefix_tree_inner_node_t * predecessor_node;
      predecessor_node = node;

      while (prefix_sum_length <= max_prefix_length) {

         prefix_tree_read_inner_node(tree, predecessor_node, str);

         // check if not node string contains '@' prior max_prefix_length position
         char * at_pointer = strstr(str, "@");
         if (at_pointer != NULL) {
            if (!(prefix_sum_length + (at_pointer - str) <= max_prefix_length)) break;
         }

         prefix_sum_length += strlen(str);
         prefix_sum_count += predecessor_node->count_of_string - prefix_last_count;
         prefix_last_count = predecessor_node->count_of_string;

         // printf("str: %s, count_of_string: %i\n", str, predecessor_node->count_of_string);

         predecessor_node = predecessor_node->parent;

         if (predecessor_node == NULL) break;
      }

#ifdef DEBUG
      // printf("--- prefix_count: %i\n", prefix_sum_count);
#endif

      if (prefix_sum_count > prefix_examination_detection_threshold) {
         char sip_to[MAX_STRING_PREFIX_TREE_NODE + 1];

         // initialize sip_to string
         sip_to[0] = '\0';

         // set predecessor_node as leaf node
         predecessor_node = node;

         // compose one of sip_to uri from prefix attack
         while (predecessor_node != NULL) {
            prefix_tree_read_inner_node(tree, predecessor_node, str);
            strcat(sip_to, str);
            predecessor_node = predecessor_node->parent;
         }

         PRINT_STD_LOG("==> Detected Prefix Examination (sip_to:\"", sip_to, "\")");
         PRINT_STD_LOG_NOTDATETIME("(prefix_sum_count=", inttostr(prefix_sum_count), " (>) ");
         PRINT_STD_LOG_NOTDATETIME("threshold=", inttostr(prefix_examination_detection_threshold), ")!!!");
         return STATE_ATTACK_DETECTED;
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
   max_prefix_length = DEFAULT_MAX_PREFIX_LENGTH;
   prefix_examination_detection_threshold = DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD;
   detection_interval = DEFAULT_DETECTION_INTERVAL;

   // Parse remaining parameters and get configuration
   char opt;

   while ((opt = getopt(argc, argv, "l:m:s:t:")) != -1) {
      switch (opt) {
         case 'l':
            log_file = optarg;
            break;
         case 'm':
            max_prefix_length = atoi(optarg);
            break;
         case 's':
            detection_interval = atoi(optarg);
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
   PRINT_STD_LOG("    - prefix_examination_detection_threshold=", inttostr(prefix_examination_detection_threshold), "\n");
   PRINT_STD_LOG("    - detection interval=", inttostr(detection_interval), "\n");
   if (log_file != NULL) PRINT_STD_LOG("    - log file:", log_file, "\n");
   PRINT_STD_LOG("-----------------------------------------------------\n");


   // ***** Create UniRec templates *****

   char *ur_template_specifier = UNIREC_INPUT_TEMPLATE;

   ur_template_t *template = ur_create_template(ur_template_specifier);


   // ***** Main processing loop 

   // initialize hash table for IP addresses
   cc_hash_table_v2_t hash_table_ip;
   ht_init_v2(&hash_table_ip, HASH_TABLE_IP_SIZE, sizeof (ip_item), sizeof (ip_addr_t));


   // save start time module
   time_t time_start_module;
   time(&time_start_module);


   // Read data from input, process them and write to output
   while (!stop) {

      const void *in_rec;
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

      // is request type: call oriented
      if (voip_packet_type == 3) {

         // get number of INVITE messages in the flow record
         uint64_t sip_stats;
         uint32_t invite_stats;

         sip_stats = ur_get(template, in_rec, UR_INVEA_SIP_STATS);


         // INVITE stats
         // same as: invite_stats = (uint32_t) (sip_stats & 0x00000000ffffffff);
         invite_stats = (uint32_t) sip_stats;

         // CANCEL, ACK, BYE stats:  invite_stats = sip_stats>>32;


#ifdef TEST_DEBUG
         //  printf("Invite_stats i: %i\n", invite_stats);
#endif

         // is at least one INVITE message
         if (invite_stats > 0) {

            // add one to statistic of number invite flow
            statistic_num_invite_flow++;

            char * sip_from, * sip_to, *sip_via;
            int sip_from_len, sip_to_len, sip_via_len;

#ifdef TEST_DEBUG
            sip_via = ur_get_dyn(template, in_rec, UR_INVEA_SIP_VIA);
            sip_via_len = ur_get_dyn_size(template, in_rec, UR_INVEA_SIP_VIA);

            printf("Via: %.*s\n", sip_via_len, sip_via);
#endif

            sip_from = ur_get_dyn(template, in_rec, UR_INVEA_SIP_CALLING_PARTY);
            sip_from_len = ur_get_dyn_size(template, in_rec, UR_INVEA_SIP_CALLING_PARTY);

            sip_to = ur_get_dyn(template, in_rec, UR_INVEA_SIP_CALLED_PARTY);
            sip_to_len = ur_get_dyn_size(template, in_rec, UR_INVEA_SIP_CALLED_PARTY);

#ifdef SIP_HEADER_ISPECTION
            // check sip_to beginning with "sip:"
            if ((strlen(sip_to) <= 4) || (strncmp(sip_to, "sip:", 4) != 0)) {
               print_error(2, "SIP To header is invalid!\n");
               PRINT_STD_LOG("SIP To header is invalid: ", sip_to, "\n");
               statistic_num_invalid_sip_to++;
            }
#endif

            // cut "sip:" from sip_to and sip_from
            cut_sip_identifier_from_string(&sip_to, &sip_to_len);
            cut_sip_identifier_from_string(&sip_from, &sip_from_len);

#ifdef TEST_DEBUG
            ip_addr_t * ip_temp;
            ip_temp = &ur_get(template, in_rec, UR_SRC_IP);
            char ip_str_temp[20];
            ip_to_str(ip_temp, ip_str_temp);

            printf("%s;IP:%s;INVITE: SIP_FROM:\"%.*s\";\n", get_actual_time_string(), ip_str_temp, sip_from_len, sip_from);
            printf("%s;IP:%s;INVITE: SIP_TO:\"%.*s\";\n", get_actual_time_string(), ip_str_temp, sip_to_len, sip_to);
#endif

            // check if sip_to is numeric with allowed special char ('+','*','#') or this text part before '@'
            if (!is_numeric_participant(sip_to, sip_to_len)) continue;

            // get source IP (unirec)
            ip_addr_t * ip;
            ip = &ur_get(template, in_rec, UR_SRC_IP);
            char ip_str[20];
            ip_to_str(ip, ip_str);

            ip_item * hash_table_item;
            time_t time_actual;

            if ((hash_table_item = (ip_item *) ht_get_v2(&hash_table_ip, (char *) (ip->bytes))) == NULL) {

               // IP address not found in hash table

               // create and initialize hash_table_item
               hash_table_item = (ip_item *) malloc(sizeof (ip_item));
               hash_table_item->tree = malloc(sizeof (prefix_tree_inner_node_t *));
               hash_table_item->tree = prefix_tree_initialize(SUFFIX, 0, -1);
               hash_table_item->time_last_check = time_start_module;

               // add sip_to to prefix tree
               prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

               // insert into hash table
               if (ht_insert_v2(&hash_table_ip, (char *) ip->bytes, (void *) hash_table_item) != NULL) {
#ifdef TEST_DEBUG
                  printf("hash table reaches size limit!\n");
#endif
               }
            } else {
               // IP address is found in hash table

               ip_to_str((ip_addr_t *) ip->bytes, ip_str);

               // add sip_to to prefix tree
               prefix_tree_insert(hash_table_item->tree, sip_to, sip_to_len > MAX_STRING_PREFIX_TREE_NODE ? MAX_STRING_PREFIX_TREE_NODE : sip_to_len);

            }

            // get actual time
            time(&time_actual);

            // check if detection interval was expired
            if (difftime(time_actual, hash_table_item->time_last_check) >= detection_interval) {
               int status_detection;
               // call detection voip fraud
               status_detection = detect_prefix_examination(hash_table_item->tree, hash_table_item->tree->root);
               if (status_detection == STATE_ATTACK_DETECTED) {

                  PRINT_STD_LOG_NOTDATETIME("Detail: SRC_IP:", ip_str, " <==\n");
                  statistic_num_attack_detected++;

                  // destroy tree for current IP address
                  prefix_tree_destroy(hash_table_item->tree);
                  // remove IP address item from hash table
                  ht_remove_by_key_v2(&hash_table_ip, (char *) ip->bytes);
               }
               // save last detection time
               time(&(hash_table_item->time_last_check));

#ifdef DEBUG
               // PRINT_STD_LOG("DEBUG: calling function detect_prefix_examination() with IP:", ip_str,"\n");
#endif

            }

         }
      }
   }

   // print statistics
   PRINT_STD_LOG("-----------------------------------------------------\n");
   PRINT_STD_LOG("Total module statistics:\n");
   PRINT_STD_LOG("   - num_attack_detected=", inttostr(statistic_num_attack_detected), "\n");
   PRINT_STD_LOG("   - num_invite_flow=", inttostr(statistic_num_invite_flow), "\n");
#ifdef SIP_HEADER_ISPECTION
   PRINT_STD_LOG("   - num_invalid_sip_to=", inttostr(statistic_num_invalid_sip_to), "\n");
#endif
   PRINT_STD_LOG("   - num_warden_alert=", "not implemented", "\n");

   // ***** Cleanup *****

#ifdef DEBUG
   PRINT_STD_LOG("Module cleanup!\n");
#endif

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   // free memory - destroy tree for all IP addresses
   ip_item * hash_table_item;
   for (int i = 0; i < hash_table_ip.table_size; i++) {
      if (hash_table_ip.ind[i].valid) {
         hash_table_item = (ip_item *) hash_table_ip.data[i];
         prefix_tree_destroy(hash_table_item->tree);
      }
   }

   // destroy hash table (free memory)
   ht_destroy_v2(&hash_table_ip);

   // destroy template (free memory)
   ur_free_template(template);

   PRINT_STD_LOG("... VoIP fraud detection module exit! (version:", MODULE_VERSION, ")\n");
   PRINT_STD_LOG("-----------------------------------------------------\n");

   return 0;
}
