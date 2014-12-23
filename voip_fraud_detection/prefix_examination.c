/**
 * \file prefix_examination.c
 * \brief VoIP fraud detection module - prefix_examination
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

#include "prefix_examination.h"


// Detection prefix examination in input suffix tree,
// if attack is detected delete node and his descendants

int prefix_examination_tree_detection(prefix_tree_t * tree, prefix_tree_inner_node_t * node)
{
   // check if node is in cache_no_attack
   if (cache_node_no_attack_exists(node)) {
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

         // count length and number of descendants
         prefix_sum_length += strlen(str);
         prefix_sum_count += predecessor_node->count_of_string - prefix_last_count;
         prefix_last_count = predecessor_node->count_of_string;

         // save actual node
         last_predecessor_node = predecessor_node;

         // move to predecessor of node
         predecessor_node = predecessor_node->parent;

         // check if node string contains '@'
         char * at_pointer = strstr(str, "@");
         if (at_pointer != NULL) {
            break;
         }

         // check if predecessor exists
         if (predecessor_node == NULL) break;
      }

      // check if prefix_sum_count exceeds threshold
      if (prefix_sum_count > modul_configuration.prefix_examination_detection_threshold) {

         // check if node is in cache
         if (cache_node_no_attack_exists(predecessor_node) == 1) {
            return STATE_NO_ATTACK;
         }

         // reset detection statistics
         detection_statistics_reset();

         // thorough count of prefix detection
         unsigned int minus_detection_value = prefix_examination_count_minus_detection_value(tree, last_predecessor_node, 0, 1);

         // decrement prefix_sum_count by minus detection value
         if (prefix_sum_count <= minus_detection_value) {
            prefix_sum_count = 0;
         } else {
            prefix_sum_count -= minus_detection_value;
         }

         // check if prefix_sum_count exceeds threshold after recalculation
         if (prefix_sum_count > modul_configuration.prefix_examination_detection_threshold) {

            // attack detected!

            // initialize sip_to string
            detection_prefix_examination.sip_to[0] = '\0';

            // set predecessor_node as leaf node of prefix examination attack
            predecessor_node = detection_prefix_examination.report_node;

            // compose one of sip_to uri from prefix attack
            while (predecessor_node != NULL) {
               prefix_tree_read_inner_node(tree, predecessor_node, str);
               // strcat(detection.sip_to, "|");
               strcat(detection_prefix_examination.sip_to, str);
               predecessor_node = predecessor_node->parent;
            }

            detection_prefix_examination.prefix_examination_count = prefix_sum_count;

            detection_prefix_examination.sip_user_agent_hash = ((node_data_t *) detection_prefix_examination.report_node->value)->user_agent_hash;

            // delete node and his descendants from prefix tree
            prefix_tree_delete_inner_node(tree, last_predecessor_node);

            return STATE_ATTACK_DETECTED;

         } else {
            // attack not detected, save node to cache
            cache_node_no_attack_save(last_predecessor_node);
         }
      }

   } else {
      // node is an inner node

      int state_detection;

      for (i = 0; i < COUNT_OF_LETTERS_IN_DOMAIN; i++) {
         if (node->child[i] != NULL) {

            // recursive call
            state_detection = prefix_examination_tree_detection(tree, node->child[i]);
            if (state_detection == STATE_ATTACK_DETECTED) return STATE_ATTACK_DETECTED;
         }
      }

   }

   return STATE_NO_ATTACK;

}

// Function to thorough count of prefix detection minus value and save information about attack to detection_struct

unsigned int prefix_examination_count_minus_detection_value(prefix_tree_t * tree, prefix_tree_inner_node_t * node, unsigned int sum_prefix_down, char first_node)
{
   unsigned int result = 0;

   char str [MAX_STRING_PREFIX_TREE_NODE + 1];
   prefix_tree_read_inner_node(tree, node, str);

   // check if node string not contains '@'
   char * at_pointer = strstr(str, "@");
   if (at_pointer == NULL && first_node != 1) {
      // count length of actual prefix node string
      sum_prefix_down += strlen(str);
   }

   // checking actual prefix length against module configuration
   if (sum_prefix_down > modul_configuration.max_prefix_length) {

      result += node->count_of_string + 1;

   } else {
      // node belongs to detection

      // checking if node has data
      if (node->value != NULL) {

#ifdef CONSIDER_SUCCESSFUL_CALL_AFTER_SIPACK
         if (((node_data_t *) (node->value))->ok_count > 0 && ((node_data_t *) (node->value))->ack_count > 0) {
#else
         if (((node_data_t *) (node->value))->ok_count > 0) {
#endif
            // incrementation result by one
            result += 1;

            // incrementation of unique_ok
            detection_prefix_examination.successful_call += 1;

         } else {

            // node is in prefix examination attack

            if (detection_prefix_examination.report_prefix_length < sum_prefix_down) {
               // save node of prefix examination for reporting
               detection_prefix_examination.report_node = node;
               detection_prefix_examination.report_prefix_length = sum_prefix_down;
            }

         }

         detection_prefix_examination.invite += ((node_data_t *) (node->value))->invite_count;
         detection_prefix_examination.cancel += ((node_data_t *) (node->value))->cancel_count;
         detection_prefix_examination.ack += ((node_data_t *) (node->value))->ack_count;
         detection_prefix_examination.bye += ((node_data_t *) (node->value))->bye_count;
         detection_prefix_examination.ok += ((node_data_t *) (node->value))->ok_count;
         detection_prefix_examination.trying += ((node_data_t *) (node->value))->trying_count;
         detection_prefix_examination.ringing += ((node_data_t *) (node->value))->ringing_count;
         detection_prefix_examination.forbidden += ((node_data_t *) (node->value))->forbidden_count;
         detection_prefix_examination.unauthorized += ((node_data_t *) (node->value))->unauthorized_count;
         detection_prefix_examination.proxy_auth_req += ((node_data_t *) (node->value))->proxy_auth_req_count;
         detection_prefix_examination.rtcp_data += ((node_data_t *) (node->value))->rtp_data;
      }

      // is not node leaf?
      if (node->child != NULL) {

         // node is an inner node
         int i;
         for (i = 0; i < COUNT_OF_LETTERS_IN_DOMAIN; i++) {
            if (node->child[i] != NULL) {

               // recursive calling function
               result += prefix_examination_count_minus_detection_value(tree, node->child[i], sum_prefix_down, 0);
            }
         }
      }
   }

   return result;
}

// Detection of prefix examination attack and write/send information about it

int prefix_examination_detection(cc_hash_table_v2_t * hash_table_user_agent, ip_item_t * hash_table_item, ip_addr_t * ip_src)
{
   // get actual time
   time_t time_actual;
   time(&time_actual);

   // check if detection interval was expired
   if (difftime(time_actual, hash_table_item->time_last_check_prefix_examination) >= modul_configuration.detection_interval) {

      // check if detection_pause_after_attack was expired
      if (difftime(time_actual, hash_table_item->time_attack_detected_prefix_examination) >= modul_configuration.detection_pause_after_attack) {

         // clear cache_node_no_attack
         cache_node_no_attack_clear();

         int status_detection;

         // call detection of prefix examination attack in suffix tree
         status_detection = prefix_examination_tree_detection(hash_table_item->tree, hash_table_item->tree->root);

         if (status_detection == STATE_ATTACK_DETECTED) {

            /* PREFIX EXAMINATION ATTACK DETECTED */

            uint32_t event_id;

            // Write attack information to stdout and log ...
            PRINT_OUT_LOG("==> Detected Prefix Examination");

            // check if attack continue or the new attack will be reported
            if (hash_table_item->prefix_examination_attack_event_id != 0 \
                             && hash_table_item->prefix_examination_attack_sip_to != NULL \
                             && strcmp(detection_prefix_examination.sip_to + detection_prefix_examination.report_prefix_length, \
                                       hash_table_item->prefix_examination_attack_sip_to + hash_table_item->prefix_examination_attack_prefix_length) == 0) {
               // last attack continues

               event_id = hash_table_item->prefix_examination_attack_event_id;

               PRINT_OUT_LOG_NOTDATETIME(" (continuation)");

            } else {
               // new attack

               // increment event_id
               last_event_id++;

               event_id = last_event_id;

               // save attack detection prefix_examination
               hash_table_item->prefix_examination_attack_detected_count++;

               // add one to statistics of number attacks
               global_module_statistic.prefix_examination_attack_detected_count++;
            }

            // save attack detection prefix_examination
            hash_table_item->prefix_examination_detection_event_count++;

            // add one to statistics of number detection events
            global_module_statistic.prefix_examination_detection_event_count++;

            // get IP adresses in text format
            char ip_src_str[INET6_ADDRSTRLEN + 1];
            ip_to_str(ip_src, ip_src_str);

            // ... attack information to stdout and log ...
            PRINT_OUT_LOG_NOTDATETIME("!; event_id=", uint_to_str(event_id), "; ");
            PRINT_OUT_LOG_NOTDATETIME("detection_time=\"", time_t_to_str(detection_prefix_examination.time), "\"; ");
            PRINT_OUT_LOG_NOTDATETIME("time_first=\"", time_t_to_str(hash_table_item->first_invite_request), "\"; ");
            PRINT_OUT_LOG_NOTDATETIME("SRC_IP=", ip_src_str, "; ");
            PRINT_OUT_LOG_NOTDATETIME("SIP_TO=\"", detection_prefix_examination.sip_to, "\"; ");
            char * user_agent_str;
            user_agent_str = *(char **) ht_get_v2(hash_table_user_agent, (char *) (&(detection_prefix_examination.sip_user_agent_hash)));
            if (user_agent_str != NULL) {
               PRINT_OUT_LOG_NOTDATETIME("User-Agent=\"", user_agent_str, "\"; ");
            }
            PRINT_OUT_LOG_NOTDATETIME("prefix_length=", uint_to_str(detection_prefix_examination.report_prefix_length), "; ");
            PRINT_OUT_LOG_NOTDATETIME("prefix_examination_count=", uint_to_str(detection_prefix_examination.prefix_examination_count), "; ");
            PRINT_OUT_LOG_NOTDATETIME("successful_call_count=", uint_to_str(detection_prefix_examination.successful_call), "; ");
            PRINT_OUT_LOG_NOTDATETIME("invite_count=", uint_to_str(detection_prefix_examination.invite), "; ");
            PRINT_OUT_LOG_NOTDATETIME("IP_detection_event_count=", uint_to_str(hash_table_item->prefix_examination_detection_event_count), "; ");
            PRINT_OUT_LOG_NOTDATETIME("IP_attack_detected_count=", uint_to_str(hash_table_item->prefix_examination_attack_detected_count), " <== # ");

            // ... additional information output ...
            if (detection_prefix_examination.ok > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_detection_value_ok=", uint_to_str(detection_prefix_examination.ok), "; ");
            }
            if (detection_prefix_examination.trying > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_trying=", uint_to_str(detection_prefix_examination.trying), "; ");
            }
            if (detection_prefix_examination.ringing > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_detection_value_ringing=", uint_to_str(detection_prefix_examination.ringing), "; ");
            }
            if (detection_prefix_examination.ack > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_ack=", uint_to_str(detection_prefix_examination.ack), "; ");
            }
            if (detection_prefix_examination.rtcp_data > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_rtcp_data=", uint_to_str(detection_prefix_examination.rtcp_data), "; ");
            }
            if (detection_prefix_examination.cancel > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_cancel=", uint_to_str(detection_prefix_examination.cancel), "; ");
            }
            if (detection_prefix_examination.bye > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_bye=", uint_to_str(detection_prefix_examination.bye), "; ");
            }
            if (detection_prefix_examination.forbidden > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_detection_value_forbidden=", uint_to_str(detection_prefix_examination.forbidden), "; ");
            }
            if (detection_prefix_examination.unauthorized > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_detection_value_unauthorized=", uint_to_str(detection_prefix_examination.unauthorized), "; ");
            }
            if (detection_prefix_examination.proxy_auth_req > 0) {
               PRINT_OUT_LOG_NOTDATETIME("count_detection_value_proxy_auth_req=", uint_to_str(detection_prefix_examination.proxy_auth_req), "; ");
            }

            PRINT_OUT_LOG_NOTDATETIME("\n");

            // Send attack information to output interface

            // fill in fields of detection event
            ur_set(ur_template_out, detection_record, UR_EVENT_ID, event_id);
            ur_set(ur_template_out, detection_record, UR_EVENT_TYPE, UR_EVT_T_VOIP_PREFIX_GUESS);
            ur_set(ur_template_out, detection_record, UR_SRC_IP, *ip_src);
            ur_set(ur_template_out, detection_record, UR_DETECTION_TIME, ur_time_from_sec_msec(detection_prefix_examination.time, 0));
            ur_set(ur_template_out, detection_record, UR_TIME_FIRST, ur_time_from_sec_msec(hash_table_item->first_invite_request, 0));
            ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_SIP_TO, detection_prefix_examination.sip_to, sizeof (char) * strlen(detection_prefix_examination.sip_to));
            if (user_agent_str == NULL) {
               ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_USER_AGENT, "", 0);
            } else {
               ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_USER_AGENT, user_agent_str, sizeof (char) * strlen(user_agent_str));
            }
            ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_PREFIX_LENGTH, detection_prefix_examination.report_prefix_length);
            ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_PREFIX_EXAMINATION_COUNT, detection_prefix_examination.prefix_examination_count);
            ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_SUCCESSFUL_CALL_COUNT, detection_prefix_examination.successful_call);
            ur_set(ur_template_out, detection_record, UR_VOIP_FRAUD_INVITE_COUNT, detection_prefix_examination.invite);

            // send alert to output interface
            int return_code = trap_send(0, detection_record, ur_rec_size(ur_template_out, detection_record));
            TRAP_DEFAULT_SEND_ERROR_HANDLING(return_code,;, PRINT_ERR("Error during sending", UNIREC_OUTPUT_TEMPLATE, " to output interface!\n"););

            // save attack information to hash_table_item
            hash_table_item->prefix_examination_attack_event_id = event_id;
            hash_table_item->prefix_examination_attack_prefix_length = detection_prefix_examination.report_prefix_length;

            // check allocation of attack_sip_to
            if (hash_table_item->prefix_examination_attack_sip_to == NULL) {
               hash_table_item->prefix_examination_attack_sip_to = (char *) malloc(sizeof (char) * (MAX_STRING_PREFIX_TREE_NODE + 1));
            }

            // check of successful allocation memory
            if (hash_table_item->prefix_examination_attack_sip_to == NULL) {
               PRINT_ERR("hash_table_item->attack_sip_to: Error memory allocation\n");
            } else {
               strncpy(hash_table_item->prefix_examination_attack_sip_to, detection_prefix_examination.sip_to, MAX_STRING_PREFIX_TREE_NODE);
            }

            // save event_id to file
            event_id_save(modul_configuration.event_id_file);

            // update time of last attack
            time(&(hash_table_item->time_attack_detected_prefix_examination));

         }

         // save last detection time
         time(&(hash_table_item->time_last_check_prefix_examination));

         return status_detection;

      }

   }
   return STATE_NO_ATTACK;
}
