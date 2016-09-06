/**
 * \file data_structure.c
 * \brief VoIP fraud detection module - data_structure
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

#include "data_structure.h"


// Initialize item of hash table defined by input parameter

int hash_table_item_initialize(ip_item_t * hash_table_item)
{
   // initialize suffix tree (data structure named prefix_tree)
   hash_table_item->tree = prefix_tree_initialize(SUFFIX, 0, -1, DOMAIN_EXTENSION_NO, RELAXATION_AFTER_DELETE_YES);

   // check successful allocation memory
   if (hash_table_item->tree == NULL) {
      PRINT_ERR("hash_table_item->tree: prefix_tree_initialize: Error memory allocation\n");
      return -1;
   }

   // prefix examination attack
   hash_table_item->first_invite_request = (ur_time_t) 0;
   hash_table_item->time_last_check_prefix_examination = (ur_time_t) 0;
   hash_table_item->time_last_communication = (ur_time_t) 0; // set for memory management of module
   hash_table_item->time_attack_detected_prefix_examination = 0;
   hash_table_item->prefix_examination_detection_event_count = 0;
   hash_table_item->prefix_examination_attack_detected_count = 0;
   hash_table_item->prefix_examination_attack_event_id = 0;
   hash_table_item->prefix_examination_attack_prefix_length = 0;
   hash_table_item->prefix_examination_attack_sip_to = NULL;

   // calling to different country
   hash_table_item->time_attack_detected_call_different_country = 0;
   hash_table_item->call_different_country_attack_event_id = 0;
   hash_table_item->call_different_country_attack_country[0] = '\0';
   hash_table_item->call_different_country_attack_country[1] = '\0';
   hash_table_item->call_different_country_detection_event_count = 0;
   hash_table_item->call_different_country_attack_detected_count = 0;
   hash_table_item->country_count = 0;

   return 0;
}

// Free memory of additional items in hash table item

void hash_table_item_free_inner_memory(ip_item_t * hash_table_item)
{
   if (hash_table_item->tree != NULL) {
      prefix_tree_destroy(hash_table_item->tree);
      hash_table_item->tree = NULL;
   }

   if (hash_table_item->prefix_examination_attack_sip_to != NULL) {
      free(hash_table_item->prefix_examination_attack_sip_to);
      hash_table_item->prefix_examination_attack_sip_to = NULL;
   }
}


// Initialize data of tree node defined by input parameter

int node_data_check_initialize(prefix_tree_domain_t * prefix_tree_node)
{
   // check if prefix_tree_node is not empty string node
   if (prefix_tree_node->parent == NULL) return -1;

   // check if input prefix_tree_node has not allocate memory
   if (prefix_tree_node->parent->value == NULL) {

      // allocate memory for node data
      prefix_tree_node->parent->value = (void *) malloc(sizeof (node_data_t));

      // check successful allocation memory
      if (prefix_tree_node->parent->value == NULL) {
         PRINT_ERR("initialize_node_data: Error memory allocation\n");
         return -1;
      }

      // initialize values of node_data
      ((node_data_t *) (prefix_tree_node->parent->value))->invite_count = 0;
      ((node_data_t *) (prefix_tree_node->parent->value))->ok_count = 0;
      ((node_data_t *) (prefix_tree_node->parent->value))->user_agent_hash = 0;
      ((node_data_t *) (prefix_tree_node->parent->value))->call_id_full = 0;
      ((node_data_t *) (prefix_tree_node->parent->value))->call_id_insert_position = 0;
   }

   return 0;
}

// Initialization of all statistics in memory (used once after start module)

void statistics_initialize()
{
   global_module_statistic.call_different_country_attack_detected_count = 0;
   global_module_statistic.invalid_sip_identifier_count = 0;
   global_module_statistic.prefix_examination_attack_detected_count = 0;
   global_module_statistic.prefix_examination_detection_event_count = 0;
   global_module_statistic.received_invite_flow_count = 0;
}

// Reset detection statistics used during detection of prefix examination attack

void detection_statistics_reset()
{
   detection_prefix_examination.invite = 0;
   detection_prefix_examination.ok = 0;
   detection_prefix_examination.successful_call = 0;
   detection_prefix_examination.report_node = NULL;
   detection_prefix_examination.report_prefix_length = 0;
   detection_prefix_examination.sip_user_agent_hash = 0;
   strcpy(detection_prefix_examination.sip_to, "");
   detection_prefix_examination.prefix_examination_count = 0;
   detection_prefix_examination.time = current_time; // set actual time
}
