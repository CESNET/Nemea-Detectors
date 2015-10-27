/**
 * \file vportscan_detector.c
 * \brief Vertical portscan detector.
 * \author Marek Svepes <svepemar@fit.cvut.cz>
 * \date 2015
 */
/*
 * Copyright (C) 2015 CESNET
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

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include <b_plus_tree.h>

#define MAX_PACKETS 4 // Maximum number of packets in suspicious flow
#define MAX_PORTS 50 // After reaching this maximum of scanned ports for one IP address, alert is sent
#define MAX_AGE_OF_IP_IN_SEC(num_hours) num_hours*60*60 // This determines maximum age of the unchanged IP address in the B+ tree
#define MAX_AGE_OF_PORTS_TABLE_IN_SEC 60*60 // This determines maximum age of the unchanged ports table for one IP address

#define TCP_PROTOCOL 6
#define TCP_FLAGS_SYN 0x2

#define NUM_OF_ITEMS_IN_TREE_LEAF 5
#define TRUE 1
#define FALSE 0

#define NUM_INSERTS_PRUNE_TREE 100000
#define NUM_OF_PORTS_IN_ALERT 25
#define PORTS_BUFFER_SIZE(ports_num) ((ports_num * 5) + (ports_num - 1)) * 2 // buffer used for concatenating subset of scanned ports into string

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint16 DST_PORT,
   uint16 SRC_PORT,

   uint32 PACKETS,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,


   uint8 EVENT_TYPE,
   time TIME_FIRST,
   time TIME_LAST,
   double EVENT_SCALE,
   string DST_PORT_LIST
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("Vertical portscan detector", "-", 1, 1)

#define MODULE_PARAMS(PARAM)

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

typedef struct item_s item_t;

struct item_s {
   time_t time_stamp;
   uint16_t ports[MAX_PORTS];
};

/***********************************************/

int compare_64b(void * a, void * b)
{
   uint64_t *h1, *h2;
   h1 = (uint64_t*)a;
   h2 = (uint64_t*)b;
   if (*h1 == *h2) {
         return EQUAL;
   }
   else if (*h1 < *h2) {
      return LESS;
   }
   else {
      return MORE;
   }
}

char *create_ports_string(void *p)
{
   static char buffer[PORTS_BUFFER_SIZE(NUM_OF_PORTS_IN_ALERT)];
   memset(buffer, 0, PORTS_BUFFER_SIZE(NUM_OF_PORTS_IN_ALERT) * sizeof(char));

   if (p == NULL) {
      return NULL;
   }

   item_t *info = (item_t *) p;
   int x = 0, bytes_printed = 0, ret_val = 0;

   for (x = 0; x < NUM_OF_PORTS_IN_ALERT; x++) {
      ret_val = sprintf(buffer + bytes_printed, "%d", info->ports[x]);

      if (ret_val > 0) {
         bytes_printed += ret_val;
      } else {
         return NULL;
      }

      if (x < (NUM_OF_PORTS_IN_ALERT - 1)) {
         ret_val = sprintf(buffer + bytes_printed, ",");
         if (ret_val > 0) {
            bytes_printed += ret_val;
         } else {
            return NULL;
         }
      }
   }

   // After sending the alert, reset the ports table
   memset((void *) (info->ports), 0, MAX_PORTS * sizeof(uint16_t));
   return buffer;
}


/**
 * Function returns 1 in case of alert, 0 after successful added port and -1 in case of error.
 */
int insert_port(void *p, int port)
{
   time_t act_time = 0;
   int x = 0, free_idx = -1;
   item_t *info = NULL;

   if (p == NULL) {
      return -1;
   }

   info = (item_t *) p;
   time(&act_time);

   // If the ports table was not modified longer than MAX_AGE_OF_PORTS_TABLE_IN_SEC, reset the table (zero values)
   if ((act_time - info->time_stamp) > MAX_AGE_OF_PORTS_TABLE_IN_SEC) {
      memset((void *) (info->ports), 0, MAX_PORTS * sizeof(uint16_t));
   }

   for (x = 0; x < MAX_PORTS; x++) {
      if (info->ports[x] == port) {
         info->ports[x] = 0; // The port was found in the table, delete it (only once scanned ports are important)
         time(&info->time_stamp); // Actualize the time of table modification
         return 0;
      }
   }

   for (x = 0; x < MAX_PORTS; x++) {
      if (info->ports[x] == 0) {
         free_idx = x; // Insert the new port into first free index
         time(&info->time_stamp); // Actualize the time of table modification
         break;
      }
   }

   if (free_idx != -1) {
      info->ports[free_idx] = port;
   } else {
      return 1; // Signalize alert after reaching MAX_PORTS scanned ports
   }

   return 0;
}

int main(int argc, char **argv)
{
   uint32_t ins_addr_cnt = 0;
   char *concat_ports_str = NULL;
   int ret_val = 0;
   const void *recv_data;
   uint16_t recv_data_size = 0;
   
   // Needed fields
   ip_addr_t *src_ip = NULL;
   ip_addr_t *dst_ip = NULL;
   uint16_t dst_port = 0;
   uint32_t packets = 0;
   uint8_t tcp_flags = 0;
   uint8_t protocol = 0;

   char ip_buffer[20];
   uint32_t int_src_ip = 0;
   uint32_t int_dst_ip = 0;
   uint64_t ip_to_tree = 0;

   void *b_plus_tree = b_plus_tree_initialize(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_64b, sizeof(item_t), sizeof(uint64_t));
   if (b_plus_tree == NULL) {
      fprintf(stderr, "ERROR: Could not initialize B_PLUS_TREE\n");
      fflush(stderr);
      return 0;
   }
   void *insertet_item = NULL;

   ur_template_t *out_tmplt = NULL, *in_tmplt = NULL;
   void *out_rec = NULL;

   /******************************/


   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec templates *****
   in_tmplt = ur_create_input_template(0, NULL, NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "ERROR: Input template could not be created.\n");
      fflush(stderr);
      goto cleanup;
   }

   out_tmplt = ur_create_output_template(0, "EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE,DST_PORT_LIST", NULL);
   if (out_tmplt == NULL){
      fprintf(stderr, "ERROR: Output template could not be created.\n");
      fflush(stderr);
      goto cleanup;
   }
   // Allocate memory for output record
   out_rec = ur_create_record(out_tmplt, PORTS_BUFFER_SIZE(NUM_OF_PORTS_IN_ALERT));
   if (out_rec == NULL){
      fprintf(stderr, "ERROR: Output record could not be created.\n");
      fflush(stderr);
      goto cleanup;
   }

   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);

   while (!stop) {
      ret_val = TRAP_RECEIVE(0, recv_data, recv_data_size, in_tmplt);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret_val, continue, break);
      // Check size of received data
      if (recv_data_size < ur_rec_fixlen_size(in_tmplt)) {
         if (recv_data_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "ERROR: data with wrong size received (expected size: >= %hu, received size: %hu)\n", ur_rec_fixlen_size(in_tmplt), recv_data_size);
            fflush(stderr);
            goto cleanup;
         }
      }

      src_ip = & ur_get(in_tmplt, recv_data, F_SRC_IP);
      dst_ip = & ur_get(in_tmplt, recv_data, F_DST_IP);

      // Filter ip_v4 addresses
      if (ip_is4(src_ip) != 1 || ip_is4(dst_ip) != 1) {
         continue;
      }

      packets = ur_get(in_tmplt, recv_data, F_PACKETS);
      dst_port = ur_get(in_tmplt, recv_data, F_DST_PORT);
      tcp_flags = ur_get(in_tmplt, recv_data, F_TCP_FLAGS);
      protocol = ur_get(in_tmplt, recv_data, F_PROTOCOL);

      int_src_ip = ip_get_v4_as_int(src_ip);
      int_dst_ip = ip_get_v4_as_int(dst_ip);

      // Concatenate ip_v4 DST_IP and ip_v4 SRC_IP to uint64 (used as a key value in B+ tree)
      ip_to_tree = int_dst_ip;
      ip_to_tree = ip_to_tree << 32;
      ip_to_tree += int_src_ip;

      ip_to_str(src_ip ,ip_buffer);

      if (packets <= MAX_PACKETS && protocol == TCP_PROTOCOL && (tcp_flags & TCP_FLAGS_SYN)) {
         insertet_item = b_plus_tree_insert_or_find_item(b_plus_tree, &ip_to_tree);
         if (insertet_item == NULL) {
            fprintf(stderr, "ERROR: could not allocate port-scan info structure in leaf node of the B+ tree.\n");
            fflush(stderr);
            goto cleanup;
         }
         if (insert_port(insertet_item, dst_port) == 1) {
            // Scan detected
            ur_copy_fields(out_tmplt, out_rec, in_tmplt, recv_data);

            ur_set(out_tmplt, out_rec, F_EVENT_TYPE, 1);
            ur_set(out_tmplt, out_rec, F_EVENT_SCALE, MAX_PORTS);
            
            concat_ports_str = create_ports_string(insertet_item);
            ur_set_string(out_tmplt, out_rec, F_DST_PORT_LIST, concat_ports_str);

            ret_val = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));

            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret_val, continue, break);
         }

         ins_addr_cnt++;

         // B+ tree pruning
         if (ins_addr_cnt >= NUM_INSERTS_PRUNE_TREE) {
            uint64_t *key_pt = NULL;
            item_t *value_pt = NULL;
            b_plus_tree_item *b_item = NULL;
            int is_there_next = 0;

            // Create a structure for iterating throw the leaves 
            b_item = b_plus_tree_create_list_item(b_plus_tree);
            if (b_item == NULL) {
               fprintf(stderr,"ERROR: could not initialize a list iterator structure\n");
               goto cleanup;
            }

            // Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
            is_there_next = b_plus_tree_get_list(b_plus_tree, b_item);
            while (is_there_next == 1) {
               // Get the value from B+ item structure
               value_pt = b_item->value;
               if (value_pt == NULL) {
                  //there is problem in the tree. This case should be unreachable
                  fprintf(stderr,"ERROR during iteration through the tree. Value is NULL\n");
                  goto cleanup;
               }
               // Get the key from B+ item structure
               key_pt = b_item->key;
               if (key_pt == NULL) {
                  //there is problem in the tree. This case should be unreachable
                  fprintf(stderr,"ERROR during iteration through the tree. Key is NULL\n");
                  goto cleanup;
               }

               // Delete the item if it wasn't modified longer than MAX_AGE_OF_IP_IN_SEC(1)
               if (value_pt->time_stamp > MAX_AGE_OF_IP_IN_SEC(1)) {
                  is_there_next = b_plus_tree_delete_item_from_list(b_plus_tree, b_item);
               } else { // Get next item from the list
                  is_there_next = b_plus_tree_get_next_item_from_list(b_plus_tree, b_item);
               }
            }

            ins_addr_cnt = 0;
         }

      } else {
         // normal flow
      }
   }

   // ***** Cleanup *****
cleanup:
   b_plus_tree_destroy(b_plus_tree);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return 0;
}

