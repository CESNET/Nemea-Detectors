/**
 * \file vportscan_detector.c
 * \brief Vertical portscan detector.
 * \author Marek Svepes <svepemar@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2015
 * \date 2016
 */
/*
 * Copyright (C) 2015-2016 CESNET
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
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include <b_plus_tree.h>
#include <time.h>

#define MAX_PACKETS 4 // Maximum number of packets in suspicious flow
#define MAX_PORTS 50 // After reaching this maximum of scanned ports for one IP address, alert is sent
#define MAX_AGE_OF_UNMODIFIED_PORTS_TABLE 5*60 // This determines maximum age of the unchanged ports table for one IP address

#define TIME_BEFORE_PRUNING 1*60

#define TCP_PROTOCOL 0x6
#define TCP_FLAGS_SYN 0x2

#define NUM_OF_ITEMS_IN_TREE_LEAF 5
#define STATIC_PORT_ARR_SIZE  10
#define DYNAMIC_PORT_ARR_SIZE  (MAX_PORTS - STATIC_PORT_ARR_SIZE)

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
   uint32 PORT_CNT
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("vportscan_detector", "Vportscan detector is a simple, threshold-based detector for vertical scans detection. The detection algorithm uses information from basic flow records (source and destination IP addresses and ports, protocol, #packets, #bytes).", 1, 1)

#define MODULE_PARAMS(PARAM)

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

typedef struct item_s item_t;

struct item_s {
   time_t ts_modified;
   uint16_t static_ports[STATIC_PORT_ARR_SIZE];
   uint16_t *dynamic_ports;
   uint8_t ports_cnts;
   ur_time_t ts_first;
   ur_time_t ts_last;
};

/***********************************************/

int compare_64b(void *a, void *b)
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

/**
 * Function returns 1 in case of alert, 0 after successful added port and -1 in case of error.
 */
int insert_port(void *p, int port)
{
   int x = 0;
   item_t *info = NULL;

   if (p == NULL) {
      return -1;
   }

   info = (item_t *) p;

   for (x = 0; x < info->ports_cnts; x++) {
      if (x < STATIC_PORT_ARR_SIZE) {
         if (info->static_ports[x] == port) {
            if (info->ports_cnts > STATIC_PORT_ARR_SIZE) {
               info->static_ports[x] = info->dynamic_ports[info->ports_cnts - STATIC_PORT_ARR_SIZE - 1];
               info->dynamic_ports[info->ports_cnts - STATIC_PORT_ARR_SIZE - 1] = 0;
            } else if (info->ports_cnts > 1) {
               info->static_ports[x] = info->static_ports[info->ports_cnts - 1];
               info->static_ports[info->ports_cnts - 1] = 0;
            } else {
               info->static_ports[x] = 0;
            }
            info->ports_cnts--;
            time(&info->ts_modified); // Update the time of table modification
            return 0;
         }
      } else {
         if (info->dynamic_ports[x - STATIC_PORT_ARR_SIZE] == port) {
            if (x < (info->ports_cnts - 1)) {
               info->dynamic_ports[x - STATIC_PORT_ARR_SIZE] = info->dynamic_ports[info->ports_cnts - 1 - STATIC_PORT_ARR_SIZE];
               info->dynamic_ports[info->ports_cnts - 1 - STATIC_PORT_ARR_SIZE] = 0;
            } else {
               info->dynamic_ports[x - STATIC_PORT_ARR_SIZE] = 0;
            }
            info->ports_cnts--;
            time(&info->ts_modified); // Update the time of table modification
            return 0;
         }
      }
   }

   if (info->ports_cnts < STATIC_PORT_ARR_SIZE) {
      info->static_ports[info->ports_cnts] = port; // Insert the new port into first free index
   } else {
      if (info->dynamic_ports == NULL) {
         // Inserting first port to dynamic array - allocate the array
         info->dynamic_ports = (uint16_t *) calloc(DYNAMIC_PORT_ARR_SIZE, sizeof(uint16_t));
      }
      info->dynamic_ports[info->ports_cnts - STATIC_PORT_ARR_SIZE] = port;
   }

   info->ports_cnts++;
   time(&info->ts_modified); // Update the time of table modification

   if (info->ports_cnts >= MAX_PORTS) {
      return 1; // Signalize alert after reaching MAX_PORTS scanned ports
   }

   return 0;
}

int main(int argc, char **argv)
{
   time_t ts_last_pruning;
   time_t ts_cur_time;
   int ret_val = 0;
   const void *recv_data;
   uint16_t recv_data_size = 0;

   // Needed fields
   ip_addr_t *src_ip = NULL;
   ip_addr_t *dst_ip = NULL;
   uint16_t dst_port = 0;
   uint32_t packets = 0;
   uint8_t protocol = 0;
   uint8_t tcp_flags = 0;

   uint32_t int_src_ip = 0;
   uint32_t int_dst_ip = 0;
   uint64_t ip_to_tree = 0;
   ur_time_t ts_first, ts_last;

   bpt_t *b_plus_tree = bpt_init(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_64b, sizeof(item_t), sizeof(uint64_t));
   if (b_plus_tree == NULL) {
      fprintf(stderr, "ERROR: Could not initialize B_PLUS_TREE\n");
      fflush(stderr);
      return 0;
   }
   void *new_item = NULL;
   item_t *np = NULL;

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

   out_tmplt = ur_create_output_template(0, "EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PORT_CNT", NULL);
   if (out_tmplt == NULL){
      fprintf(stderr, "ERROR: Output template could not be created.\n");
      fflush(stderr);
      goto cleanup;
   }
   // Allocate memory for output record
   out_rec = ur_create_record(out_tmplt, 0);
   if (out_rec == NULL){
      fprintf(stderr, "ERROR: Output record could not be created.\n");
      fflush(stderr);
      goto cleanup;
   }

   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);

   // Initialize time of last pruning of the B+ tree
   time(&ts_last_pruning);

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

      src_ip = &ur_get(in_tmplt, recv_data, F_SRC_IP);
      dst_ip = &ur_get(in_tmplt, recv_data, F_DST_IP);

      // Filter ip_v4 addresses
      if (ip_is4(src_ip) != 1 || ip_is4(dst_ip) != 1) {
         continue;
      }

      packets = ur_get(in_tmplt, recv_data, F_PACKETS);
      dst_port = ur_get(in_tmplt, recv_data, F_DST_PORT);
      protocol = ur_get(in_tmplt, recv_data, F_PROTOCOL);
      tcp_flags = ur_get(in_tmplt, recv_data, F_TCP_FLAGS);

      int_src_ip = ip_get_v4_as_int(src_ip);
      int_dst_ip = ip_get_v4_as_int(dst_ip);

      // Concatenate ip_v4 DST_IP and ip_v4 SRC_IP to uint64 (used as a key value in B+ tree)
      ip_to_tree = int_dst_ip;
      ip_to_tree = ip_to_tree << 32;
      ip_to_tree |= int_src_ip;

      if (packets <= MAX_PACKETS && (protocol == TCP_PROTOCOL && (tcp_flags == TCP_FLAGS_SYN))) {
         new_item = bpt_search_or_insert(b_plus_tree, &ip_to_tree);
         if (new_item == NULL) {
            fprintf(stderr, "ERROR: could not allocate port-scan info structure in leaf node of the B+ tree.\n");
            fflush(stderr);
            goto cleanup;
         }
         ts_first = ur_get(in_tmplt, recv_data, F_TIME_FIRST);
         ts_last = ur_get(in_tmplt, recv_data, F_TIME_LAST);
         np = (item_t *) new_item;
         if (np->ports_cnts == 0) {
            np->ts_first = ts_first;
            np->ts_last = ts_last;
         } else {
            if (np->ts_first > ts_first) {
               np->ts_first = ts_first;
            }
            if (np->ts_last < ts_last) {
               np->ts_last = ts_last;
            }
         }

         if (insert_port(new_item, dst_port) == 1) {
            // Scan detected
            ur_copy_fields(out_tmplt, out_rec, in_tmplt, recv_data);

            ur_set(out_tmplt, out_rec, F_EVENT_TYPE, 1);
            ur_set(out_tmplt, out_rec, F_PORT_CNT, MAX_PORTS);
            ur_set(out_tmplt, out_rec, F_TIME_FIRST, np->ts_first);
            ur_set(out_tmplt, out_rec, F_TIME_LAST, np->ts_last);

            ret_val = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));

            // free dynamic array of ports
            if (np->dynamic_ports != NULL) {
               free(np->dynamic_ports);
            }

            // delete item from tree no matter how successful was trap_send()
            bpt_item_del(b_plus_tree, &ip_to_tree);

            // break on error, do nothing on timeout in order to perform tree pruning
            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret_val, (void) 0, break);
         }

      } else {
         // flow of unsatisfied condition (TCP, packet number)
      }

      // B+ tree pruning
      time(&ts_cur_time);
      if ((ts_cur_time - ts_last_pruning) > TIME_BEFORE_PRUNING) {
         item_t *value_pt = NULL;
         bpt_list_item_t *b_item = NULL;
         int has_next = 0;

         // Create a structure for iterating throw the leaves
         b_item = bpt_list_init(b_plus_tree);
         if (b_item == NULL) {
            fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
            goto cleanup;
         }

         // Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
         has_next = bpt_list_start(b_plus_tree, b_item);
         while (has_next == 1) {
            // Get the value from B+ item structure
            value_pt = b_item->value;
            if (value_pt == NULL) {
               //there is problem in the tree. This case should be unreachable
               fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
               goto cleanup;
            }

            // Delete the item if it wasn't modified longer than MAX_AGE_OF_IP_IN_SEC(1)
            if ((ts_cur_time - value_pt->ts_modified) > MAX_AGE_OF_UNMODIFIED_PORTS_TABLE) {
               // free dynamic array of ports
               if (value_pt->dynamic_ports != NULL) {
                  free(value_pt->dynamic_ports);
               }
               has_next = bpt_list_item_del(b_plus_tree, b_item);
            } else { // Get next item from the list
               has_next = bpt_list_item_next(b_plus_tree, b_item);
            }
         }

         time(&ts_last_pruning);
      }
   }

   // ***** Cleanup *****
cleanup:
   bpt_clean(b_plus_tree);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_free_record(out_rec);
   ur_finalize();
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return 0;
}

