/**
 * \file haddrscan_detector.c
 * \brief Horizontal address scan detector.
 * \author Marek Svepes <svepemar@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include <b_plus_tree.h>
#include <stdbool.h>
#include <time.h>

#define MAX_PACKETS 1 // Maximum number of packets in suspicious flow

#define STATIC_ADDR_ARR_SIZE  10

#define TCP_PROTOCOL 0x6
#define TCP_FLAGS_SYN 0x2

#define NUM_OF_ITEMS_IN_TREE_LEAF 5
#define TRUE 1
#define FALSE 0

/* TODO
 * remember already reported SRC_IP (keep it in the tree after alert, only memset array and reset counter)
 * and before removing from the tree (pruning), report the rest of scanned addresses < threshold
 * (also in vportscan detector)
 */

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
   uint32 ADDR_CNT,

   ipaddr DST_IP0,
   ipaddr DST_IP1,
   ipaddr DST_IP2,
   ipaddr DST_IP3
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("haddrscan_detector", "This module is a simple, threshold-based detector for horizontal scans which processes incoming flow records and outputs alerts. The detection algorithm uses information from basic flow records and it is based on analysis of the number of destination addresses per source address. It is important to remember all unique destination addresses for each source address separately. The source address is a potential source of scan, meanwhile, the destination addresses are victims.", 1, 1)


/**
 * Definition of module parameters - every parameter has short_opt,
 * long_opt, description, flag whether an argument is required or
 * optional (NULL) Module parameter argument types: int8, int16,
 * int32, int64, uint8, uint16, uint32, uint64, float, string.
 *
 * See README.md for more detailed descriptions of these parameters.
 */
#define MODULE_PARAMS(PARAM) \
   PARAM('n', "numaddrs-threshold", "Send alert after this number of DST_IP are contacted by one SRC_IP × DST_PORT combination (default 50).", required_argument, "uint32") \
   PARAM('d', "idle-threshold", "Discard entry for an SRC_IP × DST_PORT combination after it has been unchanged this many seconds (default 300).", required_argument, "uint16") \
   PARAM('p', "pruning-interval", "Prune DST_IP tables with this interval in seconds (default 60).", required_argument, "uint16")


static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the
// module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

typedef struct item_s item_t;

struct item_s {
   time_t ts_modified;
   uint32_t static_addrs[STATIC_ADDR_ARR_SIZE];
   uint32_t *dynamic_addrs;
   uint8_t addr_cnt;
   ur_time_t ts_first;
   ur_time_t ts_last;
};

typedef struct param_s {
   uint32_t numaddrs_threshold;
   uint16_t idle_threshold;
   uint16_t pruning_interval;
} param_t;

static param_t param;

/***********************************************/

int compare_64b(void *a, void *b)
{
   uint64_t *h1, *h2;
   h1 = (uint64_t *) a;
   h2 = (uint64_t *) b;
   if (*h1 == *h2) {
      return EQUAL;
   } else if (*h1 < *h2) {
      return LESS;
   } else {
      return MORE;
   }
}


/**
 * Function returns 1 in case of alert, 0 on already present or
 * successful added address and -1 in case of error.
 */
int insert_addr(void *p, uint32_t int_dst_ip)
{
   int x = 0;
   item_t *info = NULL;

   if (p == NULL) {
      return -1;
   }

   info = (item_t *) p;

   for (x = 0; x < info->addr_cnt; x++) {
      if (x < STATIC_ADDR_ARR_SIZE) {
         if (info->static_addrs[x] == int_dst_ip) {
            time(&info->ts_modified); // Update the time of table modification
            return 0;
         }
      } else {
         if (info->dynamic_addrs[x - STATIC_ADDR_ARR_SIZE] == int_dst_ip) {
            time(&info->ts_modified); // Update the time of table modification
            return 0;
         }
      }
   }

   if (info->addr_cnt < STATIC_ADDR_ARR_SIZE) {
      // Insert the new address into first free index
      info->static_addrs[info->addr_cnt] = int_dst_ip;
   } else {
      if (info->addr_cnt == STATIC_ADDR_ARR_SIZE) {
         // Inserting first address to dynamic array - allocate the
         // array
         info->dynamic_addrs = (uint32_t *) calloc((param.numaddrs_threshold - STATIC_ADDR_ARR_SIZE), sizeof(uint32_t));
      }
      info->dynamic_addrs[info->addr_cnt - STATIC_ADDR_ARR_SIZE] = int_dst_ip;
   }

   info->addr_cnt++;
   time(&info->ts_modified); // Update the time of table modification

   if (info->addr_cnt >= param.numaddrs_threshold) {
      return 1; // Signal alert after reaching numaddrs_threshold scanned DST_IP
   }

   return 0;
}

int main(int argc, char **argv)
{
   time_t ts_last_pruning;
   time_t ts_cur_time;
   signed char opt;
   int ret_val = 0;
   const void *recv_data;
   uint16_t recv_data_size = 0;

   // Needed fields
   ip_addr_t *src_ip = NULL;
   ip_addr_t *dst_ip = NULL;
   uint32_t packets = 0;
   uint8_t protocol = 0;
   uint8_t tcp_flags = 0;
   uint16_t dst_port = 0;

   uint64_t key_to_tree = 0;
   uint32_t int_src_ip = 0;
   uint32_t int_dst_ip = 0;
   ur_time_t ts_first, ts_last;

   param.numaddrs_threshold = 50;
   param.idle_threshold = 5 * 60;
   param.pruning_interval = 1 * 60;

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

   /***** TRAP initialization *****/

   /*
    * Macro allocates and initializes module_info structure according
    * to MODULE_BASIC_INFO and MODULE_PARAMS definitions earlier in
    * this file. It also creates a string with short_opt letters for
    * getopt function called "module_getopt_string" and long_options
    * field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   /*
    * Let TRAP library parse program arguments, extract its parameters
    * and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   bool invalid_argument = false;

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1
      && invalid_argument == false) {
      switch (opt) {
         case 'n':
            if (sscanf(optarg, "%" SCNu32, &param.numaddrs_threshold) != 1) {
               invalid_argument = true;
            } else if (param.numaddrs_threshold < 2) {
               fprintf(stderr, "Numaddrs threshold < 2 makes no sense.\n");
               invalid_argument = true;
            }
            break;

         case 'd':
            if (sscanf(optarg, "%" SCNu16, &param.idle_threshold) != 1) {
               invalid_argument = true;
            } else if (param.idle_threshold < 1) {
               fprintf(stderr, "Idle threshold < 1 makes no sense.\n");
               invalid_argument = true;
            }
            break;

         case 'p':
            if (sscanf(optarg, "%" SCNu16, &param.pruning_interval) != 1) {
               invalid_argument = true;
            } else if (param.pruning_interval < 1) {
               fprintf(stderr, "Pruning interval < 1 makes no sense.\n");
               invalid_argument = true;
            }
            break;

         default:
            invalid_argument = true;
            break;
      }
   }

   if (invalid_argument == true) {
      fprintf(stderr, "Invalid arguments.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   // ***** Create UniRec templates *****
   in_tmplt = ur_create_input_template(0, NULL, NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "ERROR: Input template could not be created.\n");
      fflush(stderr);
      goto cleanup;
   }

   out_tmplt = ur_create_output_template(0,
                                         "EVENT_TYPE,TIME_FIRST,TIME_LAST,"
                                         "SRC_IP,DST_PORT,PROTOCOL,ADDR_CNT,"
                                         "DST_IP0,DST_IP1,DST_IP2,DST_IP3",
                                         NULL);
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
            fprintf(stderr,
                    "ERROR: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), recv_data_size);
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
      dst_port = ur_get(in_tmplt, recv_data, F_DST_PORT); // key to B+ tree
      protocol = ur_get(in_tmplt, recv_data, F_PROTOCOL);
      tcp_flags = ur_get(in_tmplt, recv_data, F_TCP_FLAGS);

      int_src_ip = ip_get_v4_as_int(src_ip); // also key to B+ tree
      int_dst_ip = ip_get_v4_as_int(dst_ip);

      // Concatenate ip_v4 SRC_IP and DST_PORT to uint64 (used as a
      // key value in B+ tree)
      key_to_tree = (uint64_t) int_src_ip;
      key_to_tree = key_to_tree << 16;
      key_to_tree |= dst_port;

      if (packets == MAX_PACKETS && (protocol == TCP_PROTOCOL && (tcp_flags == TCP_FLAGS_SYN))) {
         new_item = bpt_search_or_insert(b_plus_tree, &key_to_tree);
         if (new_item == NULL) {
            fprintf(stderr,
                    "ERROR: could not allocate port-scan info structure in leaf node of the B+ tree.\n");
            fflush(stderr);
            goto cleanup;
         }
         ts_first = ur_get(in_tmplt, recv_data, F_TIME_FIRST);
         ts_last = ur_get(in_tmplt, recv_data, F_TIME_LAST);
         np = (item_t *) new_item;
         if (np->addr_cnt == 0) {
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

         if (insert_addr(new_item, int_dst_ip) == 1) {
            // Scan detected
            ur_copy_fields(out_tmplt, out_rec, in_tmplt, recv_data);

            ur_set(out_tmplt, out_rec, F_EVENT_TYPE, 1);
            ur_set(out_tmplt, out_rec, F_ADDR_CNT, param.numaddrs_threshold);
            ur_set(out_tmplt, out_rec, F_TIME_FIRST, np->ts_first);
            ur_set(out_tmplt, out_rec, F_TIME_LAST, np->ts_last);

            ur_set(out_tmplt, out_rec, F_DST_IP0, ip_from_int(np->static_addrs[0]));
            ur_set(out_tmplt, out_rec, F_DST_IP1, ip_from_int(np->static_addrs[1]));
            ur_set(out_tmplt, out_rec, F_DST_IP2, ip_from_int(np->static_addrs[2]));
            ur_set(out_tmplt, out_rec, F_DST_IP3, ip_from_int(np->static_addrs[3]));

            ret_val = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));

            // free dynamic array of addresses
            if (np->dynamic_addrs != NULL) {
               free(np->dynamic_addrs);
            }
            // delete item from tree no matter how successful was trap_send()
            bpt_item_del(b_plus_tree, &key_to_tree);
            // break on error, do nothing on timeout in order to
            // perform tree pruning
            TRAP_DEFAULT_SEND_ERROR_HANDLING(ret_val, (void) 0, break);
         }

      } else {
         // flow of unsatisfied condition (TCP, packet number)
      }

      // B+ tree pruning
      time(&ts_cur_time);
      if ((ts_cur_time - ts_last_pruning) > param.pruning_interval) {
         item_t *value_pt = NULL;
         bpt_list_item_t *b_item = NULL;
         int has_next = 0;

         // Create a structure for iterating throw the leaves
         b_item = bpt_list_init(b_plus_tree);
         if (b_item == NULL) {
            fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
            goto cleanup;
         }

         printf("==== PRUNING THE TREE ====\noriginal number of values:  %lu\n", bpt_item_cnt(b_plus_tree));

         // Get first value from the list. Function returns 1 if there
         // are more values, 0 if there is no value
         has_next = bpt_list_start(b_plus_tree, b_item);
         while (has_next == TRUE) {
            // Get the value from B+ item structure
            value_pt = b_item->value;
            if (value_pt == NULL) {
               //there is problem in the tree. This case should be
               //unreachable
               fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
               goto cleanup;
            }

            // Delete the item if it wasn't modified in over
            // idle_threshold
            if ((ts_cur_time - value_pt->ts_modified) > param.idle_threshold) {
               // free dynamic array of addresses
               if (value_pt->dynamic_addrs != NULL) {
                  free(value_pt->dynamic_addrs);
               }
               has_next = bpt_list_item_del(b_plus_tree, b_item);
            } else { // Get next item from the list
               has_next = bpt_list_item_next(b_plus_tree, b_item);
            }
         }
         printf("\nnumber of values after pruning:  %lu\n", bpt_item_cnt(b_plus_tree));
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

/* local variables: */
/* c-basic-offset: 3; */
/* end: */
