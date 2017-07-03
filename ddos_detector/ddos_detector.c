/**
 * \file ddos_detector.c
 * \brief Module for detecting volumetric DDoS attacks.
 * \author Otto Hollmann <hollmott@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2017
 */
/*
 * Copyright (C) 2017 CESNET
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
#include <time.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"
#include <b_plus_tree.h>
#include <stdbool.h>
#include <assert.h>

/*#define DEBUG1
#define DEBUG2*/

#define NUM_OF_ITEMS_IN_TREE_LEAF 5

/* ---------------------------------------------------------------------- */
/*
 * Module parameters (not run-time configurable to allow compile-time
 * optimizations).
 */
/*
 * Base interval in seconds (average amount of traffic per this interval is
 * computed and compared to threshold).
 */
#define INTERVAL 60

/*
 * Maximum duration of flows (i.e. active timeout set on exporter(s)) in
 * seconds.
 */
#define MAX_FLOW_LEN 330

/*
 * Maximum delay between flow records (i.e. how long can it take for a flow
 * from last seen packet to arrival of the flow record to this module, or
 * inactive timeout + some time to travel from exporter to the module).
 */
#define MAX_FLOW_DELAY 90

/*
 * Number of intervals of history to store.
 *
 * According to experiments, delay of 120s never happens, 90 very few times,
 * 60 happens normally so 60 is good value (at CESNET's deployment).
 */
#define N_INTERVALS ((MAX_FLOW_LEN + MAX_FLOW_DELAY) / (INTERVAL))

/*
 * History must be stored because flows can be longer than base intervals so we
 * sometimes need to update more intervals than just the latest one.
 * Note: MAX_FLOW_LEN+MAX_FLOW_DELAY should be divisible by INTERVAL.
 */
#if (MAX_FLOW_LEN + MAX_FLOW_DELAY) % (INTERVAL) != 0
#warning (MAX_FLOW_LEN + MAX_FLOW_DELAY) should be divisible by INTERVAL
#endif

/* Number of entries in SRC_IP table. Should be divisible by 8. */
#define N_TABLE_SIZE 64 * 8

#if (N_TABLE_SIZE) % 8 != 0
#warning N_TABLE_SIZE should be divisible by 8
#endif

#define MIN_TIME_BETWEEN_REPORT 5 * 60

#if (MIN_TIME_BETWEEN_REPORT) % (INTERVAL) != 0
#warning MIN_TIME_BETWEEN_REPORT should be divisible by INTERVAL
#endif
/*
 * Number of descendants of each tree node ("order" or "branching factor" of
 * the tree).
 */
#define TREE_BRANCH_FACTOR 16

/**
 * Definition of fields used in UniRec templates (for both input and output
 * interfaces) in this example basic flow from flow_meter. This module
 * functions as a filter of flows forwarded by flow_meter, I need all fields
 * written below to be forwarded to the next module.
 */
UR_FIELDS (
   ipaddr SRC_IP,
   ipaddr DST_IP,
   uint64 BYTES,
   time   TIME_FIRST,
   time   TIME_LAST,
   uint64 EVENT_ID,
   uint16 EVENT_SEQ,
   uint64 AVG_BYTES_CURRENT,
   uint64 AVG_BYTES_ORIGINAL,
   uint32 AVG_IP_CNT_CURRENT,
   uint32 AVG_IP_CNT_ORIGINAL
)

trap_module_info_t *module_info = NULL;

/**
 * Definition of basic module information - module name, module description,
 * number of input and output interfaces.
 */
#define MODULE_BASIC_INFO(BASIC) \
   BASIC("ddos_detector", "A simple module for detection of extremely intensive flooding attacks.", 1, 1)

/**
 * Definition of module parameters - every parameter has short_opt, long_opt,
 * description, flag whether an argument is required or optional (NULL)
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16,
 * uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
   PARAM('m', "minimal_attack_size", "Minimal attack size (kb/s). Default value is 1000 kb/s.", required_argument, "uint64") \
   PARAM('b', "min_traffic_before_attack", "Minimal average traffic before attack (kb/s). Default value is 1 kb/s.", required_argument, "uint64") \
   PARAM('t', "threshold_flow_rate", "Rate, how many times must increase flow in next 2 windows compared to average of previous windows to be detected as flood attack.", required_argument, "uint16") \
   PARAM('c', "threshold_ip_count_rate", "Rate between the increase of number of unique SRC_IP addresses in next 2 windows and the average from previous windows to consider this behavior as a flood attack.", required_argument, "uint16") \
   PARAM('s', "mask_source_addresses", "Get only prefix bits from source addresses corresponding given mask, default value/mask is 24.", required_argument, "uint8") \
   PARAM('d', "mask_destination_addresses", "Get only prefix bits from destination addresses corresponding given mask, default value/mask is 32.", required_argument, "uint8") \
   PARAM('p', "min_threshold_before_pruning", "Minimal size of flow traffic (average of flow in windows) in kb/s which will not be removed. Entries containing less flow will be removed. Default value is 10kb/s.", required_argument, "uint64")

static int stop = 0;
/**
 * A function to handle SIGTERM and SIGINT signals (used to stop the module).
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * Struct with information about flood.
 */
typedef struct flood_s {
   uint32_t dst_ip;
   uint32_t last_reported;
   uint64_t total_bytes;
   uint64_t uuid;
   uint8_t msg_cnt;
   uint64_t avg_flow_original;
   uint64_t avg_flow_current;
   uint32_t avg_ip_cnt_original;
   uint32_t avg_ip_cnt_current;
   uint8_t window_cnt;
   bool is_valid;
} flood_t;

typedef struct dst_addr_record_s {
   uint64_t bytes_per_int[N_INTERVALS];
   uint16_t src_ip_per_int[N_INTERVALS];
   char src_ip_table[N_TABLE_SIZE / 8];
   uint64_t total;
   flood_t *flood_info;
} dst_addr_record_t;

typedef struct param_s {
   uint64_t minimal_attack_size;
   uint64_t min_threshold_pruning;
   uint64_t min_traffic_before_attack;
   uint16_t threshold_flow_rate;
   uint16_t threshold_ip_cnt_rate;
   uint8_t src_mask;
   uint8_t dst_mask;
} param_t;

static param_t param;

/* Current time - the highest TIME_LAST value seen so far (seconds only). */
uint32_t current_time = 0;

/*
 * Start of the current latest interval (i.e. current_time rounded down to
 * INTERVAL).
 */
uint32_t current_int_start = 0;

/* Index of the current interval in addr_record_t.bytes_per_int. */
int current_int_idx = N_INTERVALS - 1;

/***********************************************/

int compare_32b(void *a, void *b)
{
   uint32_t *h1, *h2;
   h1 = (uint32_t *) a;
   h2 = (uint32_t *) b;
   if (*h1 == *h2) {
      return EQUAL;
   } else if (*h1 < *h2) {
      return LESS;
   } else {
      return MORE;
   }
}

/**
 * A function that returns true only if the flood has been successfully
 * reported, otherwise returns false.
 */
bool report_flood(flood_t *flood_info, ur_template_t *out_tmplt, void *out_rec,
                  uint32_t time_last)
{
   if (flood_info == NULL) {
      fprintf(stderr, "ERROR: flood_info is NULL\n");
      return false;
   }
   if (out_tmplt == NULL || out_rec == NULL) {
      fprintf(stderr, "ERROR: output template is NULL\n");
      return false;
   }
   #ifdef DEBUG1
   printf("######## reporting flood:\n");
   char addr[64];
   ip_addr_t ip_key = ip_from_int((flood_info->dst_ip));
   ip_to_str(&ip_key, addr);
   printf("# DST_IP: %s\n", addr);
   printf("# BYTES: %lu\n", flood_info->total_bytes);
   printf("# DURATION: %u\n", time_last ? time_last - flood_info->last_reported : 0);
   printf("# TIME_FIRST: %u\n", flood_info->last_reported);
   #endif

   if (flood_info->window_cnt != 0) {
      flood_info->avg_flow_current /= flood_info->window_cnt * INTERVAL;
      flood_info->avg_ip_cnt_current /= flood_info->window_cnt;
   } else {
      flood_info->avg_flow_current = 0;
      flood_info->avg_ip_cnt_current = 0;
   }

   ur_set(out_tmplt, out_rec, F_DST_IP, ip_from_int(flood_info->dst_ip));
   ur_set(out_tmplt, out_rec, F_BYTES, flood_info->total_bytes);
   ur_set(out_tmplt, out_rec, F_TIME_FIRST, ur_time_from_sec_msec(flood_info->last_reported, 0));
   if (time_last == 0) {
      ur_set(out_tmplt, out_rec, F_TIME_LAST, ur_time_from_sec_msec(flood_info->last_reported, 0));
   } else {
      ur_set(out_tmplt, out_rec, F_TIME_LAST, ur_time_from_sec_msec(time_last, 0));
      flood_info->last_reported = time_last;
   }

   #ifdef DEBUG1
   printf("# TIME_LAST: %u\n", flood_info->last_reported);
   printf("# AVG_BYTES: %lu\n", flood_info->avg_flow_current);
   printf("# AVG_BYTES_ORIGINAL: %lu\n", flood_info->avg_flow_original / INTERVAL);
   printf("# AVG_IP_CNT: %u\n", flood_info->avg_ip_cnt_current);
   printf("# AVG_IP_CNT_ORIGINAL: %u\n", flood_info->avg_ip_cnt_original);
   printf("# EVENT_ID: %lu\n", flood_info->uuid);
   printf("# EVENT_SEQ: %u\n", flood_info->msg_cnt);
   printf("########\n");
   #endif

   ur_set(out_tmplt, out_rec, F_EVENT_ID, flood_info->uuid);
   ur_set(out_tmplt, out_rec, F_EVENT_SEQ, flood_info->msg_cnt);
   ur_set(out_tmplt, out_rec, F_AVG_BYTES_CURRENT, flood_info->avg_flow_current);
   ur_set(out_tmplt, out_rec, F_AVG_BYTES_ORIGINAL, flood_info->avg_flow_original / INTERVAL);
   ur_set(out_tmplt, out_rec, F_AVG_IP_CNT_CURRENT, flood_info->avg_ip_cnt_current);
   ur_set(out_tmplt, out_rec, F_AVG_IP_CNT_ORIGINAL, flood_info->avg_ip_cnt_original);

   flood_info->msg_cnt++;
   flood_info->total_bytes = 0;
   flood_info->avg_ip_cnt_current = 0;
   flood_info->avg_flow_current = 0;
   flood_info->window_cnt = 0;

   int ret_val = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));

   TRAP_DEFAULT_SEND_ERROR_HANDLING(ret_val, (void) 0, return false);
   return true;
}

/**
 * A function that moves each tree entry, returns whether the operation was
 * successfull.
 */
bool move_window(int move, bpt_t *b_plus_tree, ur_template_t *out_tmplt,
                 void *out_rec)
{

   #ifdef DEBUG2
   printf("Move window by %d\n", move);
   #endif
   /* Create a structure for iterating through the leaves. */
   bpt_list_item_t *b_item = bpt_list_init(b_plus_tree);
   if (b_item == NULL) {
      fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
      return false;
   }

   dst_addr_record_t *rec = NULL;
   int has_next = 0;

   /*
    * Get the first value from the list. Function returns 1 if there are more
    * values, 0 if there are no values.
    */
   has_next = bpt_list_start(b_plus_tree, b_item);
   while (has_next == 1) {
      int i, j;
      /* Get the value from B+ item structure */
      rec = b_item->value;
      if (rec == NULL) {
         /*There is a problem in the tree. This case should be unreachable*/
         fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
         bpt_list_clean(b_item);
         return false;
      }

      /* Check the end of the flood. */
      if (rec->flood_info != NULL && rec->flood_info->is_valid == true) {
         int last_flood = -1;
         for (i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS; ++i) {
            if (rec->bytes_per_int[i % N_INTERVALS] >= param.threshold_flow_rate * rec->flood_info->avg_flow_original
               && rec->src_ip_per_int[ i % N_INTERVALS] >= param.threshold_ip_cnt_rate * rec->flood_info->avg_ip_cnt_original) {
               last_flood = i - current_int_idx - 1;
            }
         }
         if (last_flood == -1) {
            if (rec->flood_info->avg_flow_original >= param.min_traffic_before_attack) {
               report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL);
            }
            free(rec->flood_info);
            rec->flood_info = NULL;
         } else if (last_flood < move) {
            for (i = current_int_idx + 1; i < current_int_idx + 1 + last_flood + 1; ++i) {
               rec->flood_info->total_bytes += rec->bytes_per_int[i % N_INTERVALS] - rec->flood_info->avg_flow_original;
            }
            if (rec->flood_info->avg_flow_original >= param.min_traffic_before_attack) {
               report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL);
            }
            free(rec->flood_info);
            rec->flood_info = NULL;
         }
      }

      /* Calculate the average flow and the number of SRC_IP before the flood. */
      if (rec->flood_info != NULL && rec->flood_info->is_valid == false) {
         /* Calculate the number of windows before the flood begins. */
         int int_size = (rec->flood_info->last_reported - current_int_start + (N_INTERVALS - 1) * INTERVAL) / INTERVAL;
         int empty_window = 0;
         if (int_size == 0) {
            fprintf(stderr, "ERROR during calculating average flow\n");
            bpt_list_clean(b_item);
            return false;
         }
         /* Skip windows with no traffic. */
         for (i = current_int_idx + 1; i < current_int_idx + 1 + int_size; ++i) {
            if (rec->bytes_per_int[i % N_INTERVALS] != 0) {
               break;
            }
            empty_window++;
         }
         for (; i < current_int_idx + 1 + int_size; ++i) {
            rec->flood_info->avg_flow_original += rec->bytes_per_int[i % N_INTERVALS];
            rec->flood_info->avg_ip_cnt_original += rec->src_ip_per_int[i % N_INTERVALS];
         }
         if (int_size - empty_window <= 0) {
            fprintf(stderr, "ERROR during calculating average flow\n");
            bpt_list_clean(b_item);
            return false;
         }
         rec->flood_info->avg_flow_original /= (int_size - empty_window);
         rec->flood_info->avg_ip_cnt_original /= (int_size - empty_window);
         rec->flood_info->is_valid = true;
      }

      /* Move window and set new intervals to 0. */
      if(rec->flood_info != NULL && rec->flood_info->is_valid == true) {
         int int_start = 0;
         if (current_int_start - (N_INTERVALS - 1) * INTERVAL < rec->flood_info->last_reported) {
            int_start = (rec->flood_info->last_reported - current_int_start + (N_INTERVALS - 1) * INTERVAL) / INTERVAL;
         }
         for (i = current_int_idx + 1 + int_start; i < current_int_idx + 1 + move; ++i) {
            if (rec->bytes_per_int[i % N_INTERVALS] > rec->flood_info->avg_flow_original) {
               rec->flood_info->total_bytes += rec->bytes_per_int[i % N_INTERVALS] - rec->flood_info->avg_flow_original;
               rec->flood_info->avg_ip_cnt_current += rec->src_ip_per_int[i % N_INTERVALS];
               rec->flood_info->avg_flow_current += rec->bytes_per_int[i % N_INTERVALS];
               rec->flood_info->window_cnt++;
            } else {
               /* TODO: End of the flood? */
               /* break; */
            }
         }
      }

      for (i = current_int_idx + 1; i < current_int_idx + 1 + move; ++i) {
         rec->total -= rec->bytes_per_int[i % N_INTERVALS];
         rec->bytes_per_int[i % N_INTERVALS] = 0;
         rec->src_ip_per_int[i % N_INTERVALS] = 0;
      }
      for (j = 0; j < N_TABLE_SIZE / 8; ++j) {
         rec->src_ip_table[j] = 0;
      }

      /* If there is no flow / bytes for ip address, leaf is deleted. */
      uint64_t bytes = 0;
      for (i = 0; i < N_INTERVALS; ++i) {
         bytes += rec->bytes_per_int[i];
      }

      if (rec->total <= param.min_threshold_pruning) {
         /* Delete the flood_info struct if it exists and report. */
         if (rec->flood_info != NULL) {
            if (rec->flood_info->is_valid == true
               && rec->flood_info->avg_flow_original >= param.min_traffic_before_attack) {
               report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL);
            }
            free(rec->flood_info);
            rec->flood_info = NULL;
         }
         has_next = bpt_list_item_del(b_plus_tree, b_item);
      } else {
         uint32_t time_last = current_int_start - (N_INTERVALS - 1 - move) * INTERVAL;
         if (rec->flood_info != NULL
            && rec->flood_info->last_reported + MIN_TIME_BETWEEN_REPORT <= time_last) {
            if (rec->flood_info->avg_flow_original >= param.min_traffic_before_attack) {
               report_flood(rec->flood_info, out_tmplt, out_rec, time_last);
            } else {
               free(rec->flood_info);
               rec->flood_info = NULL;
            }
         }
         has_next = bpt_list_item_next(b_plus_tree, b_item);
      }
   }
   bpt_list_clean(b_item);
   return true;
}

/**
 * A function that deletes a tree and additional allocated structure. Returns
 * true after a successful deletion, otherwise false.
 */
bool delete_tree(bpt_t *b_plus_tree, ur_template_t *out_tmplt, void *out_rec)
{
   /* Create a structure for iterating through the leaves. */
   bpt_list_item_t *b_item = bpt_list_init(b_plus_tree);
   if (b_item == NULL) {
      fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
      return false;
   }

   dst_addr_record_t *rec = NULL;
   int has_next = 0;

   /*
    * Get the first value from the list. Function returns 1 if there are more
    * values, 0 if there are no values.
    */
   has_next = bpt_list_start(b_plus_tree, b_item);
   while (has_next == 1) {
      /* Get value from B+ item structure. */
      rec = b_item->value;
      if (rec == NULL) {
         /* There is a problem in the tree. This case should be unreachable. */
         fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
         bpt_list_clean(b_item);
         return false;
      }
      /* Delete the flood_info struct if it exists and report. */
      if (rec->flood_info != NULL) {
         int i;
         if (rec->flood_info->is_valid == true){
            for (i = 0; i < N_INTERVALS; ++i) {
               if (rec->bytes_per_int[i] > rec->flood_info->avg_flow_original) {
                  rec->flood_info->total_bytes += rec->bytes_per_int[i] - rec->flood_info->avg_flow_original;
               }
               rec->flood_info->avg_ip_cnt_current += rec->src_ip_per_int[i];
               rec->flood_info->avg_flow_current += rec->bytes_per_int[i];
               rec->flood_info->window_cnt++;
            }
            if (rec->flood_info->avg_flow_original >= param.min_traffic_before_attack) {
               report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL);
            }
         }
         free(rec->flood_info);
         rec->flood_info = NULL;
      }
      has_next = bpt_list_item_next(b_plus_tree, b_item);
   }
   bpt_list_clean(b_item);

   bpt_clean(b_plus_tree);
   return true;
}

/**
 * A function that returns an index for SRC_IP in src_ip_table.
 */
uint32_t get_index(ip_addr_t *src_ip)
{
   /* TODO find some better hash function */
   return ip_get_v4_as_int(src_ip) % (N_TABLE_SIZE - 1);
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;

   ip_addr_t *src_ip = NULL;
   ip_addr_t *dst_ip = NULL;
   void *out_rec = NULL;
   ur_template_t *out_tmplt = NULL;
   ur_template_t *in_tmplt = NULL;
   uint32_t key;

   param.minimal_attack_size = 1000 * 1000 / 8 * INTERVAL;
   param.min_threshold_pruning = 10 * 1000 / 8 * INTERVAL * N_INTERVALS;
   param.min_traffic_before_attack = 1 * 1000 / 8 * INTERVAL;
   param.threshold_flow_rate = 4;
   param.threshold_ip_cnt_rate = 4;
   param.src_mask = 24;
   param.dst_mask = 32;

   bpt_t *b_plus_tree = NULL;

   /***** TRAP initialization *****/

   /*
    * Macro allocates and initializes module_info structure according to
    * MODULE_BASIC_INFO and MODULE_PARAMS definitions on the lines 161 and 167 of
    * this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for
    * getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   /*
    * Let TRAP library parse program arguments, extract its parameters and
    * initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /*
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   /*
    * Parse program arguments defined by MODULE_PARAMS macro with getopt()
    * function (getopt_long() if available).  This macro is defined in config.h
    * file generated by configure script.
    */

   bool invalid_argument = false;

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1
      && invalid_argument == false) {
      switch (opt) {
      case 'm':
         if (sscanf(optarg,"%" SCNu64, &param.minimal_attack_size) != 1) {
            invalid_argument = true;
         } else {
            param.minimal_attack_size = param.minimal_attack_size * INTERVAL * 1000 / 8;
         }
         break;

      case 'p':
         if (sscanf(optarg,"%" SCNu64, &param.min_threshold_pruning) != 1) {
            invalid_argument = true;
         } else {
            param.min_threshold_pruning = param.min_threshold_pruning * INTERVAL * N_INTERVALS * 1000 / 8;
         }
         break;

      case 'b':
         if (sscanf(optarg,"%" SCNu64, &param.min_traffic_before_attack) != 1) {
            invalid_argument = true;
         } else {
            param.min_traffic_before_attack = param.min_traffic_before_attack * INTERVAL * 1000 / 8;
         }
         break;

      case 't':
         if (sscanf(optarg,"%" SCNu16, &param.threshold_flow_rate) != 1) {
            invalid_argument = true;
         }
         break;

      case 'c':
         if (sscanf(optarg,"%" SCNu16, &param.threshold_ip_cnt_rate) != 1) {
            invalid_argument = true;
         }
         break;

      case 's':
         if (sscanf(optarg,"%" SCNu8, &param.src_mask) != 1) {
            invalid_argument = true;
         }
         break;

      case 'd':
         if (sscanf(optarg,"%" SCNu8, &param.dst_mask) != 1) {
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

   if (param.src_mask > 32 || param.dst_mask > 32) {
      fprintf(stderr, "Invalid value of argument. Mask must be between 0 and 32.\n");
      goto cleanup;
   }

   b_plus_tree = bpt_init(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_32b, sizeof(dst_addr_record_t), sizeof(uint32_t));
   if (b_plus_tree == NULL) {
      fprintf(stderr, "ERROR: Could not initialize B_PLUS_TREE\n");
      goto cleanup;
   }

   /***** Create UniRec templates *****/
   in_tmplt = ur_create_input_template(0, "DST_IP,SRC_IP,BYTES,TIME_FIRST,TIME_LAST", NULL);
   if (in_tmplt == NULL) {
      fprintf(stderr, "Error: Input template could not be created.\n");
      goto cleanup;
   }
   out_tmplt = ur_create_output_template(0, "DST_IP,BYTES,TIME_FIRST,TIME_LAST,EVENT_ID,EVENT_SEQ,AVG_BYTES_CURRENT,AVG_BYTES_ORIGINAL,AVG_IP_CNT_CURRENT,AVG_IP_CNT_ORIGINAL", NULL);
   if (out_tmplt == NULL) {
      fprintf(stderr, "Error: Output template could not be created.\n");
      goto cleanup;
   }

   /* Allocate memory for output record */
   out_rec = ur_create_record(out_tmplt, 0);
   if (out_rec == NULL) {
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      goto cleanup;
   }

   /* Initializes random number generator */
   srand(time(NULL));

   /***** Main processing loop *****/

   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      int i;

      /* Receive data from input interface 0. */
      /*
       * Block if data are not available immediately (unless a timeout is set
       * using trap_ifcctl)
       */

      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

      /* Handle possible errors */
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      src_ip = &ur_get(in_tmplt, in_rec, F_SRC_IP);
      dst_ip = &ur_get(in_tmplt, in_rec, F_DST_IP);
      src_ip->ui32[2] &= htonl((uint32_t)0xffffffff << (32 - param.src_mask));
      dst_ip->ui32[2] &= htonl((uint32_t)0xffffffff << (32 - param.dst_mask));


      /* Filter ip_v4 addresses only. */
      if (ip_is4(dst_ip) != 1) {
         continue;
      }

      #ifdef DEBUG2
      char addr[64];
      ip_to_str(src_ip, addr);
      printf("%s\t(%u)\t",addr, get_index(src_ip));
      ip_to_str(dst_ip, addr);
      printf("->%s\t",addr);
      printf("(%lu)\n",ur_get(in_tmplt, in_rec, F_BYTES));
      #endif

      /* Check the size of received data. */
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; /* End of data (used for testing purposes) */
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                  ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      /**** Time handling ****/
      /* Set current time */
      uint32_t flow_end = ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_LAST));
      if (flow_end > current_time) {
         /*
          * If this is the first flow or if the difference from last time is
          * too large (this can happen when invalid flow with timestamp far in
          * the future arrives, or when input stream was interrupted for some
          * time)->(re)initialize everything
          */
         if (flow_end - current_time > INTERVAL * N_INTERVALS) {
            if (current_time != 0) {
               fprintf(stderr, "WARNING: Received flow with timestamp too far in the future compared to previous flows. Assuming the input was interrupted for some time. Re-initializing all data structures.\n");
            }
            current_time = flow_end;

            /* Delete and re-create whole B+ tree */
            if (delete_tree(b_plus_tree, out_tmplt, out_rec) != true) {
               goto cleanup;
            }

            /*
             * Set interval start to the closest "rounded" interval before
             * (or equal to) the flow end.
             */
            current_int_start = flow_end - flow_end % INTERVAL;

            b_plus_tree = NULL;
            b_plus_tree = bpt_init(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_32b, sizeof(dst_addr_record_t), sizeof(uint32_t));
            if (b_plus_tree == NULL) {
               fprintf(stderr, "ERROR: Could not reinitialize B_PLUS_TREE\n");
               goto cleanup;
            }
         }
         /* Set current_time to the end timestamp of the current flow. */
         current_time = flow_end;
      }

      /* Move time windows if necessary. */
      if (current_time >= current_int_start + INTERVAL) {
         int move = (current_time - current_int_start) / INTERVAL;
         if (move_window(move, b_plus_tree, out_tmplt, out_rec) == false) {
            goto cleanup;
         }
         current_int_idx = (current_int_idx + move) % N_INTERVALS;
         current_int_start += INTERVAL * move;
      }

      /* Search the records for dst_ip. */
      key = ip_get_v4_as_int(dst_ip);

      void *new_item = bpt_search_or_insert(b_plus_tree, &key);
      if (new_item == NULL) {
         fprintf(stderr, "ERROR: could not allocate dst_addr_record_t structure in leaf node of the B+ tree.\n");
         goto cleanup;
      }

      uint64_t bytes = ur_get(in_tmplt, in_rec, F_BYTES);
      uint32_t flow_start = ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_FIRST));
      uint32_t dur = flow_end - flow_start + 1;

      if (flow_end < flow_start) {
         fprintf(stderr, "WARNING: Received flow with TIME_LAST < TIME_FIRST. It will be ignored.\n");
         continue;
      }

      /*
       * The end of a flow should always be before the end of the current
       * interval (if a flow with TIME_LAST greater than end of the current
       * interval arrives, a new interval(s) is/are created).
       **/
      assert(flow_end < current_int_start + INTERVAL);

      dst_addr_record_t *rec = new_item;

      uint32_t src_ip_idx = get_index(src_ip);
      uint32_t src_ip_bit = src_ip_idx % 8;
      src_ip_idx /= 8;

      if ((rec->src_ip_table[src_ip_idx] & (1 << src_ip_bit)) == 0) {
         rec->src_ip_table[src_ip_idx] |= (1 << src_ip_bit);
         rec->src_ip_per_int[current_int_idx]++;
      }

      for (i = 0; i < N_INTERVALS && bytes > 0; ++i) {
         uint32_t int_start = current_int_start - i * INTERVAL;
         uint32_t int_end = int_start + INTERVAL;
         int int_idx = (current_int_idx - i + N_INTERVALS) % N_INTERVALS;

         /*
          * If flow ends before the start of this interval, go to the next (i.e.
          * older) interval.
          */
         if (flow_end < int_start) {
            continue;
         }

         /*
          * Flow starts in this interval - store the rest of bytes into this
          * interval and stop.
          */
         if (flow_start >= int_start) {
            rec->bytes_per_int[int_idx] += bytes;
            rec->total += bytes;
            break;
         }
         /*
          * If we getopt there, only a part of the flow lies within this
          * interval.
          */
         if (flow_end > int_end) {
            /* Flow runs over the whole interval. */
            uint64_t bytes_portion = bytes * INTERVAL / dur;
            rec->bytes_per_int[int_idx] += bytes_portion;
            rec->total += bytes_portion;
            bytes -= bytes_portion;
            dur -= INTERVAL;
            break;
         } else {
            /*
             * Flow ends inside this interval.
             * +1 because the end of the flow is inside the interval, see note
             * above.
             */
            uint32_t seconds_in_interval = flow_end - int_start + 1;
            uint64_t bytes_portion = bytes * seconds_in_interval / dur;
            rec->bytes_per_int[int_idx] += bytes_portion;
            rec->total += bytes_portion;
            bytes -= bytes_portion;
            dur -= seconds_in_interval;
         }
      }

      uint64_t avg_flow = 0;
      uint64_t avg_ip_cnt = 0;
      uint8_t empty_window = 0;

      /*
       * For each of the 2 following windows check if bytes per second are
       * threshold_flow_rate times higher than the average of preceding
       * windows and the same for SRC_IP. Each flood must be higher than
       * minimal_attack_size.
       */

      if (rec->flood_info == NULL) {
         /* Skip windows with no traffic. */
         for (i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS - 2; ++i) {
            if (rec->bytes_per_int[i % N_INTERVALS] != 0) {
               break;
            }
            empty_window++;
         }
         for (; i < current_int_idx + 1 + N_INTERVALS - 2; ++i) {
            avg_flow += rec->bytes_per_int[i % N_INTERVALS];
            avg_ip_cnt += rec->src_ip_per_int[i % N_INTERVALS];
            uint64_t current_avg_flow = avg_flow / (i - current_int_idx - empty_window);
            uint64_t current_avg_ip_cnt = avg_ip_cnt / (i - current_int_idx - empty_window);
            if (current_avg_flow * param.threshold_flow_rate < rec->bytes_per_int[(i + 1) % N_INTERVALS]
               && current_avg_flow * param.threshold_flow_rate < rec->bytes_per_int[(i + 2) % N_INTERVALS]
               && rec->bytes_per_int[(i + 1) % N_INTERVALS] > param.minimal_attack_size
               && rec->bytes_per_int[(i + 2) % N_INTERVALS] > param.minimal_attack_size
               && current_avg_ip_cnt * param.threshold_ip_cnt_rate < rec->src_ip_per_int[(i + 1) % N_INTERVALS]
               && current_avg_ip_cnt * param.threshold_ip_cnt_rate < rec->src_ip_per_int[(i + 2) % N_INTERVALS]
               ) {
               rec->flood_info = (flood_t *) calloc(sizeof(flood_t), 1);
               if (rec->flood_info == NULL) {
                  fprintf(stderr, "ERROR: Could not initialize flood_info struct.\n");
                  goto cleanup;
               }
               int relative_flood_begin = (current_int_idx - i - 1 + N_INTERVALS) % N_INTERVALS;
               rec->flood_info->last_reported = current_int_start - INTERVAL * relative_flood_begin;
               rec->flood_info->dst_ip = key;
               rec->flood_info->uuid = (uint64_t) rand() << 32;
               rec->flood_info->uuid += (uint32_t) key;
               break;
            }
         }
      }
   }

   #ifdef DEBUG1
   /* End - print whole tree */
   printf("--- END - printing all records ---\n");
   /* Create a structure for iterating through the leaves */
   bpt_list_item_t *b_item = bpt_list_init(b_plus_tree);
   if (b_item == NULL) {
      fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
      goto cleanup;
   }

   dst_addr_record_t *rec = NULL;
   int has_next = 0;

   /*
    * Get first value from the list. Function returns 1 if there are more
    * values, 0 if there is no value.
    */
   has_next = bpt_list_start(b_plus_tree, b_item);
   while (has_next == 1) {
      /* Get the value from B+ item structure. */
      rec = b_item->value;
      if (rec == NULL) {
         /* There is problem in the tree. This case should be unreachable. */
         fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
         bpt_list_clean(b_item);
         goto cleanup;
      }
      /* Convert key to IP address and print. */
      char addr[64];
      ip_addr_t ip_key = ip_from_int( *(uint32_t *) (b_item->key));
      ip_to_str(&ip_key, addr);
      printf("%s  %lu\t\n", addr, rec->total);

      has_next = bpt_list_item_next(b_plus_tree, b_item);
   }
   bpt_list_clean(b_item);
   #endif

   /***** Cleanup *****/
cleanup:
   fflush(stderr);

   delete_tree(b_plus_tree, out_tmplt, out_rec);

   /* Do all the necessary cleanup in libtrap before exiting. */
   TRAP_DEFAULT_FINALIZATION();

   /* Release the memory allocated for module_info structure. */
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   /* Free UniRec templates and output record. */
   ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_finalize();

   return 0;
}
