/**
 * \file ddos_detector.c
 * \brief Module for detecting volumetric DDoS attacks.
 * \author Otto Hollmann <hollmott@fit.cvut.cz>
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \author Marek Svepes <svepemar@fit.cvut.cz>
 * \author Jaroslav Hlavac <hlavaj20@fit.cvut.cz>
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

//#define DEBUG1
//#define DEBUG2

//#define TCP_PROTOCOL 0x6
//#define TCP_FLAGS_SYN 0x2

#define NUM_OF_ITEMS_IN_TREE_LEAF 5

// ----------------------------------------------------------------------
// Module parameters (not run-time configurable to allow compile-time optimizations)

#define INTERVAL 60   // base interval in seconds (average amount of traffic per this interval is computed and comapred to threshod)
#define MAX_FLOW_LEN 330   // maximum duration of flows (i.e. active timeout set on exporter(s)) in seconds
#define MAX_FLOW_DELAY 90 //60  // maximum delay of flow records (i.e. how long can it take for a flow from last seen packet to arrival of the flow record to this module; or inactive timeout + some time to travel from exporter to the module)
  // according to experiments, delay of 120s never happens, 90 very few times, 60 happens normally so 60 is good value (at CESNET's deployment)
#define N_INTERVALS ((MAX_FLOW_LEN+MAX_FLOW_DELAY)/INTERVAL)   // number of intervals of history to store
// history must be stored because flows can be longer than base intervals so we sometimes need to update more intervals than just the latest one.

// Note: MAX_FLOW_LEN+MAX_FLOW_DELAY should be divisible by INTERVAL

#if (MAX_FLOW_LEN + MAX_FLOW_DELAY) % INTERVAL != 0
   #warning (MAX_FLOW_LEN + MAX_FLOW_DELAY) should be divisible by INTERVAL
#endif

#define TREE_BRANCH_FACTOR 16 // number of descendants of each tree node ("order" or "branching factor" of the tree)


/**
 * Definition of fields used in unirec templates (for both input and output interfaces) in this example basic flow from flow_meter
 */
/*This module functions as a filter of flows forwarded by flow_meter, I need all fields written below to be forwarded to the next module.*/
UR_FIELDS ( 
	ipaddr SRC_IP,
	ipaddr DST_IP,
	uint64 BYTES,
	time   TIME_FIRST,
	time   TIME_LAST,
	uint64 EVENT_ID,
	uint8  EVENT_TYPE

	//time   TIME,
	//uint64 LINK_BIT_FIELD,
	//uint32 PACKETS,
	//uint16 DST_PORT,
	//uint16 SRC_PORT,
	//uint8 DIR_BIT_FIELD,
	//uint8 PROTOCOL,
	//uint8 TCP_FLAGS,
	//uint8 TOS,
	//uint8 TTL
)


trap_module_info_t *module_info = NULL;

/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("ddos_detector", "A simple module for detection of extremely intensive flooding attacks.", 1, 1)


/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
 //TODO
#define MODULE_PARAMS(PARAM) \
  PARAM('m', "min flow", "Minimal flow (B/s), which is checked for threshold.", required_argument, "uint64") \
  PARAM('t', "threshold flow rate", "Threshold rate between flow in current window and average of flow in previous windows.", required_argument, "uint64") \
  PARAM('s', "mask source addresses", "mask source addresses, default value is 24", required_argument, "uint8") \
  PARAM('d', "mask destination addresses", "mask destination addresses, default value is 32", required_argument, "uint8") \
  PARAM('p', "min threshold before pruning", "min threshold flow before pruning leaf in tree in (B/s), default value is 0", required_argument, "uint8")
  //PARAM(char, char *, char *, no_argument  or  required_argument, char *)
static int stop = 0;
/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
  * Struct for information about flood.
  */
typedef struct flood_s {
	uint32_t dst_ip;
	uint32_t last_reported;
	uint32_t total_bytes;
	uint64_t uuid;
	uint8_t	 msg_cnt;
	uint8_t  src_ip_cnt;
} flood_t;


typedef struct dst_addr_record_s {
	uint64_t	bytes_per_int[N_INTERVALS];
	//uint32_t	flows_per_int[N_INTERVALS];
	uint64_t	total;
	bpt_t * 	subtree;
	flood_t *   flood_info;
	//TPC, UDP count
} dst_addr_record_t;


typedef struct src_addr_record_s {
	uint64_t	bytes_per_int[N_INTERVALS];
	//uint32_t	flows_per_int[N_INTERVALS];
	uint64_t	total;
	bool		flood;
	uint32_t	avg_flow;
} src_addr_record_t;


uint32_t current_time = 0; // Current time - highest TIME_LAST value (seconds only) seen so far
uint32_t current_int_start = 0; // Start of currently latest interval (i.e. current_time rounded down to INTERVAL)
int current_int_idx = N_INTERVALS-1; // Index to the current interval in addr_record_t.bytes_per_int
/***********************************************/

int compare_32b(void *a, void *b)
{
	uint32_t *h1, *h2;
	h1 = (uint32_t*)a;
	h2 = (uint32_t*)b;
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

bool report_flood(flood_t * flood_info, ur_template_t * out_tmplt, void * out_rec, uint32_t time_last){
	#ifdef DEBUG1
		printf("######## reporting flood:\n");
			char addr[64];
			ip_addr_t ip_key = ip_from_int((flood_info->dst_ip));
			ip_to_str(&ip_key, addr);
		printf("# DST_IP: %s\n", addr);
		printf("# BYTES: %u\n", flood_info->total_bytes);
		printf("# TIME_FIRST: %u\n", flood_info->last_reported);
		printf("# TIME_LAST: %u\n", time_last);
		printf("# DURATION: %u\n", time_last - flood_info->last_reported);
		printf("# EVENT_ID: %lu\n", flood_info->uuid);
		printf("# EVENT_TYPE: %u\n", flood_info->msg_cnt);
		printf("# SRC_IP_CNT: %u\n", flood_info->src_ip_cnt);
		printf("########\n");
	#endif


	ur_set(out_tmplt, out_rec, F_DST_IP, ip_from_int(flood_info->dst_ip));
	ur_set(out_tmplt, out_rec, F_BYTES, flood_info->total_bytes);
	ur_set(out_tmplt, out_rec, F_TIME_FIRST, flood_info->last_reported);
	if (time_last == 0){
		ur_set(out_tmplt, out_rec, F_TIME_LAST, flood_info->last_reported);
	} else {
		ur_set(out_tmplt, out_rec, F_TIME_LAST, time_last);
		flood_info->last_reported = time_last;
	}
	//TODO
	ur_set(out_tmplt, out_rec, F_EVENT_ID, flood_info->uuid);
	ur_set(out_tmplt, out_rec, F_EVENT_TYPE, flood_info->msg_cnt);

	flood_info->msg_cnt++;
	flood_info->total_bytes = 0;

	int ret_val = trap_send(0, out_rec, ur_rec_size(out_tmplt, out_rec));

	TRAP_DEFAULT_SEND_ERROR_HANDLING(ret_val, (void) 0, return false);
	return true;
}

void move_window(int move, bpt_t * b_plus_tree, ur_template_t * out_tmplt, void * out_rec,
				 uint32_t threshold_flow_rate, uint64_t min_flow, uint8_t min_threshold_pruning){

	#ifdef DEBUG2
		printf("Move window by %d.\n", move);
	#endif
	// Create a structure for iterating throw the leaves
	bpt_list_item_t *b_item = bpt_list_init(b_plus_tree);
	if (b_item == NULL) {
		fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
		return;
	}

	dst_addr_record_t *rec = NULL;
	int has_next = 0;

	// Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
	has_next = bpt_list_start(b_plus_tree, b_item);
	while (has_next == 1) {
		// Get the value from B+ item structure
		rec = b_item->value;
		if (rec == NULL) {
			//There is problem in the tree. This case should be unreachable
			fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
			bpt_list_clean(b_item);
			return;
		}

		// Move window and set new intervals to 0
		for (int i = current_int_idx + 1; i < current_int_idx + 1 + move; ++i){
			rec->total -= rec->bytes_per_int[i%N_INTERVALS];
			rec->bytes_per_int[i%N_INTERVALS] = 0;
			//rec->flows_per_int[i%N_INTERVALS] = 0;
		}

		// If there is no flow / bytes for ip address, leaf is deleted
		//TODO mělo by být stejné jako rec->total
		uint64_t bytes = 0;
		//uint64_t flows = 0;
		for (int i = current_int_idx + 1 + move; i < current_int_idx + 1 + N_INTERVALS - move; ++i){
			bytes += rec->bytes_per_int[i%N_INTERVALS];
			////flows += rec->flows_per_int[i%N_INTERVALS];
		}
		if (bytes <= min_threshold_pruning){
			//Delete subtree if exists
			if (rec->subtree != NULL){
				bpt_clean(rec->subtree);
			}
			//delete flood_info struct if exists and report
			if (rec->flood_info != NULL){
				report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL);
				free(rec->flood_info);
				rec->flood_info = NULL;
			}
			has_next = bpt_list_item_del(b_plus_tree, b_item);
		} else {
			// move subtree
			if (rec->subtree != NULL){
				// Create a structure for iterating throw the leaves of subtree
				bpt_list_item_t *b_subtree_item = bpt_list_init(rec->subtree);
				if (b_subtree_item == NULL) {
					fprintf(stderr, "ERROR: could not initialize a list iterator structure for subtree\n");
					bpt_list_clean(b_item);
					return;
				}

				src_addr_record_t * subtree_rec = NULL;
				int subtree_has_next = 0;

				// Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
				subtree_has_next = bpt_list_start(rec->subtree, b_subtree_item);
				while (subtree_has_next == 1) {
					// Get the value from B+ item structure
					subtree_rec = b_subtree_item->value;
					if (subtree_rec == NULL) {
						//there is problem in the tree. This case should be unreachable
						fprintf(stderr, "ERROR during iteration through the subtree. Value is NULL\n");
						bpt_list_clean(b_subtree_item);
						bpt_list_clean(b_item);
						return;
					}

					// calculate average flow befor flood
					if (subtree_rec->flood == true && subtree_rec->avg_flow == 0){
						uint32_t avg_flow = 0;
						for (int i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS - 1; ++i){
							avg_flow += subtree_rec->bytes_per_int[i % N_INTERVALS];
							uint64_t current_avg = avg_flow / (i - current_int_idx);
							if (current_avg > min_flow
								&& current_avg * threshold_flow_rate < subtree_rec->bytes_per_int[(i + 1) % N_INTERVALS]){
									subtree_rec->avg_flow = current_avg;
									break;
							}
						}
					}

					//check end of flood
					if (subtree_rec->flood == true && subtree_rec->avg_flow != 0){
						int last_flood = -1;
						for (int i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS - 1; ++i){
							if (subtree_rec->bytes_per_int[(i + 1) % N_INTERVALS] >= 2*subtree_rec->avg_flow){
								last_flood = i - current_int_idx;
							}
						}
						if (last_flood == -1){
							subtree_rec->flood = false;
							subtree_rec->avg_flow = 0;
							rec->flood_info->src_ip_cnt--;
						} else if (last_flood < move) {
							for (int i = current_int_idx + 1; i < current_int_idx + 1 + last_flood - 1; ++i){
								rec->flood_info->total_bytes += subtree_rec->bytes_per_int[(i + 1) % N_INTERVALS] - subtree_rec->avg_flow;
							}	
							subtree_rec->flood = false;
							subtree_rec->avg_flow = 0;
							rec->flood_info->src_ip_cnt--;
						}
					}

					// Move window and set new intervals to 0
					for (int i = current_int_idx + 1; i < current_int_idx + 1 + move; ++i){
						if(rec->flood_info != NULL && subtree_rec->avg_flow != 0){
							if (subtree_rec->bytes_per_int[i%N_INTERVALS] > subtree_rec->avg_flow){
								rec->flood_info->total_bytes += subtree_rec->bytes_per_int[i%N_INTERVALS] - subtree_rec->avg_flow;
							}
						}
						subtree_rec->total -= subtree_rec->bytes_per_int[i%N_INTERVALS];
						subtree_rec->bytes_per_int[i%N_INTERVALS] = 0;
						//subtree_rec->flows_per_int[i%N_INTERVALS] = 0;
					}
					if (subtree_rec->total <= min_threshold_pruning){
						if (rec->flood_info != NULL && subtree_rec->flood == true){
							rec->flood_info->src_ip_cnt--;
						}
						subtree_has_next = bpt_list_item_del(rec->subtree, b_subtree_item);
					} else {
						subtree_has_next = bpt_list_item_next(rec->subtree, b_subtree_item);
					}
				}
				bpt_list_clean(b_subtree_item);
			}
			if (rec->flood_info != NULL
				&& rec->flood_info->last_reported + INTERVAL * (N_INTERVALS * 2 - 1) <= current_int_start +INTERVAL * move){
					report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL * (move - N_INTERVALS));
			} else if (rec->flood_info != NULL
				&& rec->flood_info->src_ip_cnt == 0){
					report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL * (move - N_INTERVALS));
					free(rec->flood_info);
					rec->flood_info = NULL;
			}

			has_next = bpt_list_item_next(b_plus_tree, b_item);
		}
	}
	bpt_list_clean(b_item);
}


bool delete_tree(bpt_t * b_plus_tree, ur_template_t * out_tmplt, void * out_rec){
	
	// Create a structure for iterating throw the leaves
	bpt_list_item_t *b_item = bpt_list_init(b_plus_tree);
	if (b_item == NULL) {
		fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
		return false;
	}

	dst_addr_record_t *rec = NULL;
	int has_next = 0;

	// Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
	has_next = bpt_list_start(b_plus_tree, b_item);
	while (has_next == 1) {
		// Get the value from B+ item structure
		rec = b_item->value;
		if (rec == NULL) {
			//there is problem in the tree. This case should be unreachable
			fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
			bpt_list_clean(b_item);
			return false;
		}
		//delete subtree if exists
		if (rec->subtree != NULL){
			bpt_clean(rec->subtree);
		}
		//delete flood_info struct if exists and report
		if (rec->flood_info != NULL){
			report_flood(rec->flood_info, out_tmplt, out_rec, current_int_start + INTERVAL);
			free(rec->flood_info);
			rec->flood_info = NULL;
		}
		has_next = bpt_list_item_next(b_plus_tree, b_item);
		//has_next = bpt_list_item_del(b_plus_tree, b_item);
	}
	bpt_list_clean(b_item);
	
	bpt_clean(b_plus_tree);
	return true;
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
	uint32_t subtree_key;

	uint64_t min_flow = 250 * INTERVAL;
	uint8_t  min_threshold_pruning = 0 * INTERVAL;
	uint64_t threshold_flow_rate = 4;
	uint8_t src_mask = 24;
	uint8_t dst_mask = 32;

	bpt_t * b_plus_tree = NULL;

	/* **** TRAP initialization **** */

	/*
	 * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
	 * definitions on the lines 69 and 77 of this file. It also creates a string with short_opt letters for getopt
	 * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
	 */
	INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
	/*
	 * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
	 */
	TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

	/*
	 * Register signal handler.
	 */
	TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

	/*
	 * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
	 * This macro is defined in config.h file generated by configure script
	 */
	while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
		switch (opt) {
			case 'm':
				min_flow = atoi(optarg) * INTERVAL;
				break;
			case 'p':
				min_threshold_pruning = atoi(optarg) * INTERVAL;
				break;
			case 't':
				threshold_flow_rate = atoi(optarg);
				break;
			case 's':
				src_mask = atoi(optarg);
				break;
			case 'd':
				dst_mask = atoi(optarg);
				break;
			default:
				fprintf(stderr, "Invalid arguments.\n");
				FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
				TRAP_DEFAULT_FINALIZATION();
				return -1;
		}
	}

	if (src_mask > 32 || dst_mask > 32){
		fprintf(stderr, "Invalid value of argument. Mask must be between 0 and 32.\n");
		goto cleanup;
	}

	b_plus_tree = bpt_init(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_32b, sizeof(dst_addr_record_t), sizeof(uint32_t));
	if (b_plus_tree == NULL) {
		fprintf(stderr, "ERROR: Could not initialize B_PLUS_TREE\n");
		goto cleanup;
	}

	/* **** Create UniRec templates **** */
	//in_tmplt = ur_create_input_template(0, "DST_IP,SRC_IP,BYTES,TIME_FIRST,TIME_LAST,TIME", NULL);
	in_tmplt = ur_create_input_template(0, NULL, NULL);
	if (in_tmplt == NULL){
		fprintf(stderr, "Error: Input template could not be created.\n");
		goto cleanup;
	}
	out_tmplt = ur_create_output_template(0, "DST_IP,BYTES,TIME_FIRST,TIME_LAST,EVENT_ID,EVENT_TYPE", NULL);
	//out_tmplt = ur_create_output_template(0, "DST_IP,BYTES,TIME_FIRST,TIME_LAST", NULL);
	if (out_tmplt == NULL){
		fprintf(stderr, "Error: Output template could not be created.\n");
		goto cleanup;
	}

	// Allocate memory for output record
	out_rec = ur_create_record(out_tmplt, 0);
	if (out_rec == NULL){
		fprintf(stderr, "Error: Memory allocation problem (output record).\n");
		goto cleanup;
	}

	/* Intializes random number generator */
	srand (time(NULL));

	/* **** Main processing loop **** */

	while (!stop) {
		const void *in_rec;
		uint16_t in_rec_size;

		// Receive data from input interface 0.
		// Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
		ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

		// Handle possible errors
		TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

		src_ip = &ur_get(in_tmplt, in_rec, F_SRC_IP);
		dst_ip = &ur_get(in_tmplt, in_rec, F_DST_IP);
		src_ip->ui32[2] &= htonl((uint32_t)0xffffffff << (32 - src_mask));
		dst_ip->ui32[2] &= htonl((uint32_t)0xffffffff << (32 - dst_mask));

		
		// Filter ip_v4 addresses only
		if (ip_is4(dst_ip) != 1) {
			continue;
		}

		#ifdef DEBUG2
			char addr[64];
			ip_to_str(src_ip, addr);
			printf("%s\t",addr);  
			ip_to_str(dst_ip, addr);
			printf("->%s\t",addr);
			printf("(%lu)\n",ur_get(in_tmplt, in_rec, F_BYTES));
		#endif

		// Check size of received data
		if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
			if (in_rec_size <= 1) {
				break; // End of data (used for testing purposes)
			} else {
				fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
						ur_rec_fixlen_size(in_tmplt), in_rec_size);
				break;
			}
		}

		/* *** Time handling *** */
		// Set current time
		uint32_t flow_end = ur_time_get_sec(ur_get(in_tmplt, in_rec, F_TIME_LAST));
		if (flow_end > current_time) {
			/* If this is the first flow or if there is too large difference from 
				last time (this can happen when invalid flow with timestamp far in 
				the furute arrives, or when input stream was interrupted for some
				time)->(re)initialize everything
			*/
			if (flow_end - current_time > INTERVAL * N_INTERVALS) {
				if (current_time != 0) {
					fprintf(stderr, "WARNING: Received flow with timestamp too far in the future compared to previous flows. Assuming the input was interrupted for some time. Re-initializing all data structures.\n");
				}
				current_time = flow_end;
			
				// Delete and re-create whole B+ tree
				if (delete_tree(b_plus_tree, out_tmplt, out_rec) != true){
					goto cleanup;
				}

				// Set interval start to the closet "rounded" interval before (or equal to) the flow end 
				current_int_start = flow_end - flow_end % INTERVAL;
				
				b_plus_tree = NULL;
				b_plus_tree = bpt_init(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_32b, sizeof(dst_addr_record_t), sizeof(uint32_t));
				if (b_plus_tree == NULL) {
					fprintf(stderr, "ERROR: Could not reinitialize B_PLUS_TREE\n");
					goto cleanup;
				}
			}
			// set current_time to the end timestamp of current flow
			current_time = flow_end;
		}

		// Move time windows if necessary
		if (current_time >= current_int_start + INTERVAL){
			int move = (current_time - current_int_start) / INTERVAL;
			move_window(move, b_plus_tree, out_tmplt, out_rec,threshold_flow_rate, min_flow, min_threshold_pruning);
			current_int_idx = (current_int_idx + move) % N_INTERVALS;
			current_int_start += INTERVAL * move;
		}

		// Search record for dst_ip
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
			goto cleanup;
		}

   		// the end of a flow should always be before the end of the current interval (if a flow with TIME_LAST greter than end of the current interval arrives, a new interval(s) is/are created)
   		assert(flow_end < current_int_start + INTERVAL);

		dst_addr_record_t *bpt_record = new_item;
		src_addr_record_t *bpt_subtree_record = NULL;
		
		// Search record for src_ip
		if (bpt_record->subtree != NULL){
			subtree_key = ip_get_v4_as_int(src_ip);
			subtree_key &= htonl((uint32_t)0xffffffff >> (32 - src_mask));
			//subtree_key = ip_get_v4_as_int(src_ip & htonl((uint32_t)0xffffffff << (32 - src_mask)));
			
			//printf("key %u, subtree_key %u\n", key, subtree_key);

			new_item = bpt_search_or_insert(bpt_record->subtree, &subtree_key);
			if (new_item == NULL) {
				fprintf(stderr, "ERROR: could not allocate src_addr_record_t structure in leaf node of the B+ tree.\n");
				goto cleanup;
			}
			bpt_subtree_record = new_item;
		}

		for (int i = 0; i < N_INTERVALS && bytes > 0; ++i){
			uint32_t int_start = current_int_start - i*INTERVAL;
			uint32_t int_end = int_start + INTERVAL;
			// +N_INTERVALS is here to avoid negative dividend would result in negative result of modulo operation)
			int int_idx = (current_int_idx - i + N_INTERVALS) % N_INTERVALS;

			// Flow ends before this interval starts, go to the next (i.e. older) interval
			if (flow_end < int_start) {
				continue;
			}

			// Flow starts in this interval - store the rest of bytes into this interval and stop
			if (flow_start >= int_start) {
				bpt_record->bytes_per_int[int_idx]+=bytes;
				//bpt_record->flows_per_int[int_idx]++;
				if (bpt_record->subtree != NULL){
					bpt_subtree_record->bytes_per_int[int_idx]+=bytes;
					//bpt_subtree_record->flows_per_int[int_idx]++;
					bpt_subtree_record->total += bytes;
				}
				bpt_record->total += bytes;
				//bytes = 0;
				//dur = 0;
				break;
			}
			// if we get there, only a part of the flow lies within this interval
			// store portion of bytes proportional to portion of flow duration lying in this interval and go the next one
			if (flow_end > int_end) { // flow runs over the whole interval
				uint64_t bytes_portion = bytes * INTERVAL / dur;
				bpt_record->bytes_per_int[int_idx]+=bytes_portion;
				//bpt_record->flows_per_int[int_idx]++;
				bpt_record->total += bytes_portion;
				if (bpt_record->subtree != NULL){
					bpt_subtree_record->bytes_per_int[int_idx]+=bytes_portion;
					//bpt_subtree_record->flows_per_int[int_idx]++;
					bpt_subtree_record->total += bytes_portion;
				}
				bytes -= bytes_portion;
				dur -= INTERVAL;
			} else { 
				// flow ends inside this interval
				uint32_t seconds_in_interval = flow_end - int_start + 1; // +1 because flow end is inclusive, see note above
				uint64_t bytes_portion = bytes * seconds_in_interval / dur;
				bpt_record->bytes_per_int[int_idx]+=bytes_portion;
				//bpt_record->flows_per_int[int_idx]++;
				bpt_record->total += bytes_portion;
				if (bpt_record->subtree != NULL){
					bpt_subtree_record->bytes_per_int[int_idx]+=bytes_portion;
					//bpt_subtree_record->flows_per_int[int_idx]++;
					bpt_subtree_record->total += bytes_portion;
				}
				bytes -= bytes_portion;
				dur -= seconds_in_interval;
			}
		}

		uint64_t avg = 0;

		//Create subtree if needed
		if (bpt_record->subtree == NULL){
			for (int i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS - 1; ++i){	
					avg += bpt_record->bytes_per_int[i % N_INTERVALS];
				uint64_t current_avg = avg / (i - current_int_idx);
				if (current_avg > min_flow 
				&& current_avg * threshold_flow_rate < bpt_record->bytes_per_int[(i + 1) % N_INTERVALS]
				&& bpt_record->subtree == NULL){
					bpt_record->subtree = bpt_init(NUM_OF_ITEMS_IN_TREE_LEAF, &compare_32b, sizeof(src_addr_record_t), sizeof(uint32_t));
					if (bpt_record->subtree == NULL) {
						fprintf(stderr, "ERROR: Could not initialize B_PLUS_TREE for src records.\n");
						//goto cleanup; //TODO
					}
					break;
				}
			}
		} else {
			// For each 2 following window check, if bytes per second are threshold_flow_rate times higher than average of previous windows
			// Each average must be higher than min_flow to avoid false detection

			for (int i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS - 2; ++i){
					avg += bpt_subtree_record->bytes_per_int[i % N_INTERVALS];
				uint64_t current_avg = avg / (i - current_int_idx);
				if (current_avg > min_flow
					&& current_avg * threshold_flow_rate < bpt_subtree_record->bytes_per_int[(i + 1) % N_INTERVALS]
					&& current_avg * threshold_flow_rate < bpt_subtree_record->bytes_per_int[(i + 2) % N_INTERVALS]){
						if (bpt_record->flood_info == NULL){
							bpt_record->flood_info = (flood_t *) calloc(sizeof(flood_t), 1);
							if (bpt_record->flood_info == NULL){
								fprintf(stderr, "ERROR: Could not initialize flood_info struct.\n");
								goto cleanup;
							}
							bpt_record->flood_info->last_reported = current_int_start - INTERVAL * (N_INTERVALS - 1 - i + current_int_idx);
							bpt_record->flood_info->dst_ip = key;
							bpt_record->flood_info->uuid = (uint64_t) rand() << 32;
							bpt_record->flood_info->uuid += (uint32_t) key;
							report_flood(bpt_record->flood_info, out_tmplt, out_rec, 0);
							
							if (bpt_subtree_record->flood == false){
								bpt_subtree_record->flood = true;
								bpt_record->flood_info->src_ip_cnt++;
							}
						}
				}
			}
		}
	}

	#ifdef DEBUG1
		// End - print whole tree
		puts("--- END - printing all records ---");
		// Create a structure for iterating throw the leaves
		bpt_list_item_t *b_item = bpt_list_init(b_plus_tree);
		if (b_item == NULL) {
			fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
			goto cleanup;
		}

		dst_addr_record_t *rec = NULL;
		int has_next = 0;

		// Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
		has_next = bpt_list_start(b_plus_tree, b_item);
		while (has_next == 1) {
			// Get the value from B+ item structure
			rec = b_item->value;
			if (rec == NULL) {
				//there is problem in the tree. This case should be unreachable
				fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
				bpt_list_clean(b_item);
				goto cleanup;
			}
			// Convert key to IP address and print
			char addr[64];
			ip_addr_t ip_key = ip_from_int( *(uint32_t*)(b_item->key));
			ip_to_str(&ip_key, addr);
			printf("%s  %lu\t", addr, rec->total);  
			//printf("%d  %s  %lu\t",rec->flood, addr, rec->total);

			// Print total bytes per interval for current IP address
			for (int i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS; ++i){
				//printf("%lu %u   ", rec->bytes_per_int[i % N_INTERVALS], rec->flows_per_int[i % N_INTERVALS]);
			}
			printf("\n");

			if (rec->subtree != NULL){
				// Create a structure for iterating throw the leaves
				bpt_list_item_t *b_subtree_item = bpt_list_init(rec->subtree);
				if (b_subtree_item == NULL) {
					fprintf(stderr, "ERROR: could not initialize a list iterator structure\n");
					goto cleanup;
				}

				src_addr_record_t *subtree_rec = NULL;
				int subtree_has_next = 0;

				// Get first value from the list. Function returns 1 if there are more values, 0 if there is no value
				subtree_has_next = bpt_list_start(rec->subtree, b_subtree_item);
				while (subtree_has_next == 1) {
					// Get the value from B+ item structure
					subtree_rec = b_subtree_item->value;
					if (subtree_rec == NULL) {
						//there is problem in the tree. This case should be unreachable
						fprintf(stderr, "ERROR during iteration through the tree. Value is NULL\n");
						bpt_list_clean(b_subtree_item);
						goto cleanup;
					}
					// Convert key to IP address and print
					char src_addr[64];
					ip_addr_t ip_key = ip_from_int( *(uint32_t*)(b_subtree_item->key));
					ip_to_str(&ip_key, src_addr);
					printf("%d  %s  %lu\t",subtree_rec->flood, src_addr, subtree_rec->total);  
					//printf("%d  %s  %lu\t",rec->flood, src_addr, rec->total);  

					// Print total bytes per interval for current IP address
					for (int i = current_int_idx + 1; i < current_int_idx + 1 + N_INTERVALS; ++i){
						//printf("\t\t%lu %u   ", subtree_rec->bytes_per_int[i % N_INTERVALS], subtree_rec->flows_per_int[i % N_INTERVALS]);
					}
					printf("\n");

					subtree_has_next = bpt_list_item_next(rec->subtree, b_subtree_item);
				}
				bpt_list_clean(b_subtree_item);
			}
			has_next = bpt_list_item_next(b_plus_tree, b_item);
		}
		bpt_list_clean(b_item);

	#endif



	/* **** Cleanup **** */
cleanup:
 	fflush(stderr);

	delete_tree(b_plus_tree, out_tmplt, out_rec);

	// Do all necessary cleanup in libtrap before exiting
	TRAP_DEFAULT_FINALIZATION();

	// Release allocated memory for module_info structure
	FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

	// Free unirec templates and output record
	ur_free_record(out_rec);
	ur_free_template(in_tmplt);
	ur_free_template(out_tmplt);
	ur_finalize();

	return 0;
}
