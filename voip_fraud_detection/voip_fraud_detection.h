/**
 * \file voip_fraud_detection.h
 * \brief VoIP fraud detection module - header file
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

#include <prefix_tree.h>

#ifndef VOIP_FRAUD_DETECTION_H
#define	VOIP_FRAUD_DETECTION_H

// version of module
#define MODULE_VERSION "0.0.1"

// UniRec template definition
#define UNIREC_INPUT_TEMPLATE "<COLLECTOR_FLOW>,<VOIP>"

// enable debug mode
#define DEBUG

// temp test
#define TEST_DEBUG

// enable checking format of sip messages
#define SIP_HEADER_ISPECTION

// default values of module parameters
#define DEFAULT_MAX_PREFIX_LENGTH 4
#define DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD 5
#define DEFAULT_DETECTION_INTERVAL 10

// default size of hashing table for storing IP addresses
#define HASH_TABLE_IP_SIZE 100000

// define ID of states
#define STATE_NO_ATTACK 0
#define STATE_ATTACK_DETECTED 1

// length of buffer in inttostr() function
#define LENGTH_BUFFER_INTTOSTR 10

// maximum string length of node in prefix tree
#define MAX_STRING_PREFIX_TREE_NODE 100

// prefix of error message
#define LOG_ERROR_PREFIX "ERR_voip_fraud_detection#"

// Function macro for printing messages
#define PRINT_STD(...) write_std(get_actual_time_string(),";", __VA_ARGS__, NULL)
#define PRINT_LOG(...) write_to_log(get_actual_time_string(),";", __VA_ARGS__, NULL)
#define PRINT_STD_LOG(...) write_std(get_actual_time_string(),";", __VA_ARGS__, NULL);write_to_log(get_actual_time_string(),";", __VA_ARGS__, NULL)
#define PRINT_STD_LOG_NOTDATETIME(...) write_std(__VA_ARGS__, NULL);write_to_log(__VA_ARGS__, NULL)

typedef struct ip_item_struct {
   prefix_tree_t * tree;
   time_t time_last_check;
} ip_item;


// functions
char * get_actual_time_string();
char * inttostr(int integer);
void print_error(int error_number, char * error_description);
void write_to_log(char * str, ...);
void write_std(char * str, ...);
void cut_sip_identifier_from_string(char ** str, int * str_len);
int is_numeric_participant(char * str, int str_len);
int detect_prefix_examination(prefix_tree_t * tree, prefix_tree_inner_node_t * node);

#endif	/* VOIP_FRAUD_DETECTION_H */
