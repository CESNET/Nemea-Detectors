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
#define VOIP_FRAUD_DETECTION_H

/** \brief Version of module. */
#define MODULE_VERSION "0.0.2"

/** \brief UniRec input template definition. */
#define UNIREC_INPUT_TEMPLATE "<COLLECTOR_FLOW>,<VOIP>"

/** \brief Enable debug mode. */
#define DEBUG

/** \brief Enable testing mode. */
#define TEST_DEBUG

/** \brief Default value of max_prefix_length.
 * If parameter max_prefix_length not set at startup of module, then this default value is used. */
#define DEFAULT_MAX_PREFIX_LENGTH 4

/** \brief Default value of min_lenght_called_number.
 * If parameter min_lenght_called_number not set at startup of module, then this default value is used. */
#define DEFAULT_MIN_LENGTH_CALLED_NUMBER 0

/** \brief Default value of prefix_examination_detection_threshold.
 * If parameter prefix_examination_detection_threshold not set at startup of module, then this default value is used. */
#define DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD 10

/** \brief Default value of detection_interval.
 * If parameter detection_interval not set at startup of module, then this default value is used. */
#define DEFAULT_DETECTION_INTERVAL 10

/** \brief Default value of detection_pause_after_attack.
 * If parameter detection_pause_after_attack not set at startup of module, then this default value is used. */
#define DEFAULT_DETECTION_PAUSE_AFTER_ATTACK 60

/** \brief Default size of hashing table for storing IP addresses. */
#define HASH_TABLE_IP_SIZE 100000

/** \brief Definition ID of detection states. */
#define STATE_NO_ATTACK 0
#define STATE_ATTACK_DETECTED 1

/** \brief Maximum length of SIP_FROM. */
#define MAX_LENGTH_SIP_FROM 100

/** \brief Maximum length of SIP_TO. */
#define MAX_LENGTH_SIP_TO 100

/** \brief Length of buffer in inttostr() function. */
#define LENGTH_BUFFER_INTTOSTR 10

/** \brief Maximum string length of node in prefix tree. */
#define MAX_STRING_PREFIX_TREE_NODE 100

/** \brief Maximum size of cache_no_attack. */
#define MAX_CACHE_NO_ATTACK_SIZE 100

/** \brief Prefix of error message. */
#define LOG_ERROR_PREFIX "ERR_voip_fraud_detection#"

/** \brief IP item structure.
 * It contains a tree pointer and last check time of detection.
 */
typedef struct ip_item_struct {
   prefix_tree_t * tree; /**< Pointer to prefix_tree. */
   time_t time_last_check; /**< Last check time of detection. */
   time_t time_attack_detected_prefix_examination; /**< Last detection of prefix examination attack. */
   unsigned int attack_count; /**< Number of attacks for the IP. */
} ip_item;

/** \brief Node data structure.
 * It contains numbers of invite, cancel, ack, bay requests and ok response.
 */
typedef struct node_data_struct {
   unsigned int invite_count; /**< Number of INVITE requests. */
   unsigned int cancel_count; /**< Number of CANCEL requests. */
   unsigned int ack_count; /**< Number of ACK requests. */
   unsigned int bye_count; /**< Number of BYE requests. */
   unsigned int ok_count; /**< Number of OK responses. */

   unsigned int trying_count; /**< Number of trying responses. */
   unsigned int ringing_count; /**< Number of ringing responses. */
   unsigned int service_ok_count; /**< Number of service OK responses. */

   unsigned int rtp_data; /**< Indication of RTP data. */
} node_data;

/** \brief Function macro for printing to standard output with actual datetime.
 * Unlimited input parameters are printed to standard output with actual datetime at the beginning of text.
 */
#define PRINT_STD(...) write_std(get_actual_time_string(),";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to log file with actual datetime.
 * Unlimited input parameters are printed to log files with actual datetime at the beginning of text.
 */
#define PRINT_LOG(...) write_to_log(get_actual_time_string(),";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard output and log file at the same time with actual datetime .
 * Unlimited input parameters are printed to standard output and log file at the same time with actual
 * datetime at the beginning of text.
 */
#define PRINT_STD_LOG(...) write_std(get_actual_time_string(),";", __VA_ARGS__, NULL);write_to_log(get_actual_time_string(),";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard output and log file at the same time.
 * Unlimited input parameters are printed to standard output and log file at the same time with actual
 * datetime at the beginning of text.
 */
#define PRINT_STD_LOG_NOTDATETIME(...) write_std(__VA_ARGS__, NULL);write_to_log(__VA_ARGS__, NULL)


/** \brief Return actual date and time in system default format.
 * \return String with actual date and time.
 */
char * get_actual_time_string();
char * inttostr(int integer);
void print_error(int error_number, char * error_description);
void write_to_log(char * str, ...);
void write_std(char * str, ...);
unsigned int count_minus_detection_value(prefix_tree_t * tree, prefix_tree_inner_node_t * node, int sum_prefix_down);

/** \brief Cut SIP identifier from input string
 * Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' + string after it.
 * \param[out] output_str Pointer to result string
 * \param[in] input_str Input string.
 * \param[in,out] str_len Length of input string./Length of output string.
 * \param[in] input_description Description of input sip identifier. It is used for logging purpose.
 * \return Return 0 if sip identifier is valid, otherwise -1.
 */
int cut_sip_identifier_from_string(char ** output_str, char * input_str, int * str_len, char * input_description);

/** \brief Check if input string is numeric participant
 * Check if input string is numeric with allowed special char ('+','*','#') or this text part before '@' + check of minimum numeric length.
 * \param[in] str Input string to test.
 * \param[in] str_len Integer - length of input string.
 * \return Return 1 if input string is numeric_participant, 0 otherwise.
 */
int is_numeric_participant(char * str, int str_len);

/** \brief Detection prefix examination in input prefix tree
 * \param[in] tree Pointer to prefix_tree.
 * \param[in] node Pointer to start node of detection.
 * \return ID that indicates results of testing (STATE_NO_ATTACK or STATE_ATTACK_DETECTED).
 */
int detect_prefix_examination(prefix_tree_t * tree, prefix_tree_inner_node_t * node);

#endif	/* VOIP_FRAUD_DETECTION_H */
