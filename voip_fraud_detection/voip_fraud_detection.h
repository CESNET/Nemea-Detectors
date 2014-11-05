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

/** \brief Maximum length of Call-ID. */
#define MAX_LENGTH_CALL_ID 80

/** \brief Maximum number of Call-ID item in storage. */
#define CALL_ID_STORAGE_SIZE 20

/** \brief Length of buffer in inttostr() function. */
#define LENGTH_BUFFER_INTTOSTR 10

/** \brief Maximum string length of node in prefix tree. */
#define MAX_STRING_PREFIX_TREE_NODE 100

/** \brief Maximum size of cache_no_attack. */
#define MAX_CACHE_NO_ATTACK_SIZE 100

/** \brief Prefix of error message. */
#define LOG_ERROR_PREFIX "ERR_voip_fraud_detection#"

/** \brief Modul_configuration structure.
 * It is used for saving modul configuration.
 */
struct modul_configuration_struct {
   unsigned int max_prefix_length;
   unsigned int min_length_called_number;
   unsigned int prefix_examination_detection_threshold;
   unsigned int detection_interval;
   unsigned int detection_pause_after_attack;
   char * log_file;
};

/** \brief Definition of modul_configuration (modul_configuration_struct).
 */
struct modul_configuration_struct modul_configuration;

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

   unsigned int forbidden_count; /**< Number of FORBIDDEN responses. */
   unsigned int unauthorized_count; /**< Number of UNAUTHORIZED responses. */
   unsigned int proxy_auth_req_count; /**< Number of PROXY AUTH REQUEST responses. */

   unsigned int rtp_data; /**< Indication of RTP data. */

   char call_id[CALL_ID_STORAGE_SIZE][MAX_LENGTH_CALL_ID + 1]; /**< Storage for Call-ID of INVITE request (call_id storage). */
   unsigned int call_id_insert_position; /**< Position of insert for call_id storage. */
   char call_id_full; /**< Indication if call_id storage is full (0=not full; 1=full). */
} node_data;

/** \brief Global module statistic structure.
 */
struct global_module_statistic_struct {
   unsigned int num_attack_detected;
   unsigned long long num_invite_flow;
   unsigned int num_invalid_sip_identifier;
};

/** \brief Definition and initialization of global_module_statistic (global_module_statistic_struct).
 */
struct global_module_statistic_struct global_module_statistic = {0, 0, 0};

#ifdef DEBUG

/** \brief Global request and response SIP statistic structure.
 * It contains global statistic about SIP protocol processed by module.
 */
struct global_sip_statistic_struct {
   unsigned int ok_count;
   unsigned int ack_count;
   unsigned int cancel_count;
   unsigned int bye_count;
   unsigned int invite_count;
   unsigned int trying_count;
   unsigned int ringing_count;
   unsigned int service_ok_count;
   unsigned int forbidden_count;
   unsigned int unauthorized_count;
   unsigned int proxy_auth_req_count;
};

/** \brief Definition and initialization of global_sip_statistic (global_sip_statistic_struct).
 */
struct global_sip_statistic_struct global_sip_statistic = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#endif

/** \brief Detection statistic structure.
 */
struct detection_statistic_struct {
   unsigned int invite;
   unsigned int ack;
   unsigned int cancel;
   unsigned int bye;
   unsigned int ok;
   unsigned int trying;
   unsigned int ringing;
   unsigned int service_ok;
   unsigned int forbidden;
   unsigned int unauthorized;
   unsigned int rtcp_data;
   unsigned int proxy_auth_req;
};

/** \brief Definition of detection_statistic (detection_statistic_struct).
 */
struct detection_statistic_struct detection_statistic;

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
int cache_no_attack_exists(prefix_tree_inner_node_t * node);
void cache_no_attack_save(prefix_tree_inner_node_t * node);
void cache_no_attack_clear();
int call_id_node_data_exists(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len);
void call_id_node_data_save(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len);
int check_initialize_node_data(prefix_tree_domain_t * prefix_tree_node, uint8_t voip_packet_type);
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
