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

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <prefix_tree.h>
#include <nemea-common.h>
#include "configuration.h"
#include "cache_node_no_attack.h"
#include "output.h"


#ifndef VOIP_FRAUD_DETECTION_H
#define VOIP_FRAUD_DETECTION_H

/** \brief Version of module. */
#define MODULE_VERSION "0.0.4"

/** \brief Definition ID of detection state NO_ATTACK. */
#define STATE_NO_ATTACK 0

/** \brief Definition ID of detection state ATTACK. */
#define STATE_ATTACK_DETECTED 1

/** \brief VOIP_PACKET_TYPE in the flow record used to request type: call oriented (defined by VoIP plugin). */
#define VOIP_PACKET_TYPE_REQUEST_CALL_ORIENTED 3

/** \brief VOIP_PACKET_TYPE in the flow record used to response type: service oriented (defined by VoIP plugin). */
#define VOIP_PACKET_TYPE_RESPONSE_SERVICE_ORIENTED 2

/** \brief VOIP_PACKET_TYPE in the flow record used to response type: call oriented (defined by VoIP plugin). */
#define VOIP_PACKET_TYPE_RESPONSE_CALL_ORIENTED 4


/** \brief Last used Event ID of attack detection. */
uint32_t last_event_id;

/** \brief UniRec input and output template. */
ur_template_t *ur_template_in, *ur_template_out;

/** \brief Pointer to received data from trap_recv(). */
const void *in_rec;

/** \brief Detection record for sending detection events to output interface. */
void * detection_record;

/** \brief IP item structure.
 * It contains a tree pointer and last check time of detection.
 */
typedef struct ip_item_struct {
   prefix_tree_t * tree; /**< Pointer to prefix_tree. */
   time_t first_invite_request; /**< Last check time of detection. */
   time_t time_last_check; /**< Last check time of detection. */
   time_t time_last_communication; /**< Last communication time of the IP address. */
   time_t time_attack_detected_prefix_examination; /**< Last detection of prefix examination attack. */
   char * attack_sip_to; /**< One of SIP_TO that was evaluated as prefix examination in the last attack. */
   uint32_t attack_event_id; /**< Event ID of the last attack. */
   uint16_t attack_prefix_length; /**< Prefix length of attack_sip_to (in the last prefix examination attack). */
   unsigned int detection_event_count; /**< Number of detected attack events for the IP. */
   unsigned int attack_detected_count; /**< Number of detected attacks for the IP. */
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
   unsigned int detection_event_count;
   unsigned int attack_detected_count;
   unsigned long int received_invite_flow_count;
   unsigned int invalid_sip_identifier_count;
};

/** \brief Definition and initialization of global_module_statistic (global_module_statistic_struct).
 */
struct global_module_statistic_struct global_module_statistic = {0, 0, 0, 0};

#ifdef DEBUG

/** \brief Global request and response SIP statistic structure.
 * It contains global statistic about SIP protocol processed by module.
 */
struct global_sip_statistic_struct {
   unsigned long int ok_count;
   unsigned long int ack_count;
   unsigned long int cancel_count;
   unsigned long int bye_count;
   unsigned long int invite_count;
   unsigned long int trying_count;
   unsigned long int ringing_count;
   unsigned long int service_ok_count;
   unsigned long int forbidden_count;
   unsigned long int unauthorized_count;
   unsigned long int proxy_auth_req_count;
};

/** \brief Definition and initialization of global_sip_statistic (global_sip_statistic_struct).
 */
struct global_sip_statistic_struct global_sip_statistic = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#endif

/** \brief Detection of attack structure.
 */
struct detection_struct {
   uint32_t invite;
   uint32_t ack;
   uint32_t cancel;
   uint32_t bye;
   uint32_t ok;
   uint32_t unique_ok;
   uint32_t trying;
   uint32_t ringing;
   uint32_t service_ok;
   uint32_t forbidden;
   uint32_t unauthorized;
   uint32_t rtcp_data;
   uint32_t proxy_auth_req;

   time_t time; /**< Save time of start detection process for the IP address. */
   char sip_to[MAX_STRING_PREFIX_TREE_NODE + 1]; /**< One of SIP_TO that was evaluated as prefix examination in the attack. */
   uint32_t prefix_examination_count; /**< Number of unique SIP_TO that was evaluated as prefix examination attack. */
   prefix_tree_inner_node_t * report_node; /**< Pointer to one node from prefix examination attack for reporting. */
   uint16_t report_prefix_length; /**< Prefix length of report_node (in prefix examination attack). */
};

/** \brief Definition of detection_statistic (detection_statistic_struct).
 */
struct detection_struct detection;


/** \brief Load Event ID counter from defined file.
 * \param[in] file definition of file path.
 */
void load_event_id(char * file);

/** \brief Save Event ID counter to defined file.
 * \param[in] file definition of file path.
 */
void save_event_id(char * file);

/** \brief Initialization of node_data.
 * \param[in] node Determine node to initializes its node_data.
 * \return Return 0 if node_data are successfully initialized, -1 if memory error occurs.
 */
int check_initialize_node_data(prefix_tree_domain_t * prefix_tree_node);

/** \brief Find if Call-ID exists in node_data.
 * \param[in] node Pointer to node, in which is done searching.
 * \param[in] call_id Call_id to search in node_data.
 * \param[in] call_id_len Length of call_id string to search.
 * \return Return 1 if Call-ID exists in node_data, 0 otherwise.
 */
int call_id_node_data_exists(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len);

/** \brief Save Call-ID to node_data.
 * \param[in] node Pointer to node to save node_data.
 * \param[in] call_id Call_id to save in node_data.
 * \param[in] call_id_len Length of call_id string to save.
 */
void call_id_node_data_save(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len);

/** \brief Check and free memory, that wasn't used for long time or exceeds limit of items (memory management of module).
 * \param[in] hash_table Pointer to hash table.
 */
void check_and_free_module_memory(cc_hash_table_v2_t * hash_table);

/** \brief Reset detection statistics used to count SIP requests and responses. */
void reset_detection_statistics();

/** \brief Function to thorough count of prefix detection minus value and save information about attack to detection_struct.
 * \param[in] tree ...
 * \param[in] node ...
 * \param[in] sum_prefix_down ...
 * \return Return value for decrementing of basic calculation prefix_sum_count.
 */
unsigned int count_minus_detection_value(prefix_tree_t * tree, prefix_tree_inner_node_t * node, unsigned int sum_prefix_down);

/** \brief Cut SIP identifier from input string
 * Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' + string after it.
 * \param[out] output_str Pointer to result string
 * \param[in] input_str Input string.
 * \param[in,out] str_len Length of input string./Length of output string.
 * \return Return 0 if sip identifier is valid, otherwise -1.
 */
int cut_sip_identifier_from_string(char ** output_str, char * input_str, int * str_len);

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

/** \brief Copy char array field from UniRec to defined string_output, update string_len and add terminating '\0' at the end of char array.
 * \param[in] string_output Pointer for saving output char array.
 * \param[in,out] string_len Length of saved char array (without terminating '\0')
 * \param[in] unirec_field_id ID of UniRec field
 * \param[in] max_length maximum length of string from UniRec field
 */
void get_string_from_unirec(char * string_output, int * string_len, int unirec_field_id, int max_length);

#endif	/* VOIP_FRAUD_DETECTION_H */
