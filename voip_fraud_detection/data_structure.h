/**
 * \file data_structure.h
 * \brief VoIP fraud detection module - data_structure - header file
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

#ifndef VOIP_FRAUD_DETECTION_DATA_STRUCTURE_H
#define VOIP_FRAUD_DETECTION_DATA_STRUCTURE_H

#include <time.h>
#include <prefix_tree.h>
#include "configuration.h"
#include "output.h"

extern struct modul_configuration_struct modul_configuration;
extern struct detection_prefix_examination_struct detection_prefix_examination;
extern struct global_module_statistic_struct global_module_statistic;
#ifdef DEBUG
extern struct global_sip_statistic_struct global_sip_statistic;
#endif

/** \brief Definition ID of detection state NO_ATTACK. */
#define STATE_NO_ATTACK 0

/** \brief Definition ID of detection state ATTACK. */
#define STATE_ATTACK_DETECTED 1

/** \brief Definition ID of learning countries active mode. */
#define COUNTRIES_LEARNING_MODE 0

/** \brief Definition ID of active detection of calling to different countries. */
#define COUNTRIES_DETECTION_MODE_ON 1

/** \brief Definition ID of disabled detection of calling to different countries. */
#define COUNTRIES_DETECTION_MODE_OFF 2

/** \brief Modul_configuration structure.
 * It is used for saving modul configuration.
 */
typedef struct modul_configuration_struct {
   unsigned int max_prefix_length; /**< Maximum prefix length. */
   unsigned int min_length_called_number; /**< Minimum length of called number. */
   unsigned int prefix_examination_detection_threshold; /**< Detection threshold of prefix examination. */
   unsigned int detection_interval; /**< Detection interval in seconds. */
   unsigned int detection_pause_after_attack; /**< Detection pause after attack in seconds. */
   unsigned int max_item_prefix_tree; /**< Maximum item in suffix tree. */
   unsigned int clear_data_no_communication_after; /**< Clear data without communication after defined seconds. */
#ifdef ENABLE_GEOIP
   unsigned int learning_countries_period; /**< Time in seconds for learning mode of calling to different countries. */
   unsigned char countries_detection_mode; /**< Indication of actual detection mode of calling to different country. */
   char * countries_file; /**< Setting of countries file. */
   char * allowed_countries; /**< List of allowed countries for all IP addresses. */
   unsigned int allowed_countries_count; /**< Number of allowed countries for all IP addresses. */
   short int disable_saving_new_country; /**< Indication if new country is saved to list of allowed countries for defined IP address. */
#endif
   char * log_file; /**< Setting of log file. */
   char * event_id_file; /**< Setting of event_id file. */
   char * prefix_statistic_file; /**< Setting of prefix statistic file. */
} modul_configuration_t;

/** \brief IP item structure.
 * Every IP address has this structure saved in hash table.
 */
typedef struct ip_item_struct {
   time_t first_invite_request; /**< Time of first INVITE request for the IP address. */
   time_t time_last_communication; /**< Time of last communication time of the IP address. */

   prefix_tree_t * tree; /**< Pointer to suffix tree. */
   time_t time_last_check_prefix_examination; /**< Time of last check time for prefix examination. */
   time_t time_attack_detected_prefix_examination; /**< Time of last detection of prefix examination attack. */
   char * prefix_examination_attack_sip_to; /**< One of SIP_TO that was evaluated as prefix examination in the last attack. */
   uint32_t prefix_examination_attack_event_id; /**< Event ID of the last prefix examination attack. */
   uint16_t prefix_examination_attack_prefix_length; /**< Prefix length of attack_sip_to (in the last prefix examination attack). */
   unsigned int prefix_examination_detection_event_count; /**< Number of detected prefix examination attack events for the IP. */
   unsigned int prefix_examination_attack_detected_count; /**< Number of detected prefix examination attacks for the IP. */

   time_t time_attack_detected_call_different_country; /**< Time last detection of calling to different country. */
   uint32_t call_different_country_attack_event_id; /**< Event ID of the last calling to different country attack. */
   char call_different_country_attack_country[2]; /**< Country of calling in last attack. */
   unsigned int call_different_country_detection_event_count; /**< Number of detected call to different country attack events for the IP. */
   unsigned int call_different_country_attack_detected_count; /**< Number of detected call to different country attacks for the IP. */
   char country[COUNTRY_STORAGE_SIZE][2]; /**< Storage of countries for IP address. */
   unsigned int country_count; /**< Number of saved countries for the IP address. */
} ip_item_t;

/** \brief Node data structure.
 * Every node of suffix tree has this structure for saving required items.
 */
typedef struct node_data_struct {
   unsigned int invite_count; /**< Number of INVITE requests. */
   unsigned int cancel_count; /**< Number of CANCEL requests. */
   unsigned int ack_count; /**< Number of ACK requests. */
   unsigned int bye_count; /**< Number of BYE requests initiated by calling party. */
   unsigned int ok_count; /**< Number of OK responses. */
   unsigned int trying_count; /**< Number of TRYING responses. */
   unsigned int ringing_count; /**< Number of RINGING responses. */
   unsigned int forbidden_count; /**< Number of FORBIDDEN responses. */
   unsigned int unauthorized_count; /**< Number of UNAUTHORIZED responses. */
   unsigned int proxy_auth_req_count; /**< Number of PROXY AUTH REQUEST responses. */
   char rtp_data; /**< Indication of RTP data (0=no; 1=yes). */
   uint32_t user_agent_hash; /**< User-Agent hash of INVITE request. */
   uint32_t call_id_hash[MAX_CALL_ID_STORAGE_SIZE]; /**< Storage for Call-ID hashes of INVITE request (call_id_hash storage). */
   unsigned int call_id_insert_position; /**< Position of insert for call_id storage. */
   char call_id_full; /**< Indication if call_id storage is full (0=not full; 1=full). */
} node_data_t;

/** \brief Global module statistic structure.
 */
typedef struct global_module_statistic_struct {
   unsigned int prefix_examination_detection_event_count; /**< Number of total detected prefix examination attack events. */
   unsigned int prefix_examination_attack_detected_count; /**< Number of total detected prefix examination attacks. */
   unsigned int call_different_country_detection_event_count; /**< Number of total detected call to different country attack events. */
   unsigned int call_different_country_attack_detected_count; /**< Number of total detected call to different country attacks. */
   unsigned long int received_invite_flow_count; /**< Number of total received invite flows. */
   unsigned int invalid_sip_identifier_count; /**< Number of total invalid SIP identifier. */
} global_module_statistic_t;


#ifdef DEBUG

/** \brief Global request and response SIP statistic structure.
 * It contains global statistic about SIP protocol processed by module.
 */
typedef struct global_sip_statistic_struct {
   unsigned long int invite_count; /**< Number of INVITE requests. */
   unsigned long int cancel_count; /**< Number of CANCEL requests. */
   unsigned long int ack_count; /**< Number of ACK requests. */
   unsigned long int bye_count; /**< Number of BYE requests initiated by calling party. */
   unsigned long int ok_count; /**< Number of OK responses. */
   unsigned long int trying_count; /**< Number of TRYING responses. */
   unsigned long int ringing_count; /**< Number of RINGING responses. */
   unsigned long int forbidden_count; /**< Number of FORBIDDEN responses. */
   unsigned long int unauthorized_count; /**< Number of UNAUTHORIZED responses. */
   unsigned long int proxy_auth_req_count; /**< Number of PROXY AUTH REQUEST responses. */
   unsigned long int unique_user_agent_count; /**< Number of unique User-Agent header in INVITE requests. */
} global_sip_statistic_t;

#endif

/** \brief Detection_prefix_examination structure.
 * Structure is used during detection of prefix examination attack.
 */
typedef struct detection_prefix_examination_struct {
   uint32_t invite; /**< Number of INVITE requests. */
   uint32_t cancel; /**< Number of CANCEL requests. */
   uint32_t ack; /**< Number of ACK requests. */
   uint32_t bye; /**< Number of BYE requests initiated by calling party. */
   uint32_t ok; /**< Number of OK responses. */
   uint32_t successful_call; /**< Number of successful calls to unique telephone numbers. */
   uint32_t trying; /**< Number of TRYING responses. */
   uint32_t ringing; /**< Number of RINGING responses. */
   uint32_t forbidden; /**< Number of FORBIDDEN responses. */
   uint32_t unauthorized; /**< Number of UNAUTHORIZED responses. */
   uint32_t proxy_auth_req; /**< Number of PROXY AUTH REQUEST responses. */
   uint32_t rtcp_data; /**< Indication of RTP data (0=no; 1=yes). */

   time_t time; /**< Save time of start detection process for the IP address. */
   char sip_to[MAX_STRING_PREFIX_TREE_NODE + 1]; /**< One of SIP_TO that was evaluated as prefix examination in the attack. */
   uint32_t sip_user_agent_hash; /**< Hash of User-Agent of INVITE request for SIP_TO from prefix examination in the attack. */
   uint32_t prefix_examination_count; /**< Number of unique SIP_TO that was evaluated as attack. */
   prefix_tree_inner_node_t * report_node; /**< Pointer to one node from attack for reporting. */
   uint16_t report_prefix_length; /**< Prefix length of report_node. */
} detection_prefix_examination_t;

/** \brief Initialize item of hash table defined by input parameter.
 * \param[in] hash_table_item Determine item of hash table to initialization.
 * \return Return 0 if hash_table_item is successfully initialized, -1 if memory error occurs.
 */
int hash_table_item_initialize(ip_item_t * hash_table_item);

/** \brief Free memory of additional items in hash table item.
 * \param[in] hash_table_item Determine item of hash table.
 */
void hash_table_item_free_inner_memory(ip_item_t * hash_table_item);

/** \brief Initialize data of suffix tree node defined by input parameter.
 * \param[in] prefix_tree_node Determine node to initialization its data.
 * \return Return 0 if data are successfully initialized, -1 if memory error occurs.
 */
int node_data_check_initialize(prefix_tree_domain_t * prefix_tree_node);

/** \brief Initialization of all statistics in memory (used once after start module). */
void statistics_initialize();

/** \brief Reset detection statistics used during detection of prefix examination attack. */
void detection_statistics_reset();

#endif	/* VOIP_FRAUD_DETECTION_DATA_STRUCTURE_H */
