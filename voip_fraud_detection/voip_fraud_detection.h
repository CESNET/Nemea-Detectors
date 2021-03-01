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

#ifndef VOIP_FRAUD_DETECTION_H
#define VOIP_FRAUD_DETECTION_H

/** \brief Version of module. */
#define MODULE_VERSION "1.0.1"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <ctype.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <unistd.h>
#include <cuckoo_hash_v2.h>
#include <prefix_tree.h>
#include <super_fast_hash.h>
#include "configuration.h"
#include "data_structure.h"
#include "cache_node_no_attack.h"
#include "output.h"
#include "prefix_examination.h"
#include "country.h"

#define SIP_MSG_TYPE_INVITE      1
#define SIP_MSG_TYPE_STATUS      99
#define SIP_STATUS_OK            200

/** \brief Length of country code (ISO 3166, 2 chars). */
#define LENGTH_COUNTRY_CODE 2


#define EVT_T_VOIP_PREFIX_GUESS            40         //VoIP prefix guessing
#define EVT_T_VOIP_CALL_DIFFERENT_COUNTRY  41         //VoIP call to different country

#define STATS_TIME_INTERVAL 1

extern int stop;
extern void *detection_record;
extern ur_template_t *ur_template_out;

/** \brief Check and free memory, that wasn't used for long time or exceeds limit of items (memory management of module).
 * \param[in] hash_table Pointer to hash table of IP address.
 */
void check_and_free_module_memory(cc_hash_table_v2_t * hash_table);

/** \brief Load Event ID counter from defined file.
 * \param[in] file Definition of file path.
 */
void event_id_load(char * file);

/** \brief Save Event ID counter to defined file.
 * \param[in] file Definition of file path.
 */
void event_id_save(char * file);

/** \brief Find if Call-ID exists in node_data (data of node in suffix tree).
 * \param[in] prefix_tree_node Pointer to node, in which is done searching.
 * \param[in] call_id Call-ID to search in node_data.
 * \param[in] call_id_len Length of call_id string to search.
 * \return Return 1 if Call-ID exists in node_data, 0 otherwise.
 */
int call_id_node_data_exists(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len);

/** \brief Save Call-ID to node_data (data of node in suffix tree).
 * \param[in] prefix_tree_node Pointer to node to save node_data.
 * \param[in] call_id Call-ID to save in node_data.
 * \param[in] call_id_len Length of Call-ID string to save.
 */
void call_id_node_data_save(prefix_tree_domain_t * prefix_tree_node, char * call_id, int call_id_len);

/** \brief Cut SIP identifier from input string.
 * Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' or '?' + string after it.
 * \param[out] output_str Pointer to result string.
 * \param[in] input_str Input string.
 * \param[in,out] str_len Length of input string./Length of output string.
 * \return Return 0 if sip identifier is valid, otherwise -1.
 */
int cut_sip_identifier(char ** output_str, char * input_str, int * str_len);

/** \brief Check if input string is numeric participant.
 * Check if input string is numeric with allowed special char ('+','*','#','-',':') or this text part before '@' + check of minimum numeric length.
 * \param[in] str Input string to test.
 * \param[in] str_len Length of input string to test.
 * \return Return 1 if input string is numeric participant, 0 otherwise.
 */
int is_numeric_participant(char * str, int str_len);

/** \brief Copy char array field from UniRec to defined string_output, update string_len and add terminating '\0' at the end of char array.
 * \param[in] string_output Pointer for saving output char array.
 * \param[in,out] string_len Length of saved char array (without terminating '\0').
 * \param[in] unirec_field_id ID of UniRec field.
 * \param[in] max_length maximum length of string from UniRec field.
 */
void get_string_from_unirec(char * string_output, int * string_len, int unirec_field_id, int max_length);

#endif	/* VOIP_FRAUD_DETECTION_H */
