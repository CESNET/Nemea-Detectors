/**
 * \file prefix_examination.h
 * \brief VoIP fraud detection module - prefix_examination - header file
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

#ifndef VOIP_FRAUD_DETECTION_PREFIX_EXAMINATION_H
#define VOIP_FRAUD_DETECTION_PREFIX_EXAMINATION_H

#include <time.h>
#include <prefix_tree.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "voip_fraud_detection.h"
#include "configuration.h"
#include "data_structure.h"
#include "cache_node_no_attack.h"
#include "output.h"

/** \brief Last used Event ID of attack detection (extern). */
extern uint32_t last_event_id;

/** \brief Detection prefix examination in input suffix tree. If attack is detected delete node and his descendants.
 * \param[in] tree Pointer to suffix tree (data structure named prefix_tree).
 * \param[in] node Pointer to start node of detection.
 * \return ID that indicates results of testing (STATE_NO_ATTACK or STATE_ATTACK_DETECTED).
 */
int prefix_examination_tree_detection(prefix_tree_t * tree, prefix_tree_inner_node_t * node);

/** \brief Function to thorough count of prefix detection minus value and save information about attack to detection_struct.
 * This function is used by prefix_examination_tree_detection().
 * \param[in] tree Pointer to suffix tree (data structure named prefix_tree).
 * \param[in] node Pointer to start node of detection.
 * \param[in] sum_prefix_down Length of actual prefix (used in recursive calling the function).
 * \param[in] first_node Indication of first calling this function (used in recursive calling).
 * \param[in] prefix_statistic Indication of printing prefix statistic.
 * \return Return value for decrementing of basic calculation prefix_sum_count.
 */
unsigned int prefix_examination_minus_detection(prefix_tree_t * tree, prefix_tree_inner_node_t * node, unsigned int sum_prefix_down, char first_node, char prefix_statistic);

/** \brief Detection of prefix examination attack and write/send information about it.
 * \param[in] hash_table_user_agent Pointer to hash table of User-Agent headers.
 * \param[in] hash_table_item Pointer to item of IP address (detection is performed for this IP).
 * \param[in] ip_src Source IP address as ip_addr_t structure.
 * \return ID that indicates results of detection (STATE_NO_ATTACK or STATE_ATTACK_DETECTED).
 */
int prefix_examination_detection(cc_hash_table_v2_t * hash_table_user_agent, ip_item_t * hash_table_item, ip_addr_t * ip_src);

/** \brief Print prefix statistic of node to file.
 * \param[in] tree Pointer to suffix tree (data structure named prefix_tree).
 * \param[in] node Pointer to node.
 * \param[in] prefix_length Length of prefix.
 * \param[in] successful_call Indicates successfull call (1=successfull call).
 */
void print_prefix_statistic(prefix_tree_t * tree, prefix_tree_inner_node_t * node, unsigned int prefix_length, char successful_call);

#endif	/* VOIP_FRAUD_DETECTION_PREFIX_EXAMINATION_H */
