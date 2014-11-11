/**
 * \file cache_node_no_attack.h
 * \brief VoIP fraud detection module - cache_node_no_attack - header file
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
#include "configuration.h"


#ifndef VOIP_FRAUD_DETECTION_CACHE_NODE_NO_ATTACK_H
#define VOIP_FRAUD_DETECTION_CACHE_NODE_NO_ATTACK_H

// testing
extern int test_cache_hit;
extern int test_cache_not_hit;
extern int test_cache_save;
extern int test_cache_delete_successor;

/** \brief Storage of cache_node_no_attack. */
prefix_tree_inner_node_t * cache_node_no_attack_data[MAX_CACHE_NO_ATTACK_SIZE];

/** \brief Size of cache_node_no_attack. */
extern int cache_node_no_attack_size;

/** \brief Find if node is verified for no attack by cache.
 * \param[in] node prefix_tree_inner_node_t* for finding in cache.
 * \return Return 1 if node exists in cache, 0 otherwise.
 */
int cache_node_no_attack_exists(prefix_tree_inner_node_t * node);

/** \brief Save pointer of node into cache.
 * \param[in] node prefix_tree_inner_node_t* to save in cache.
 */
void cache_node_no_attack_save(prefix_tree_inner_node_t * node);

/** \brief Clear cache_node_no_attack. */
void cache_node_no_attack_clear();

#endif	/* VOIP_FRAUD_DETECTION_CACHE_NODE_NO_ATTACK_H */
