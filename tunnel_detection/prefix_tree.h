/*!
 * \file prefix_tree.c
 * \brief Prefix tree data structure for saving informaticons about domains.
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
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
#ifndef _PREFIX_TREE_
#define _PREFIX_TREE_



#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "tunnel_detection_dns_structs.h"



int map_chatecter_to_number(char  letter);

prefix_tree_t * prefix_tree_inicialize();

void prefix_tree_destroy_recursive(prefix_tree_inner_node_t *  node);

void prefix_tree_destroy(prefix_tree_t * tree);

void recursive_plus_domain(prefix_tree_domain_t * domain_parent, prefix_tree_t * tree);

prefix_tree_domain_t * new_domain(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, prefix_tree_t * tree);

prefix_tree_inner_node_t * new_node(prefix_tree_inner_node_t * parent, int map_number);

prefix_tree_inner_node_t * add_children_array(prefix_tree_inner_node_t * parent);

prefix_tree_inner_node_t * new_node_parent_is_domain(prefix_tree_domain_t * domain);

int count_to_dot(char * string, int length);

prefix_tree_domain_t * add_new_item(prefix_tree_inner_node_t * node ,prefix_tree_domain_t * domain , char * string, int length, prefix_tree_t * tree);

prefix_tree_inner_node_t * split_node_into_two(prefix_tree_inner_node_t * node, int index);

char * read_doamin(prefix_tree_domain_t * domain, char * string);

prefix_tree_domain_t * prefix_tree_add_domain_recursive(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, char * string, int length, prefix_tree_t * tree);

prefix_tree_domain_t * prefix_tree_add_domain(prefix_tree_t * tree, char * string, int length,  character_statistic_t * char_stat);

prefix_tree_domain_t * prefix_tree_add_domain_exception(prefix_tree_t * tree, char * string, int length);


double most_used_domain_percent_of_subdomains(prefix_tree_t * tree, int depth);






 #endif /* _PREFIX_TREE_ */
