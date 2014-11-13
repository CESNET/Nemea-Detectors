/**
 * \file cache_node_no_attack.c
 * \brief VoIP fraud detection module - cache_node_no_attack
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

#include "cache_node_no_attack.h"


// testing
int write_cache_limit_info = 0;

// testing
int test_cache_hit = 0;
int test_cache_not_hit = 0;
int test_cache_save = 0;
int test_cache_delete_successor = 0;

// initialize size of cache_node_no_attack
int cache_node_no_attack_size = 0;

// Find if node is verified for no attack by cache
// Return 1 if node exists in cache, 0 otherwise

int cache_node_no_attack_exists(prefix_tree_inner_node_t * node)
{
   if (node != NULL) {
      // try to find node in cache
      int i;
      for (i = 0; i < cache_node_no_attack_size; i++) {
         if (cache_node_no_attack_data[i] == node) return 1;
      }

      // try to find predecessor of node in cache
      return cache_node_no_attack_exists(node->parent);
   }

   // node not found => return 0
   return 0;
}

// Save pointer of node into cache

void cache_node_no_attack_save(prefix_tree_inner_node_t * node)
{
   static int full_index = 0;

   // clear successors of the node in cache
   int i;
   prefix_tree_inner_node_t * predecessor_node;

   for (i = 0; i < cache_node_no_attack_size; i++) {
      predecessor_node = cache_node_no_attack_data[i]->parent;

      while (predecessor_node != NULL) {
         if (predecessor_node == node) {

            // delete cache_no_attack_data[i] from cache
            cache_node_no_attack_size--;
            if (cache_node_no_attack_size > 0) {
               cache_node_no_attack_data[i] = cache_node_no_attack_data[cache_node_no_attack_size];
            }

            test_cache_delete_successor++;
         }
         predecessor_node = predecessor_node->parent;
      }

   }

   // save the node to cache
   if (cache_node_no_attack_size >= MAX_CACHE_NO_ATTACK_SIZE) {
      cache_node_no_attack_data[full_index] = node;
      full_index++;
      if (full_index >= MAX_CACHE_NO_ATTACK_SIZE) full_index = 0;

      // only testing info
      if (write_cache_limit_info == 0) {
         printf("cache limit!!!\n");
         write_cache_limit_info = 1;
      }

   } else {
      cache_node_no_attack_data[cache_node_no_attack_size] = node;
      cache_node_no_attack_size++;
   }

}

// Clear cache

void cache_node_no_attack_clear()
{
   cache_node_no_attack_size = 0;
}
