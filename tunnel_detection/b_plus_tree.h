/*!
 * \file b_plus_tree.h
 * \brief B+ tree data structure for saving information about Ip adresses
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
#ifndef _B_PLUS_TREE_
#define _B_PLUS_TREE_

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "tunnel_detection_dns_structs.h"

/*!
 * \name Type of node
 *  Used to identify if the node is leaf or inner node.
 * \{ */
#define EXTEND_LEAF 1
#define EXTEND_INNER 0 
 /* /} */

/*!
 * \name Compare values
 *  Used for compare function.
 * \{ */ 
#define EQUAL 0
#define LESS 1
#define MORE 2
 /* /} */

typedef struct c_node c_node;
/*!
 * \brief Structure - B+ tree - node structure
 * Structure used to keep information about node and pointer to inner or leaf node. 
 */
struct c_node{
    void         * extend;  /*< pointer to leaf or inner node */
    unsigned char  state_extend;  /*< state of extended variable. leaf or inner node */
    c_node       * parent;  /*< pointer to parent */
    void          * key;  /*< pointer to key */
    int              count; /*< count of descendants */
};

/*!
 * \brief Structure - B+ tree - inner node structure
 * Structure used to keep information about inner node. 
 */
typedef struct c_inner_node {
    c_node         ** child;  /*< pointer to descendats */

} c_inner_node;


/*!
 * \brief Structure - B+ tree - leaf node structure
 * Structure used to keep information about leaf node. 
 */
typedef struct c_leaf_node{
      c_node   *   left;  /*< linked list, left value */
      c_node   *   right; /*< linked list, right value */
      void      ** value;  /*< array of values */
} c_leaf_node;


/*!
 * \brief Structure - B+ tree - main structure
 * Structure used to keep information about tree. It is main structure of tree.
 */
typedef struct c_b_tree_plus{
    unsigned long int count_of_values;  /*< count of values in tree */
    int m;  /*< count of descendant in node */
    int size_of_value;  /*< size of value */
    int size_of_key;  /*< size of key */
    c_node *root; /*< root node */
    int (*compare)(void *, void *); /*< compare function for key */
 }c_b_tree_plus;

/*!
 * \brief Structure - B+ tree - list item structure
 * Structure used to create list of items.
 */
typedef struct b_plus_tree_item{
    void * value; /*< pointer to value */
    void * key; /*< pointer to key */
    c_node * leaf;  /*< pointer to leaf where is item */
    unsigned int index_of_value;  /*< index of value in leaf */
} b_plus_tree_item;

/*!
 * \brief Copy key 
 * Function which copy key from certain poineter to another.
 * \param[in] to poineter to destination.
 * \param[in] index_to position in array of destination.
 * \param[in] from poineter of source.
 * \param[in] index_from position in array of source.
 * \param[in] size_of_key size of key to copy.
 */
 void copy_key(void * to ,int index_to ,void * from , int index_from, int size_of_key);

/*!
 * \brief Creates c_node structure 
 * Function which allocs memory for c_node structure.
 * \param[in] size_of_key size of key to allocate memory.
 * \param[in] m count of keys to allocate.
 * \return pointer to created stucture
 */  
  c_node * c_node_create (int size_of_key, int m);

/*!
 * \brief Destroy c_node structure 
 * \param[in] node pointer to node
 */  
void c_node_destroy (c_node * node);

/*!
 * \brief is key in node
 * \param[in] key 
 * \param[in] node
 * \param[in] btree pointer to b tree
 * \return 1 ON SUCCESS, OTHERWISE 0
 */  
unsigned char  c_node_is_key (void * key,c_node * node, c_b_tree_plus * btree);

/*!
 * \brief Find index in node
 * \param[in] key 
 * \param[in] node
 * \param[in] btree pointer to b tree
 * \return index or -1 if key is not in node
 */  
int  c_node_find_index_key     (void * key,c_node * node, c_b_tree_plus * btree);

/*!
 * \brief If node if leaf
 * \param[in] node
 * \return 1 ON SUCCESS, OTHERWISE 0
 */  
unsigned char c_node_is_leaf(c_node * node);

/*!
 * \brief Get parent of node
 * \param[in] node
 * \return parent of node or NULL if does not have
 */  
c_node* c_node_get_parent(c_node * node); 

/*!
 * \brief Return key from item
 * \param[in] node
 * \param[in] index index in leaf
 * \param[in] size_of_key size of key in B
 * \return poiter to key
 */  
void * c_node_get_key(c_node * node, int index, int size_of_key);



/*!
 * \brief Creates c_leaf_node structure 
 * Function which allocs memory for c_leaf_node which extends c_node structure.
 * \param[in] m count of keys and values to allocate.
 * \param[in] size_of_value size of value to allocate memory.
 * \param[in] size_of_key size of key to allocate memory.
 * \return pointer to created c_node stucture
 */  
c_node * c_leaf_node_create(int m, int size_of_value, int size_of_key);



/*!
 * \brief Return value from item
 * \param[in] node
 * \param[in] index index in leaf
 * \return poiter to key
 */  
void * c_leaf_node_get_value(c_leaf_node * node, int index);

/*!
 * \brief Next leaf
 * \param[in] node leaf
 * \return poiter to next leaf or NULL if not exists
 */  
c_node* c_leaf_node_get_next_leaf(c_node * node);


/*!
 * \brief Delete item from node on specific index
 * \param[in] node leaf
 * \param[in] index item to delete
 * \param[in] size_of_key size of key in B
 * \return count of items in leaf
 */ 
int c_leaf_node_del_key_on_index(c_node * node, int index, int size_of_key);

/*!
 * \brief Add key and value to the leaf.
 * \param[in] key key
 * \param[in] node leaf
 * \param[in] btree pointer to tree
 * \param[in] pointer to memory of item
 * \return index in leaf
 */ 
int   c_leaf_node_add_key_value ( void *key, c_node* node, c_b_tree_plus *btree, void ** return_value);

/*!
 * \brief Creates c_inner_node structure 
 * Function which allocs memory for c_inner_node which extends c_node structure.
 * \param[in] size_of_key size of key to allocate memory.
 * \param[in] m count of keys and values to allocate.
 * \return pointer to created c_node stucture
 */ 
c_node * c_inner_node_create(int size_of_key, int m);

/*!
 * \brief Get child on index
 * \param[in] node 
 * \param[in] index index of child
 * \return pointer to child
 */ 
c_node* c_inner_node_get_child(c_node * node ,int index);

/*!
 * \brief Add key to inner node
 * \param[in] add key to add 
 * \param[in] left left brother
 * \param[in] right right brother 
 * \param[in] node node to insert key  
 * \param[in] btree pointer to tree
 * \return count of descendants
 */ 
int c_inner_node_addKey(void * add, c_node * left, c_node * right, c_node *node, c_b_tree_plus * btree );

/*!
 * \brief Creates b plus tree 
 * Function which creates structure for b plus tree
 * \param[in] m m-arry tree.
 * \param[in] size_of_value size of value to allocate memory.
 * \param[in] size_of_key size of key to allocate memory.
 * \return pointer to created c_node stucture
 */ 
  c_b_tree_plus * c_b_tree_plus_create(int m, int (*compare)(void *, void *), int size_of_value, int size_of_key);

/*!
 * \brief Destroy b plus tree structure 
 * \param[in] btree pointer to tree
 */ 
void c_b_tree_plus_destroy(c_b_tree_plus * btree);

/*!
 * \brief Recursive function to delete all nodes
 * \param[in] del node to delete
 */ 
void c_b_tree_plus_del_all_node (c_node * del);

/*!
 * \brief Search item in tree
 * \param[in] key to search
 * \param[in] val pointer to leaf where will be the key
 * \param[in] btree pointer to tree 
 * \return index of item in leaf
 */ 
int c_b_tree_plus_search(void * key, c_leaf_node** val, c_b_tree_plus * btree);

/*!
 * \brief Find index of child in parent
 * \param[in] son node to find index of
 * \return index of nide in parent
 */ 
int  c_b_tree_plus_find_my_index_in_parent  (c_node * son);


/*!
 * \brief Add key to inner node. For spliting node
 * \param[in] add key to add 
 * \param[in] left left brother
 * \param[in] right right brother 
 * \param[in] btree pointer to tree
 */ 
void c_b_tree_plus_add_to_node(void *key, c_node *left, c_node *right, c_b_tree_plus * btree);

/*!
 * \brief Search leaf where shuld be item.
 * \param[in] key to search
 * \param[in] btree pointer to tree
 * \return leaf where should be item
 */ 
c_node *  c_b_tree_plus_find_leaf(void *key, c_b_tree_plus * btree);


/*!
 * \brief Find or Insert key, return pointer to item
 * \param[in] key to insert
 * \param[in] btree pointer to tree
 * \param[in] search 1 - return fouded or inserted value, 0 - return value just when the key was inserted, otherwise NULL
 * \return pointer to value
 */ 
void * c_b_tree_plus_b_tree_plus_insert(void * key, c_b_tree_plus *btree, int search);

/*!
 * \brief Found the most right leaf and return it
 * \param[in] inner node where to seach
 * \return pointer to leaf
 */ 
c_node * c_b_tree_plus_get_most_right_leaf (c_node * inner);

/*!
 * \brief check key and key in parent, it there is problem, repair it
 * \param[in] node to check
 * \param[in] btree pointer to tree
 */ 
void c_b_tree_plus_check_and_change_key (c_node * node, c_b_tree_plus * btree );

/*!
 * \brief Delete item from tree, know leaf
 * \param[in] btree pointer to tree
 * \param[in] index item to delete
 * \param[in] leaf_del leaf where is item
 * \return 1 ON SUCCESS, OTHERWISE 0
 */ 
int c_b_tree_plus_b_tree_plus_delete_know_leaf(int index, c_node * leaf_del, c_b_tree_plus * btree);

/*!
 * \brief check node if has the rigth value, not small and not big
 * \param[in] check node to check
 * \param[in] btree pointer to tree 
 */ 
void c_b_tree_plus_check_inner_node (c_node * check, c_b_tree_plus *btree);

/*!
 * \brief Found the rightest leaf and return it
 * \param[in] inner node where to seach
 * \return pointer to leaf
 */ 
c_node * c_b_tree_plus_get_most_left_leaf( c_node  *item);

/*!
 * \brief Init function of tree
 * \param[in] size_of_btree_node count of descendants in node
 * \param[in] comp compare function for key 
 * \param[in] size_of_value size of value
 * \param[in] size_of_key size of key
 * \return poiter to structure with tree
 */ 
void * b_plus_tree_initialize(unsigned int size_of_btree_node, int (*comp)(void *, void *), unsigned int size_of_value, unsigned int size_of_key);

/*!
 * \brief Insert or find item in tree
 * \param[in] btree pointer to tree 
 * \param[in] key key to insert
 * \return poiter to inserted or founded item
 */ 
void * b_plus_tree_insert_or_find_item(void * btree, void * key);

/*!
 * \brief Insert item in tree
 * \param[in] btree pointer to tree
 * \param[in] key key to insert
 * \return poiter to inserted item
 */ 
void * b_plus_tree_insert_item(void * btree, void * key);

/*!
 * \brief Search item in tree
 * \param[in] btree pointer to tree 
 * \param[in] key key to insert
 * \return poiter to searched item
 */ 
void * b_plus_tree_search(void * btree, void * key);

/*!
 * \brief Get count of all items in tree
 * \param[in] btree pointer to tree
 * \return count of items
 */ 
unsigned long int b_plus_tree_get_count_of_values(void * btree);


/*!
 * \brief Destroy b_plus tree,
 * \param[in] tree pointer to tree
 */ 
void  b_plus_tree_destroy(void * tree);

/*!
 * \brief Delete item from tree
 * \param[in] btree pointer to tree
 * \param[in] key key to delete
 * \return 1 ON SUCCESS, OTHERWISE 0
 */ 
int  b_plus_tree_delete_item(void * btree, void * key );

/*!
 * \brief Delete item from list
 * \param[in] btree pointer to tree
 * \param[in] delete_item structure to list item
 * \return 1 ON SUCCESS,  0 END OF LIST
 */ 
int  b_plus_tree_delete_item_from_list(void * btree, b_plus_tree_item * delete_item );
 
/*!
 * \brief Get list of items in tree
 * \param[in] t pointer to tree 
 * \param[in] item pointer to item list structure
 * \return 1 ON SUCCESS,  0 tree is empty
 */ 
int  b_plus_tree_get_list(void * t, b_plus_tree_item * item);

/*!
 * \brief Create structure of inte list structure
 * \param[in] btree pointer to tree 
 * \return pointer to structure
 */ 
b_plus_tree_item * b_plus_tree_create_list_item (void * btree);

/*!
 * \brief Destroy b_plus item structure
 * \param[in] item pointer to item
 */ 
void b_plus_tree_destroy_list_item(b_plus_tree_item * item);

/*!
 * \brief Get next intem from list
 * \param[in] t pointer to tree
 * \param[in] item pointer to item 
 * \return 1 ON SUCCESS,  0 END OF LIST
 */ 
int b_plus_tree_get_next_item_from_list(void * t, b_plus_tree_item * item);
 

 #endif /* _B_PLUS_TREE_ */