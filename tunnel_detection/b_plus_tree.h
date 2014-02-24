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


#define EXTEND_LEAF 1
#define EXTEND_INNER 0 

#define EQUAL 0
#define LESS 1
#define MORE 2







typedef struct C_node C_node ;
 struct C_node{
    void         * extend;// if is leaf then 1 else 0
    unsigned char  state_extend;
    C_node       * parent;
    void          * key;
    int              count; //pocet potomku, nikoli key  nebo value;
} ;

typedef struct C_inner_node C_inner_node ;
 struct C_inner_node{
    C_node         ** child;// if is leaf then 1 else 0

} ;
typedef struct C_leaf_node C_leaf_node ;
 struct C_leaf_node {
      C_node   *   left;
      C_node   *   right;
      void      ** value; 
      unsigned char  new_key_added; 
} ;

typedef struct C_b_tree_plus C_b_tree_plus;
 struct C_b_tree_plus{
    int m;
    int size_of_value;
    int size_of_key;
    C_node *root;
    int (*compare)(void *, void *);
 };


typedef struct b_plus_tree_item b_plus_tree_item ;
 struct b_plus_tree_item {
    void * value;
    void * key;
    C_node * leaf;
    unsigned int index_of_value;
} ;







inline void copy_key(void * to ,int index_to ,void * from , int index_from, int size_of_key);
// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 
  C_node * c_node_create (int size_of_key, int m);
  void c_node_destroy (C_node * node);
//------------------------------------------------------------------------------------------- 
  unsigned char  c_node_is_key (void * key,C_node * node, C_b_tree_plus * btree);
//------------------------------------------------------------------------------------------- 
  int  c_node_find_index_key     (void * key,C_node * node, C_b_tree_plus * btree);
//------------------------------------------------------------------------------------------- 
  unsigned char c_node_is_leaf(C_node * node);
//------------------------------------------------------------------------------------------- 
  int c_node_get_gamma(C_node * node);
//------------------------------------------------------------------------------------------- 
  C_node* c_node_get_parent(C_node * node); 
//------------------------------------------------------------------------------------------- 
  void * c_node_get_key(C_node * node, int index, int size_of_key);




C_node * c_leaf_node_create(int m, int size_of_value, int size_of_key);



//------------------------------------------------------------------------------------------- 
  void * c_leaf_node_get_value(C_leaf_node * node, int index);
//------------------------------------------------------------------------------------------- 

//------------------------------------------------------------------------------------------- 
  C_node* c_leaf_node_get_next_leaf(C_node * node);//------------------------------------------------------------------------------------------- 
  int c_leaf_node_del_key_on_index(C_node * node, int index, int size_of_key);

 //return value
 int   c_leaf_node_add_key_value ( void *key, C_node* node, C_b_tree_plus *btree, void ** return_value);

// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 

  C_node * c_inner_node_create(int size_of_key, int m);

//------------------------------------------------------------------------------------------- 
  C_node* c_inner_node_get_child(C_node * node ,int index);
//------------------------------------------------------------------------------------------- 
  int c_inner_node_addKey(void * add, C_node * left, C_node * right, C_node *node, C_b_tree_plus * btree );


  C_b_tree_plus * c_b_tree_plus_create(int m, int (*compare)(void *, void *), int size_of_value, int size_of_key);
//------------------------------------------------------------------------------------------- 
  void c_b_tree_plus_destroy(C_b_tree_plus * btree);
//--------------------------------------------------------------------------------------------- 
void c_b_tree_plus_del_all_node (C_node * del);
//------------------------------------------------------------------------------------------- 

    int c_b_tree_plus_b_tree_plus_search(void * key, C_leaf_node** val, C_b_tree_plus * btree);
//------------------------------------------------------------------------------------------- 
//find index of certain child in parent
   int  c_b_tree_plus_find_my_index_in_parent  (C_node * son);
//------------------------------------------------------------------------------------------- 
    void c_b_tree_plus_add_to_node(void *key, C_node *left, C_node *right, C_b_tree_plus * btree);
//------------------------------------------------------------------------------------------- 
    //find leaf where is key, or where to add key
    C_node *  c_b_tree_plus_find_leaf (void *key, C_b_tree_plus * btree);
//------------------------------------------------------------------------------------------- 
    void * c_b_tree_plus_b_tree_plus_insert(void * key, C_b_tree_plus *btree);

 //------------------------------------------------------------------------------------------- 
     C_node * c_b_tree_plus_get_rightest_leaf (C_node * inner);
//------------------------------------------------------------------------------------------- 
    void c_b_tree_plus_check_and_change_key (C_node * leaf_del, C_b_tree_plus * btree );
//------------------------------------------------------------------------------------------- 
    int c_b_tree_plus_b_tree_plus_delete(void * key, C_b_tree_plus * btree);
  int c_b_tree_plus_b_tree_plus_delete_know_leaf(int index, C_node * leaf_del, C_b_tree_plus * btree);

 void c_b_tree_plus_check_inner_node (C_node * check, C_b_tree_plus *btree);

    void c_b_tree_plus_check_repair(C_b_tree_plus *btree);

C_node * c_b_tree_plus_get_most_left_leaf( C_node  *item);

void * inicialize_b_plus_tree(unsigned int size_of_btree_node, int (*comp)(void *, void *), unsigned int size_of_value, unsigned int size_of_key);

void * create_or_find_struct_b_plus_tree(void * btree, void * key);



void  destroy_b_plus_tree(void * tree);

int  delete_item_b_plus_tree(void * btree, b_plus_tree_item * delete_item );



int  get_list(void * t, b_plus_tree_item * item);

b_plus_tree_item * create_list_item (void * btree);

void destroy_list_item(b_plus_tree_item * item);

int get_next_item_from_list(void * t, b_plus_tree_item * item);
 

 #endif /* _B_PLUS_TREE_ */