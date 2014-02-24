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


#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "tunnel_detection_dns_structs.h"



#define EQUAL 0
#define LESS 1
#define MORE 2

 #ifdef __cplusplus


using namespace std;
 extern "C" {
 #endif

void * inicialize_b_plus_tree(unsigned int size, int (*comp)(void *, void *), int size_of_value, int size_of_key);

void * create_or_find_struct_b_plus_tree(void * tree, void * key, b_plus_tree_item * item);


void  destroy_b_plus_tree(void * tree);

int  delete_item_b_plus_tree(void * tree, b_plus_tree_item * delete_item );

int  get_list(void * t, b_plus_tree_item * item);

int get_next_item_from_list(void * t, b_plus_tree_item * item);


#ifdef __cplusplus
}
#endif

#ifdef __cplusplus


//==================================================================================================
class C_leaf_node;
class C_key {
  void * key;
  void * value;
  int (*compare)(void *, void *);
public:
  C_leaf_node * leaf;
  
  C_key (const C_key & v, int (*comp)(void *, void *), int size_to_value, int size_of_key) ;
  C_key (void * v, int (*comp)(void *, void *)) ;

  ~C_key ();


  void * get_value () const;
  void * get_key () const;
  void set_value (void * v );
  void change_parent(C_leaf_node *parent);

 C_key & operator = (const C_key & i);

  bool operator == (const C_key & i) const;
  bool operator != (const C_key & i) const;
  bool operator <  (const C_key & i) const;
  bool operator >  (const C_key & i) const;
  bool operator >= (const C_key & i) const;
  bool operator <= (const C_key & i) const;


};
//==================================================================================================
/*
class C_value {
  ip_address_t *value;
  public:
    C_value (uint64_t * v);
    C_value (const C_key & i);
    C_value (const C_key & i,  const C_leaf_node * leaf=NULL);
    ~C_value ();

    void change_parent(void *parent);

    ip_address_t * get_value () const;

    void set_value (ip_address_t * v);

    //C_key * create_key();

    C_value & operator = (const C_value & i);



};*/


//==================================================================================================
 static int ids=0;
class C_inner_node;
class C_node {
    public:
      C_node(int m);
      bool is_leaf() const;
      int get_gamma() const;
      C_node* get_parent() const;
      C_key& get_key(int index) const;
      int get_id() const;
      void set_id(int id);

      bool  is_key               (const C_key & iKey)    const;
      int  find_index_key        (const C_key & iKey)    const;
      //int  find_my_index_in_parent  ()                      const;

            bool            leaf;// if is leaf then 1 else 0
            C_inner_node   *  parent;
            C_key        **  key;
            int             count; //pocet potomku, nikoli key  nebo value;
            int             id_a;
            char            m;

  };


//==================================================================================================
  class C_leaf_node : public C_node {
    public:
      C_leaf_node(int m);
      ~C_leaf_node();
      C_leaf_node* get_next_leaf() const;

      C_key * add_key_value ( const C_key & a_key, int (*comp)(void *, void *), int size_of_value, int size_of_key);
      int del_key_on_index(const int &index);
      bool is_new_key_added ( );

      C_leaf_node   *   left;
      C_leaf_node   *   right;
    private:
      bool  new_key_added; 




  };


//==================================================================================================
  class C_inner_node : public C_node {
    public:
      C_inner_node(int m);
      ~C_inner_node();
      C_node* getChild(int index) const;


      int addKey(C_key *add, C_node * left, C_node * right );
      C_node* get_child(int index) const ;

       C_node   **   child;

  };

//==================================================================================================
class C_b_tree_plus {
    private:
        int m;
        int size_of_value;
        int size_of_key;
    public:
        C_node *root;
        int (*comp)(void *, void *);


   // public:
      C_b_tree_plus(int m, int (*comp)(void *, void *), int size_of_value, int size_of_key);
      C_key * b_tree_plus_insert(const C_key& key);
      int b_tree_plus_search(const C_key& key, C_leaf_node** val);
      bool b_tree_plus_delete(const C_key& key);
      bool b_tree_plus_delete_know_leaf(const C_key& key, C_leaf_node * leaf_del);
      C_node *get_root(){return root;};
      ~C_b_tree_plus();


      C_leaf_node * find_leaf (const C_key &f_key) const;  //nalezne list kde bz mela byt vlozena nebo nalezena hodnota
      int searchInLeaf (C_key f_key) const;  //hleda hodnotu v listu, pokud nalezne vraci index, pokud ne, vraci -1;
      void add_to_node (C_key * i_key,C_node * left, C_node *right);
      void read(C_node  *item) const;
      void read2(C_node  *item) const;
      bool check(C_node  *item, C_node *par) const;
      int find_my_index_in_parent(C_node * son) const;
      void check_and_change_key (C_node * leaf_to_del);
      C_leaf_node * get_rightest_leaf     ( C_node * inner);
      void check_inner_node (C_node * check);
      void del_all_node (C_node * del);
      C_leaf_node * get_most_left_leaf( C_node  *item) const;
      int get_dimension_of_tree ()  const;
      void check_repair( );
      int get_m(){return m;}
  };

#endif
//-------------------------------------------------------------------------------------------
 

 #endif /* _B_PLUS_TREE_ */