#ifndef _B_PLUS_TREE_
#define _B_PLUS_TREE_

#include <cstdlib>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <fstream>
#include <cassert>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "tunnel_detection_dns_structs.h"
using namespace std;


void * inicialize_b_plus_tree(unsigned int size);

ip_address_t * create_or_find_struct_b_plus_tree(void * tree, uint32_t ip);

ip_address_t * get_list(void * t);

void  destroy_b_plus_tree(void * tree);

void  delete_item_b_plus_tree(void * tree, ip_address_t * delete_item );




class C_key {
  uint32_t *value;
public:
  C_key (uint32_t v = 0);

  C_key (uint32_t *v);

  ~C_key ();

  uint32_t get_value () const;
  void set_value (int v);

  C_key & operator = (const C_key & i) {
    if (this != &i)
      value = i.value;
    return *this;
  }

  bool operator == (const C_key & i) const { return *value == *i.value; }
  bool operator != (const C_key & i) const { return *value != *i.value; }
  bool operator <  (const C_key & i) const { return *value <  *i.value; }
  bool operator >  (const C_key & i) const { return *value >  *i.value; }
  bool operator >= (const C_key & i) const { return *value >= *i.value; }
  bool operator <= (const C_key & i) const { return *value <= *i.value; }


};
//==================================================================================================
class C_leaf_node;
class C_value {
  ip_address_t *value;
  public:
    C_value (uint32_t v = 0);
    C_value (const C_key & i);
    C_value (const C_key & i,  const C_leaf_node * leaf=NULL);
    ~C_value ();

    void change_parent(void *parent);

    ip_address_t * get_value () const;

    void set_value (ip_address_t * v);

    C_key * create_key();

    C_value & operator = (const C_value & i) {
      if (this != &i)
        value = i.value;
      return *this;
    }

  /*
    bool operator == (const C_value & i) const { return *value == *i.value; }
    bool operator != (const C_value & i) const { return *value != *i.value; }
    bool operator <  (const C_value & i) const { return *value <  *i.value; }
    bool operator >  (const C_value & i) const { return *value >  *i.value; }
    bool operator >= (const C_value & i) const { return *value >= *i.value; }
    bool operator <= (const C_value & i) const { return *value <= *i.value; }
  */

};


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
      C_value & get_value(int index) const;
      C_leaf_node* get_next_leaf() const;

      C_value * add_key_value ( const C_key & a_key);
      int del_key_on_index(const int &index);
      bool is_new_key_added ( );

      C_leaf_node   *   left;
      C_leaf_node   *   right;
      C_value     **   value;
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
    public:
        C_node *root;


   // public:
      C_b_tree_plus(int m);
      C_value * b_tree_plus_insert(const C_key& key);
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

  };
//-------------------------------------------------------------------------------------------
 

 #endif /* _B_PLUS_TREE_ */