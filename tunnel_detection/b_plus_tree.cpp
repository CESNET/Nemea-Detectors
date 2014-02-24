/*!
 * \file b_plus_tree.cpp
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

#include <cstdlib> 
#include <cstdio> 
#include <ctime> 
#include <iostream> 
#include <fstream> 
#include <cassert> 
#include "b_plus_tree.h"
using namespace std;






  C_key::C_key (const C_key & v, int (*comp)(void *, void *), int size_to_value, int size_of_key) : value ((void *) calloc(size_to_value,1)) 
  {
    compare = comp;
    key = ((void *) calloc(size_of_key,1));
    memcpy(key,v.get_key(), size_of_key);
  }

  C_key::C_key (void * v, int (*comp)(void *, void *)) 
  {
    key = v;
    compare = comp;
  }

  C_key::~C_key () {
    //free(value);
    //free(key);
  }

  void * C_key::get_value () const { return this->value; }
  void * C_key::get_key () const { return this->key; } 
  void C_key::set_value (void * v) { 
    value = v;
  }


  void C_key::change_parent(C_leaf_node *parent){
    leaf = parent;
  }

 C_key & C_key::operator = (const C_key & i) {
    if (this != &i){
      value = i.value;
    }
    return *this;
  }


  bool C_key::operator == (const C_key & i) const { 
    return compare (this->key, i.get_key()) == EQUAL; 
    //return (value[0] == i.value[0] &&  value[1] == i.value[1]); 
  }

  bool C_key::operator != (const C_key & i) const { 
    return compare (this->key, i.get_key()) != EQUAL; 
    //return (value[0] != i.value[0] ||  value[1] != i.value[1]);
  }

  bool C_key::operator <  (const C_key & i) const { 
    return compare (this->key, i.get_key()) == LESS;
    //return ((value[0] < i.value[0]) || ((value[0] == i.value[0]) && (value[1] < i.value[1]))); 
  }

  bool C_key::operator >  (const C_key & i) const {
    return compare (this->key, i.get_key()) == MORE;
    //return ((value[0] > i.value[0]) || ((value[0] == i.value[0]) && (value[1] > i.value[1]))); 
  }

  bool C_key::operator >= (const C_key & i) const { 
    int a = compare (this->key, i.get_key());
    return (a == EQUAL || a == MORE); 
  }
  bool C_key::operator <= (const C_key & i) const { 
    int a = compare (this->key, i.get_key());
    return (a == EQUAL || a == LESS); 
  }


// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 
 /* C_value::C_value (uint64_t * v)    : value ((ip_address_t *) calloc(sizeof(ip_address_t),1)) 
  {
    value->state_request = STATE_NEW;
    value->state_response = STATE_NEW;
    //value->ip[1] = v[1];
    //value->ip[0] = v[0];
    value->paret_in_b_plus_tree = this;
  }
  C_value::C_value (const C_key & i) : value ((ip_address_t *) calloc(sizeof(ip_address_t),1)) 
  {
    //value->ip[0] =  (i.get_value()[0]);
    //value->ip[1] =  (i.get_value()[1]);
    value->state_request = STATE_NEW;
    value->state_response = STATE_NEW;
  }
  C_value::C_value (const C_key & i,  const C_leaf_node * leaf)    : value ((ip_address_t *) calloc(sizeof(ip_address_t),1)) 
  {
    value->state_request = STATE_NEW;
    value->state_response = STATE_NEW;
    //value->ip[0] =  (i.get_value()[0]);
    //value->ip[1] =  (i.get_value()[1]);
    value->paret_in_b_plus_tree = (void*)leaf;
  }  
  C_value::~C_value () {     
    free(value); 
  }

  void C_value::change_parent(void *parent){
    value->paret_in_b_plus_tree = parent;
  }


  ip_address_t * C_value::get_value () const { return this->value; }
  void C_value::set_value (ip_address_t * v) { value = v; }

  


    C_value & C_value::operator = (const C_value & i) {
      if (this != &i)
        value = i.value;
      return *this;
    }

*/

// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 
  C_node::C_node ( int m)
  {
      parent = 0;
      key = new  C_key* [m]; //m - ty key se vyuzije pouze na testovani zda je jiz prilis uzlu, prvne se hodnota vlozi, ale nasledne se stejne splitne
      count = 1;
      this->m = m;
      id_a = ids++;
  }
//------------------------------------------------------------------------------------------- 
  bool  C_node::is_key               (const C_key & i_key)    const
  {
      if (find_index_key(i_key) != - 1) return true;
      return false;
  }
//------------------------------------------------------------------------------------------- 
  int  C_node::find_index_key     (const C_key & i_key)    const
  {
      for (int i = 0; i < count - 1; i++ )
        if (*key[i] == i_key)
           return i;
    return - 1;

  }
//------------------------------------------------------------------------------------------- 
  bool C_node::is_leaf() const 
  {
    return leaf;
  }
//------------------------------------------------------------------------------------------- 
  int C_node::get_gamma() const
  {
    return count - 1;
  }
//------------------------------------------------------------------------------------------- 
  C_node* C_node::get_parent() const 
  { 
    return ((C_node*)parent);
  }
//------------------------------------------------------------------------------------------- 
  C_key& C_node::get_key(int index) const{
    return *key[index - 1];
  }
//------------------------------------------------------------------------------------------- 
  int C_node::get_id() const
  {
    return id_a;
  }
//------------------------------------------------------------------------------------------- 
  void C_node::set_id(int id)
  {
    id_a = id;
  }



// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 



  C_leaf_node::C_leaf_node(int m):C_node(m)
  {
      left = 0;
      right = 0;
      leaf = 1;

  }
//------------------------------------------------------------------------------------------- 
  C_leaf_node::~C_leaf_node()
  {

      for (int i = 0; i < count - 1;i++ )
      {
        free(key[i]->get_value());
        free(key[i]->get_key());
        delete key[i];
      }
      delete [] key;

  }
//------------------------------------------------------------------------------------------- 

//------------------------------------------------------------------------------------------- 
  C_leaf_node* C_leaf_node::get_next_leaf() const {
    return right;
  }  
//------------------------------------------------------------------------------------------- 

  int C_leaf_node::del_key_on_index(const int &index)
  {
      free(key[index]->get_value());
      free(key[index]->get_key());
      delete key[index];

      for (int i = index; i < count - 2; i++ )
      {
          key[i] = key[i + 1];
      }
      count-- ;
      return count - 1;

  }

//------------------------------------------------------------------------------------------- 
  C_key * C_leaf_node::add_key_value ( const C_key & a_key, int (*comp)(void *, void *), int size_of_value, int size_of_key)
  {
      int i;
      i = find_index_key(a_key);

      if (i != - 1) //klic se jiz v listu nachazi
      {
          new_key_added = false;
          return key[i];
      }
        //nalezne kam vlozit klic a hodnotu a vlozime
      i = count - 2; //index posledniho prvku

      while (i >= 0 && *key[i] > a_key)
      {
         key[i + 1] = key[i];
         i-- ;


      }
      key[i + 1] = new C_key(a_key, comp, size_of_value, size_of_key) ;//value[i + 1]->create_key();
      key[i + 1]->leaf = this; 
      new_key_added = true;
      count++;

      return key[i + 1];
  }
//------------------------------------------------------------------------------------------- 
  bool C_leaf_node::is_new_key_added ( )
  {
      return new_key_added;
  }

// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 


  C_inner_node::C_inner_node(int m):C_node(m)
  {
      child = new C_node * [m + 1];
      leaf = 0;

  }
//------------------------------------------------------------------------------------------- 
  C_inner_node::~C_inner_node()
  {
      delete [] child;
      delete [] key;
  }

//------------------------------------------------------------------------------------------- 
  C_node* C_inner_node::get_child(int index) const 
  {
    return child[index - 1];
  }
//------------------------------------------------------------------------------------------- 
  int C_inner_node::addKey(C_key *add, C_node * left, C_node * right )
  {

      if (is_key(*add)) return ( - 1);
      int i = count - 2;
      while ( i >= 0 && *key[i] > *add)
      {
         key[i + 1] = key[i];
         child[i + 2] = child[i + 1];
         i-- ;

      }
      key[i + 1] = add;
      child[i + 2] = right;
      child[i + 1] = left;
      count++;
      return count;
  }
// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 

  C_b_tree_plus::C_b_tree_plus(int m, int (*comp)(void *, void *), int size_of_value, int size_of_key):m(m)
  {
      root = new C_leaf_node(m);
      this->comp= comp;
      this->size_of_value = size_of_value;
      this->size_of_key = size_of_key;
  }
//------------------------------------------------------------------------------------------- 
  C_b_tree_plus::~C_b_tree_plus()
  {
    del_all_node(root);

    //delete root;
  }
//--------------------------------------------------------------------------------------------- 
void C_b_tree_plus::del_all_node (C_node * del)
{
    if (del->leaf)
    {
        delete  static_cast < C_leaf_node* > (del);
        return;
    }
    else
    {
     for (int i = 0; i < del->count;i++ )
            del_all_node(static_cast < C_inner_node* > (del)->child[i]);

     delete  static_cast < C_inner_node* > (del);

    }

}
//------------------------------------------------------------------------------------------- 

    int C_b_tree_plus::b_tree_plus_search(const C_key& key, C_leaf_node** val)
    {
        C_leaf_node * findL = find_leaf (key);
        int result = findL->find_index_key(key);
        if (result == - 1)
            {
                *val = 0;
                return ( - 1);
            }
        *val = findL;
        return result + 1;

    }
//------------------------------------------------------------------------------------------- 

   int  C_b_tree_plus::find_my_index_in_parent  (C_node * son)                      const
   {
       if ( ! (son->parent)) return ( - 1);

       for (int i = 0; i < son->parent->count; i++ )
       {
           if (son->parent->child[i] == son)
           return i;
       }
       return ( - 2);
   }
//------------------------------------------------------------------------------------------- 
    void C_b_tree_plus::add_to_node(C_key * i_key, C_node * left, C_node *right)
    {
        C_inner_node *par = dynamic_cast < C_inner_node* > (left->parent);
        //1. rodic neexistuje - vytvorim, vlozim, prepisu root, koncim
        if (par == 0)
        {
            par = new C_inner_node(m);
            par->addKey(i_key,left,right);
            left->parent = par;
            right->parent = par;
            root = par;
            return;
        }
        //2. rodic existuje
        par->addKey(i_key, left, right);



        for (int i = 0; i < par->count; i++ )
        {
            check_and_change_key(get_rightest_leaf(par->child[i]));
        }
/*
for(int i = 0; i < par->count - 1;i++ )
cout << " " << par->key[i]->get_value() << " ";
cout << endl;
*/
        //velikost je v norme, muzu skoncit
        if (par->count <= m)
        {

            return;
        }
        //velikost neni v norme, muzu splitnout node na dva a rekurentne pokracovat
        else
        {
            C_inner_node *right_par = new C_inner_node(m);
            //left->parent = right_par;
            //right->parent = right_par;
            int cut = (par->count - 1) / 2;
            int insert = 0;
            int i;
            for (i = cut + 1; i < par->count - 1; i++ )
            {
                right_par->key[insert] = par->key[i];
                right_par->child[insert++ ] = par->child[i];
            }
            right_par->child[insert++ ] = par->child[i]; //posledni decko
            right_par->count = insert;
            par->count = cut + 1;
            right_par->parent = par->parent;
            for (int i = 0; i < right_par->count; i++ )
                right_par->child[i]->parent = right_par;

            add_to_node(par->key[cut], par,right_par);


        }
    }
//------------------------------------------------------------------------------------------- 
    C_leaf_node *  C_b_tree_plus::find_leaf        (const C_key &f_key) const
    {
        C_node *pos = root;
        bool goRight = 0;
        while ( ! pos->leaf)
        {
            C_inner_node *pos2 = static_cast < C_inner_node* > (pos);
            goRight = 0;
            for (int i = 0; i < pos2->count - 1; i++ )
            {
                if (f_key < *pos2->key[i])
                {
                    pos = pos2->child[i];
                    goRight = 1;
                    break;
                }
                else if(f_key == *pos2->key[i])
                {
                  return pos2->key[i]->leaf;
                }
            }
            if ( ! goRight)
                pos = pos2->child[pos->count - 1];
        }
        if (pos->leaf)
            return (static_cast < C_leaf_node* > (pos));
        return 0;
    }
//------------------------------------------------------------------------------------------- 
    C_key * C_b_tree_plus::b_tree_plus_insert(const C_key& key)
    {
        C_leaf_node * leaf_to_insert;
        int size;
        C_key * added_or_found_value;
        leaf_to_insert = find_leaf(key);
        added_or_found_value = leaf_to_insert->add_key_value(key, comp, size_of_value, size_of_key);
        size = leaf_to_insert->count;
        if (leaf_to_insert->is_new_key_added() == false) //pouze se prepsala hodnota
        {
            return added_or_found_value;
        }


        //byla vlozena nova hodnota, musime prekontrolovat velikost listu
        if (size <= m)
        {
            check_and_change_key(leaf_to_insert);
            //check_repair( );
        return added_or_found_value;
        }
        //vlozil se novy prvek a velikost je OK, muzeme skoncit

        // reseni poruseni velikosti
        size-- ; //pravy pocet hodnot nikoliv pouze hodnota m;
        int splitVal = size / 2;
        C_leaf_node *r_leaf = new C_leaf_node(m);
        int insert = 0;
        for (int i = splitVal; i < size; i++ )
        {
            leaf_to_insert->key[i]->change_parent(r_leaf);
            r_leaf->key[insert++] = leaf_to_insert->key[i];
            

        }
        r_leaf->count = insert + 1;
        leaf_to_insert->count = splitVal + 1;
        r_leaf->parent = leaf_to_insert->parent;
        r_leaf->right = leaf_to_insert->right;
        r_leaf->left = leaf_to_insert;
        leaf_to_insert->right = r_leaf;

    //cout << endl << "add to root " << leaf_to_insert->key[leaf_to_insert->count - 2]->get_value() << endl;
        add_to_node(leaf_to_insert->key[leaf_to_insert->count - 2], leaf_to_insert, r_leaf);
        //check_repair( );
        check_and_change_key(leaf_to_insert);
        check_and_change_key(r_leaf);

        return added_or_found_value;
    }

 //------------------------------------------------------------------------------------------- 
     C_leaf_node * C_b_tree_plus::get_rightest_leaf (C_node * inner)
     {
         if (inner->leaf) return (static_cast < C_leaf_node* > (inner));
         return get_rightest_leaf((static_cast < C_inner_node* > (inner))->child[inner->count - 1]);
     }
//------------------------------------------------------------------------------------------- 

    void C_b_tree_plus::check_and_change_key (C_node * leaf_del)
    {
            int parent_index = find_my_index_in_parent(leaf_del);
             if (parent_index < 0)
            {
                return;
            }
            else if (parent_index <= leaf_del->parent->count - 2)
            {
                leaf_del->parent->key[parent_index] = leaf_del->key[leaf_del->count - 2];
            }
            else if (parent_index == leaf_del->parent->count - 1)
            {
                //zmenime pouze hodnotu v neprimem rodici
                C_node *par = leaf_del;

                while (parent_index == par->parent->count - 1)
                {
                    par = par->parent;
                    parent_index = find_my_index_in_parent(par);
                    //cout << "parent index je " << parent_index << endl;
                    if (parent_index < 0)
                        {return;}
                }
                par->parent->key[parent_index] = leaf_del->key[leaf_del->count - 2];
                //cout << "nasel jsem index " << parent_index << endl;
                return;


            }
    }
//------------------------------------------------------------------------------------------- 
    bool C_b_tree_plus::b_tree_plus_delete(const C_key& key)
    {
        
        C_leaf_node * leaf_del = find_leaf( key);
        return b_tree_plus_delete_know_leaf(key, leaf_del);
    }
//------------------------------------------------------------------------------------------- 
    bool C_b_tree_plus::b_tree_plus_delete_know_leaf(const C_key& key, C_leaf_node * leaf_del){
        int index, parent_index,  size;
        index = leaf_del->find_index_key(key);
        //hodnota nenalezena
        if (index == ( - 1)) {
          return false;
        }
        parent_index = find_my_index_in_parent(leaf_del);
        size = leaf_del->del_key_on_index(index);
        if (size >= ((m - 1) / 2) || root->leaf)
        {
            //pocet je dostacujici, pouze zkontrolujeme rodice;
            check_and_change_key(leaf_del);
            return true;
        }
        else
        {
            C_leaf_node *brother;
            //pocet je mmoc maly, musime resit
            if ( parent_index > 0 && (leaf_del->parent->child[parent_index - 1]->count - 1) > (m - 1) / 2)
            {
                //rotace z leveho bratra
                brother = static_cast < C_leaf_node* > (leaf_del->parent->child[parent_index - 1]);
                for (int i = leaf_del->count - 2; i >= 0; i-- )
                {
                    leaf_del->key[i + 1] = leaf_del->key[i];
                }
                leaf_del->count++;
                leaf_del->key[0] = brother->key[brother->count - 2];
                leaf_del->key[0]->change_parent(leaf_del);
                brother->count-- ;
                check_and_change_key(brother);
                if(index == leaf_del->count-2)
                    check_and_change_key(leaf_del);

            }
            else if ( parent_index < leaf_del->parent->count - 1 && ((leaf_del->parent->child[parent_index + 1]->count) - 1) > (m - 1) / 2)
            {

                //rotace z praveho bratra
                brother = static_cast < C_leaf_node* > (leaf_del->parent->child[parent_index + 1]);

                leaf_del->count++;
                leaf_del->key[leaf_del->count - 2] = brother->key[0];
                leaf_del->key[leaf_del->count - 2]->change_parent(leaf_del);
                brother->count-- ;
                for (int i = 0; i < brother->count - 1;i++ )
                {
                    brother->key[i] = brother->key[i + 1];
                }
                check_and_change_key(leaf_del);
            }
            else if ( parent_index > 0 )
            {
                //slouceni s levym bratrem
                brother = static_cast < C_leaf_node* > (leaf_del->parent->child[parent_index - 1]);
                for (int i = 0; i < leaf_del->count - 1;i++ )
                {
                    brother->key[(++ brother->count) - 2] = leaf_del->key[i];
                    brother->key[brother->count - 2]->change_parent(brother);
                }
                brother->right = leaf_del->right;
                if (leaf_del->right)
                     leaf_del->right->left = brother;
                for (int i = parent_index; i < leaf_del->parent->count - 2; i++ )
                {
                    leaf_del->parent->key[i] = leaf_del->parent->key[i + 1];
                }
                for (int i = parent_index; i < leaf_del->parent->count - 1; i++ )
                {
                    leaf_del->parent->child[i] = leaf_del->parent->child[i + 1];
                }
                leaf_del->parent->count-- ;
                check_and_change_key(brother);
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                check_inner_node(brother->parent);
                leaf_del->count = 0;
                delete leaf_del;


            }
            else if (parent_index < leaf_del->parent->count - 1)
            {
                //slouceni s pravym bratrem
                brother = static_cast < C_leaf_node* > (leaf_del->parent->child[parent_index + 1]);
                for (int i = 0; i < brother->count - 1;i++ )
                {
                    leaf_del->key[(++ leaf_del->count) - 2] = brother->key[i];
                    leaf_del->key[leaf_del->count - 2]->change_parent(leaf_del);
                }
                leaf_del->right = brother->right;
                if (brother->right)
                     brother->right->left = leaf_del;
                for (int i = parent_index + 1; i < leaf_del->parent->count - 2; i++ )
                {
                    leaf_del->parent->key[i] = leaf_del->parent->key[i + 1];
                }
                for (int i = parent_index + 1; i < leaf_del->parent->count - 1; i++ )
                {
                    leaf_del->parent->child[i] = leaf_del->parent->child[i + 1];
                }
                leaf_del->parent->count-- ;
                check_and_change_key(leaf_del);
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                check_inner_node(leaf_del->parent);
                brother->count = 0;
                delete brother;
            }
        }
        //check_repair( );
        return true;



    }
//------------------------------------------------------------------------------------------- 
    void C_b_tree_plus::check_inner_node (C_node * check)
    {
        if (check->count - 1 >= ((m - 1) / 2))
        {
            //pocet je dostacujici, koncime;
            return ;
        }
        if (check == root)
        {
            if (check->count <= 1)
            {
                root = (static_cast < C_inner_node* > (root))->child[0];
                root->parent = 0;
                check->count = 0;
                if (check->leaf)
                    delete static_cast < C_leaf_node* > (check);
                else
                    delete static_cast < C_inner_node* > (check);
            }
                return;
        }
        int parent_index = find_my_index_in_parent(check);
        C_inner_node *brother;
        C_inner_node *check2 = static_cast < C_inner_node* > (check);
        if ( parent_index > 0 && (check2->parent->child[parent_index - 1]->count - 1) > (m - 1) / 2)
            {

                //rotace z leveho bratra
                brother = static_cast < C_inner_node* > (check2->parent->child[parent_index - 1]);
                for (int i = check2->count - 1; i >= 0; i-- )
                {
                    check2->child[i + 1] = check2->child[i];
                }
                for (int i = check2->count - 2; i >= 0; i-- )
                {
                    check2->key[i + 1] = check2->key[i];
                }
                check2->count++;
                check2->key[0] = brother->key[brother->count - 2];
                check2->child[0] = brother->child[brother->count - 1];
   /*zmena*/    check2->child[0]->parent = check2;
                brother->count-- ;
                check_and_change_key(get_rightest_leaf(brother));
                check_and_change_key(get_rightest_leaf(check2->child[0]));



            }
            else if ( parent_index < check2->parent->count - 1 && (check2->parent->child[parent_index + 1]->count - 1) > (m - 1) / 2)
            {
                //rotace z praveho bratra
                brother = static_cast < C_inner_node* > (check2->parent->child[parent_index + 1]);

                check2->count++;
                check2->key[check2->count - 2] = brother->key[0];
                check2->child[check2->count - 1] = brother->child[0];
   /*zmena*/    check2->child[check2->count - 1]->parent = check2;
                brother->count-- ;
                for (int i = 0; i < brother->count - 1;i++ )
                {
                    brother->key[i] = brother->key[i + 1];
                }
                for (int i = 0; i < brother->count;i++ )
                {
                    brother->child[i] = brother->child[i + 1];
                }

                check_and_change_key(get_rightest_leaf(check2->child[check2->count - 2]));
                check_and_change_key(get_rightest_leaf(check2));
            }
            else if ( parent_index > 0 )
            {
                //slouceni s levym bratrem
                brother = static_cast < C_inner_node* > (check2->parent->child[parent_index - 1]);
                int previous = brother->count - 1;
                for (int i = 0; i < check2->count;i++ )
                {
                    brother->child[(++ brother->count) - 1] = check2->child[i];
                    check2->child[i]->parent = brother;
                    //++ brother->count;
                    //cout << "jedu tu jednou" << brother->count << endl;
                }

                for (int i = parent_index; i < check2->parent->count - 2; i++ )
                {
                    check2->parent->key[i] = check2->parent->key[i + 1];
                }
                for (int i = parent_index; i < check2->parent->count - 1; i++ )
                {
                    check2->parent->child[i] = check2->parent->child[i + 1];
                }
                check2->parent->count-- ;
                for (int i = previous ; i < brother->count;i++ )
                    check_and_change_key(get_rightest_leaf(brother->child[i]));
                check2->count = 0;
                delete check2;
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                check_inner_node(brother->parent);
                return;

            }
            else if (parent_index < check2->parent->count - 1)
            {
                //slouceni s pravym bratrem
                brother = static_cast < C_inner_node* > (check2->parent->child[parent_index + 1]);
                int previous = check2->count - 1;
                for (int i = 0; i < brother->count;i++ )
                {
                    check2->child[(++ check2->count) - 1] = brother->child[i];
                    brother->child[i]->parent = check2;
                }

                for (int i = parent_index + 1; i < check2->parent->count - 2; i++ )
                {
                    check2->parent->key[i] = check2->parent->key[i + 1];
                }
                for (int i = parent_index + 1; i < check2->parent->count - 1; i++ )
                {
                    check2->parent->child[i] = check2->parent->child[i + 1];
                }
                check2->parent->count-- ;
                for (int i = previous ; i < check2->count;i++ )
                    check_and_change_key(get_rightest_leaf(check2->child[i]));

                brother->count = 0;
                delete brother;
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                check_inner_node(check2->parent);
                return;
            }
        }


    void C_b_tree_plus::check_repair( )
    {
        if (root->leaf) return;
        C_leaf_node *node;

        node = get_most_left_leaf(root);
        while(node)
        {
            check_and_change_key(node);
            node = node->get_next_leaf();
        }
    }
//------------------------------------------------------------------------------------------- 

    void C_b_tree_plus::read( C_node  *item) const
    {

        if (item->leaf)
        cout << "list ";
        for (int i = 0; i < item->count - 1; i++ )

        //cout << item->key[i]->get_value()[1] << " ";

        cout << endl;
         for (int i = 0; i < item->count; i++ )
         {
             if ( ! item->leaf)
             {
                 cout << "potomek " << i << endl;

                 read( (static_cast < C_inner_node* > (item))->child[i]);
             }


         }

    }

//------------------------------------------------------------------------------------------- 
    C_leaf_node * C_b_tree_plus::get_most_left_leaf( C_node  *item) const
    {

    while ( ! (item->leaf))
        item = static_cast < C_inner_node* > (item)->child[0];
    return static_cast < C_leaf_node* > (item);

    }

//------------------------------------------------------------------------------------------- 
    void C_b_tree_plus::read2( C_node  *item) const
    {cout << endl << "vypis je ";
        C_leaf_node *first = get_most_left_leaf(item);
        while(first)
        {
            for (int i = 0; i < first->count - 1;i++ )
               // cout << first->key[i]->get_value()[1] << " ";
            first = first->get_next_leaf();
        }

    }
    bool C_b_tree_plus::check( C_node  *item, C_node *par) const
    {
        C_inner_node * posl;
        if (item->parent != par)
            cout << " chyba ";
        if ( ! item->leaf)
        {
            posl = static_cast < C_inner_node* > (item);
            for (int i = 0; i < item->count; i++ )
            {
                check(  posl->child[i], item);

            }
        }
    return 0;
    }

//------------------------------------------------------------------------------------------- 
int C_b_tree_plus::get_dimension_of_tree () const
{
  return m;
}

// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 


void * inicialize_b_plus_tree(unsigned int size, int (*comp)(void *, void *), int size_of_value, int size_of_key){
  C_b_tree_plus *tree = new C_b_tree_plus(size, comp, size_of_value, size_of_key);
  return ((void*)tree);
}

void * create_or_find_struct_b_plus_tree(void * tree, void * key, b_plus_tree_item * item){
  C_key * found;
  found = ((C_b_tree_plus*)tree)->b_tree_plus_insert(C_key(key, ((C_b_tree_plus*)tree)->comp));
  item->value = found->get_value();
  item->key = found->get_key();
  return item->value;
}




void  destroy_b_plus_tree(void * tree){
  delete ((C_b_tree_plus*)tree);
}

int  delete_item_b_plus_tree(void * tree, b_plus_tree_item * delete_item ){
    void * key_to_del;
    C_leaf_node * leaf_del;
    int is_there_next;
    key_to_del = delete_item->key;
    leaf_del = ((C_key*)delete_item->c_key)->leaf;
    is_there_next = get_next_item_from_list(tree,delete_item);

    ((C_b_tree_plus*)tree)->b_tree_plus_delete_know_leaf(C_key(key_to_del, ((C_b_tree_plus*)tree)->comp), leaf_del);
    if(is_there_next == 0)
      return is_there_next;

    delete_item->i = ((C_key*)delete_item->c_key)->leaf->find_index_key(*((C_key*)delete_item->c_key));
    return is_there_next;

}




int  get_list(void * t, b_plus_tree_item * item){
        C_b_tree_plus * tree;
        tree = (C_b_tree_plus*)t;

        C_leaf_node *node;
        node = tree->get_most_left_leaf(tree->root);
        if(node == NULL && node->count!=0)
          return 0;
        item->i=0;
        item->c_key = (void *)node->key[0];
        item->key = node->key[0]->get_key();
        item->value = node->key[0]->get_value();
        return 1;


}

int get_next_item_from_list(void * t, b_plus_tree_item * item){
  C_leaf_node *node;
  C_key * key;
  key = (C_key*)(item->c_key);
  node = (key->leaf);
  if(item->i < node->count - 2){
    item->key = node->key[++item->i]->get_key();
    item->value = node->key[item->i]->get_value();
    item->c_key = (void*)node->key[item->i];
    return 1;
  }
  else if(node->get_next_leaf() != NULL){
    node= node->get_next_leaf();
    item->key = node->key[0]->get_key();
    item->value = node->key[0]->get_value();
    item->c_key = (void*)node->key[0];
    item->i = 0;
    return 1;
  } 
  return 0;

}













