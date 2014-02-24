/*!
 * \file b_plus_tree.c
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


#include "b_plus_tree.h"



inline void copy_key(void * to ,int index_to ,void * from , int index_from, int size_of_key){
	memcpy(to + (index_to * size_of_key), from + (index_from * size_of_key), size_of_key);
}


  C_node * c_node_create (int size_of_key, int m){
  	C_node * node;
  	node = (C_node*) calloc (sizeof(C_node),1);
  	node->key = (void*) calloc (size_of_key, m);
  	node->count = 1;
    return node;
  }

  void c_node_destroy (C_node * node){
    int i;
    free(node->key);

    //free leaf
    if(node->state_extend == EXTEND_LEAF){
      C_leaf_node * leaf;
      leaf = (C_leaf_node *) node->extend;
      for (i = 0; i < node->count - 1;i++ )
      {
        //free (leaf->value[i]);
      }
       free(leaf->value);
       free(leaf);
    }
    //free inner
    else if(node->state_extend == EXTEND_INNER){
    free(((C_inner_node*)node->extend)->child);
    free(node->extend);
    }
      free(node);
    }

 
  unsigned char  c_node_is_key (void * key,C_node * node, C_b_tree_plus * btree)
  {
      if (c_node_find_index_key(key, node, btree) != - 1) 
        return 1;
      return 0;
  }
 
  int  c_node_find_index_key     (void * key,C_node * node, C_b_tree_plus * btree) 
  {
  	int i;
      for (i = 0; i < node->count - 1; i++ )
        if (btree->compare(node->key+(i * btree->size_of_key), key) == EQUAL)
           return i;
    return - 1;
  }
 
  unsigned char c_node_is_leaf(C_node * node) 
  {
    return (node->state_extend == EXTEND_LEAF);
  }
 
  int c_node_get_gamma(C_node * node)
  {
    return node->count - 1;
  }
 
  C_node* c_node_get_parent(C_node * node) 
  { 
    return node->parent;
  }
 
  void * c_node_get_key(C_node * node, int index, int size_of_key) 
  {
    return node->key + (index - 1) * size_of_key;
  }
 







C_node * c_leaf_node_create(int m, int size_of_value, int size_of_key){
	C_node * node;
	C_leaf_node * leaf;
	node = c_node_create(size_of_key,m);
	leaf = (C_leaf_node*) calloc (sizeof(C_leaf_node), 1);
	leaf->value = (void *) calloc (sizeof(void *), m);
	node->extend = (void*)leaf;
	node->state_extend = EXTEND_LEAF;
  return node;
}


 
  void * c_leaf_node_get_value(C_leaf_node * node, int index)
  {
    return ((C_leaf_node*)node)->value[index - 1];
  }
 

 
  C_node* c_leaf_node_get_next_leaf(C_node * node){
    if(node->state_extend != EXTEND_LEAF)
    {
      return NULL;
    }
    return ((C_leaf_node*)node->extend)->right;
  }  
 
  int c_leaf_node_del_key_on_index(C_node * node, int index, int size_of_key)
  {
  	int i;
  	C_leaf_node * leaf;
  	leaf = (C_leaf_node*)node->extend;
  	free(leaf->value[index]);


  	   //memmove(node->key + index * size_of_key ,node->key + (index + 1) * size_of_key,(node->count - 2 - index) * size_of_key );
      for (i = index; i < node->count - 2; i++ )
      {
          //node->key[i] = node->key[i + 1];
        copy_key(node->key, i, node->key, i + 1, size_of_key);
          leaf->value[i] = leaf->value[i + 1];
      }
      node->count-- ;
      return node->count - 1;

  }



 
  //return value is index in leaf. If it returns -1, key is already in tree
  int   c_leaf_node_add_key_value ( void *key, C_node* node, C_b_tree_plus *btree, void ** return_value)
  {
      int i;
      C_leaf_node *leaf;
      leaf = ((C_leaf_node*)node->extend);
      i = c_node_find_index_key(key, node, btree);

      if (i != - 1) //key is already in leaf
      {
          *return_value = leaf->value[i];
          return -1;
      }
        //nalezne kam vlozit klic a hodnotu a vlozime
      i = node->count - 2; //index posledniho prvku

      while (i >= 0 && btree->compare(node->key + (i * btree->size_of_key), key) == MORE)
      {
         //node->key[i + 1] = node->key[i];
         memcpy(node->key + (i + 1) * btree->size_of_key, node->key + (i) * btree->size_of_key, btree->size_of_key);
         leaf->value[i + 1] = leaf->value[i];
         i-- ;


      }
      i++;
      leaf->value[i] = (void*)calloc(btree->size_of_value, 1);
      copy_key(node->key, i, key, 0, btree->size_of_key);
      node->count++;

      *return_value = leaf->value[i];
      return i;
  }




  C_node * c_inner_node_create(int size_of_key, int m){
  	C_inner_node * inner;
  	C_node * node;
  	inner = (C_inner_node*)calloc(sizeof(C_inner_node),1);
  	inner->child = (C_node**)calloc(sizeof(C_node*), m + 1);
  	node = c_node_create (size_of_key, m);
  	node->extend = (void*) inner;
  	node->state_extend = EXTEND_INNER;
  	return node;
  }


 
  C_node* c_inner_node_get_child(C_node * node ,int index) 
  {
    return ((C_inner_node*)node->extend)->child[index - 1];
  }
 
  int c_inner_node_addKey(void * add, C_node * left, C_node * right, C_node *node, C_b_tree_plus * btree )
  {
  	int i;
    C_inner_node *inner;
  	if (c_node_is_key(add,node,btree))
    {
      return ( - 1);
    }
  		
    inner = (C_inner_node*)node->extend;
  	i = node->count - 2;
  	while ( i >= 0 && btree->compare(node->key + i * btree->size_of_key , add) == MORE)
  	{
      //key[i + 1] = key[i];
      copy_key(node->key, i + 1, node->key, i, btree->size_of_key);
      inner->child[i + 2] = inner->child[i + 1];
      i-- ;
  	}
    copy_key(node->key, i + 1, add, 0, btree->size_of_key);
  	inner->child[i + 2] = right;
  	inner->child[i + 1] = left;

  	node->count++;
  	return node->count;
  }





  C_b_tree_plus * c_b_tree_plus_create(int m, int (*compare)(void *, void *), int size_of_value, int size_of_key)
  {
  	C_b_tree_plus * tree;
  	tree = (C_b_tree_plus*)calloc(sizeof(C_b_tree_plus),1);
  	tree->m = m;
    tree->root = c_leaf_node_create(m, size_of_value, size_of_key);
    tree->compare = compare;
    tree->size_of_value = size_of_value;
    tree->size_of_key = size_of_key;
    return tree;
  }
 
  void c_b_tree_plus_destroy(C_b_tree_plus * btree)
  {
    c_b_tree_plus_del_all_node(btree->root);
    free(btree);

  }
  
void c_b_tree_plus_del_all_node (C_node * del)
{
	int i;
    if (del->state_extend == EXTEND_LEAF){
        C_leaf_node * leaf;
        leaf = (C_leaf_node*)del->extend;
        for(i=0; i < del->count-1; i++)
        {
          free(leaf->value[i]);
        }
        c_node_destroy(del);
        return;
    }
    else
    {
      C_inner_node * inner;
      inner = (C_inner_node *)del->extend;
  		for (i = 0; i < del->count; i++)
  		{
  			c_b_tree_plus_del_all_node(inner->child[i]);
  		}
  		c_node_destroy(del);
    }

}
 

    int c_b_tree_plus_b_tree_plus_search(void * key, C_leaf_node** val, C_b_tree_plus * btree)
    {
        int result;
        C_node * node;
        node = c_b_tree_plus_find_leaf (key, btree);
        result = c_node_find_index_key(key, node, btree);
        if (result == - 1)
            {
                *val = NULL;
                return ( - 1);
            }
        *val = (C_leaf_node*)node->extend;
        return result + 1;

    }
 
//find index of certain child in parent
   int  c_b_tree_plus_find_my_index_in_parent  (C_node * son)
   {
    int i;
    if ( !(son->parent)) 
      return ( - 1);

    for (i = 0; i < son->parent->count; i++ )
    {
       if (((C_inner_node*)son->parent->extend)->child[i] == son)
       return i;
    }
    return ( - 2);
   }
 
    void c_b_tree_plus_add_to_node(void *key, C_node *left, C_node *right, C_b_tree_plus * btree)
    {
        int i;
        C_node *par;
        par= left->parent;
        //parent does not exist, has to be created and added as a parent to his children
        if (par == NULL)
        {
            par = c_inner_node_create(btree->size_of_key, btree->m);
            c_inner_node_addKey(key, left, right, par, btree );
            left->parent = par;
            right->parent = par;
            btree->root = par;
            //c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(right), btree);
            return;
        }
        //parent exists. Add key and check for size
        c_inner_node_addKey(key, left, right, par, btree );

//******** OPRAVIT
        
      /*  for (i = 0; i < par->count; i++ )
        {
            c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(((C_inner_node*)par->extend)->child[i]), btree);          

        }
        */
        //c_b_tree_plus_check_and_change_key(left,btree);
        //c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(right),btree);

        //size is ok, end
        if (par->count <= btree->m)
        {
            return;
        }
        //size is to big, split to inner node and repeat recursivly
        else
        {
            C_node *right_par, *righest_node_in_left_node;
            int cut, insert, i;
            right_par= c_inner_node_create(btree->size_of_key, btree->m);
            cut = (par->count - 1) / 2;
            insert = 0;
            //copy_key(right_par->key, insert, par->key, cut + 1, btree->size_of_key * (par->count -  cut - 2));
            for (i = cut + 1; i < par->count - 1; i++ )
            {
              //right_par->key[insert] = par->key[i];
              copy_key(right_par->key, insert, par->key, i, btree->size_of_key);
              ((C_inner_node*)right_par->extend)->child[insert++ ] = ((C_inner_node*)par->extend)->child[i];
            }
            ((C_inner_node*)right_par->extend)->child[insert++ ] = ((C_inner_node*)par->extend)->child[i]; //last child
            right_par->count = insert;
            par->count = cut + 1;
            right_par->parent = par->parent;
            for (i = 0; i < right_par->count; i++ )
            {
              ((C_inner_node*)right_par->extend)->child[i]->parent = right_par;
            }
    //zde by se mel predavat klid od left parent
            righest_node_in_left_node = c_b_tree_plus_get_rightest_leaf(((C_inner_node*)par->extend)->child[cut]);
            c_b_tree_plus_add_to_node(righest_node_in_left_node->key + (righest_node_in_left_node->count - 2) * btree->size_of_key , par, right_par, btree);
        }
    }
 
    //find leaf where is key, or where to add key
    C_node *  c_b_tree_plus_find_leaf (void *key, C_b_tree_plus * btree)
    {
    	int i;
        C_node *pos;
        unsigned char go_right, result;
        go_right = 0;
        pos = btree->root;
        while (pos->state_extend == EXTEND_INNER)
        {
            C_inner_node *pos2 = (C_inner_node*)pos->extend;
            go_right = 0;
            for (i = 0; i < pos->count - 1; i++ )
            {
            	result = btree->compare(key, pos->key + i * btree->size_of_key );
              if (result == LESS || result == EQUAL)
              {
                  pos = pos2->child[i];
                  go_right = 1;
                  break;
              }
            }
            if ( ! go_right)
                pos = pos2->child[pos->count - 1];
        }
        if (pos->state_extend == EXTEND_LEAF)
            return pos;
        return NULL;
    }
 
    void * c_b_tree_plus_b_tree_plus_insert(void * key, C_b_tree_plus *btree)
    {
        C_node * node_to_insert, * r_node;
        C_leaf_node * leaf_to_insert, * r_leaf;
        int size, splitVal, insert, i, index_of_new_key;
        void * added_or_found_value;
        node_to_insert = c_b_tree_plus_find_leaf(key, btree);
        index_of_new_key = c_leaf_node_add_key_value ( key, node_to_insert, btree, &added_or_found_value);
        
        //key is already in tree
        if (index_of_new_key == -1) 
        {
            return added_or_found_value;
        }
        btree->count_of_values++;
        leaf_to_insert = (C_leaf_node*)node_to_insert->extend;
        size = node_to_insert->count;
        //new value was added, we have to chceck size of leaf
        if (size <= btree->m)
        {
            //new item was added and size is OK. Just check keys in parents
            //if it is corner value, change parent key
            if(index_of_new_key == node_to_insert->count-2){
              c_b_tree_plus_check_and_change_key(node_to_insert, btree);
            }
            //check_repair( );
            return added_or_found_value;
        }
        //size is KO, we have to create new leaf and move half datas
        size-- ; //real count of values, not just default size m;
        splitVal = size / 2;
        r_node = c_leaf_node_create(btree->m, btree->size_of_value, btree->size_of_key);
        r_leaf = (C_leaf_node*)r_node->extend;
        insert = 0;
        //copy half datas to new leaf node
        //copy_key(r_node->key, insert, node_to_insert->key, splitVal, btree->size_of_key * (size - splitVal));
        for (i = splitVal; i < size; i++ )
        {
            //r_node->key[insert] = node_to_insert->key[i];
            copy_key(r_node->key, insert, node_to_insert->key, i, btree->size_of_key);
            r_leaf->value[insert++ ] = leaf_to_insert->value[i];
            

        }
        //set poiters to left, right, parent node
        r_node->count = insert + 1;
        node_to_insert->count = splitVal + 1;
        r_node->parent = node_to_insert->parent;
        r_leaf->right = leaf_to_insert->right;
        r_leaf->left = node_to_insert;
        leaf_to_insert->right = r_node;

        c_b_tree_plus_add_to_node(node_to_insert->key + (node_to_insert->count - 2) * btree->size_of_key, node_to_insert, r_node, btree);
        //check_repair( );
        //c_b_tree_plus_check_and_change_key(node_to_insert, btree);
        //c_b_tree_plus_check_and_change_key(r_node, btree);

        return added_or_found_value;
    }

  
     C_node * c_b_tree_plus_get_rightest_leaf (C_node * inner)
     {
        if (inner->state_extend == EXTEND_LEAF) 
          return inner;
        return c_b_tree_plus_get_rightest_leaf(((C_inner_node*)inner->extend)->child[inner->count - 1]);
     }
 
    void c_b_tree_plus_check_and_change_key (C_node * leaf_del, C_b_tree_plus * btree )
    {
            int parent_index;
            parent_index = c_b_tree_plus_find_my_index_in_parent(leaf_del);
             if (parent_index < 0)
            {
                return;
            }
            else if (parent_index <= leaf_del->parent->count - 2)
            {//set highest key in node, to parent key
                //leaf_del->parent->key[parent_index] = leaf_del->key[leaf_del->count - 2];
                copy_key(leaf_del->parent->key, parent_index, leaf_del->key, leaf_del->count - 2, btree->size_of_key );
            }
            else if (parent_index == leaf_del->parent->count - 1)
            {
                //change values in all parent till, they are not on the corner(highest value) of node
                C_node *par = leaf_del;

                while (parent_index == par->parent->count - 1)
                {
                    par = par->parent;
                    parent_index = c_b_tree_plus_find_my_index_in_parent(par);
                    //cout << "parent index je " << parent_index << endl;
                    if (parent_index < 0)
                    {	//parent does not exist
                    	return;
                    
                    }
                }
                copy_key(par->parent->key, parent_index, leaf_del->key, leaf_del->count - 2, btree->size_of_key );
            }
    }
 
    int c_b_tree_plus_b_tree_plus_delete(void * key, C_b_tree_plus * btree)
    {
        int index;
        C_node * leaf_del;
        leaf_del = c_b_tree_plus_find_leaf(key, btree);
        index = c_node_find_index_key(key, leaf_del, btree);
        return c_b_tree_plus_b_tree_plus_delete_know_leaf( index, leaf_del, btree);
    }
 
    int c_b_tree_plus_b_tree_plus_delete_know_leaf(int index,  C_node * leaf_del, C_b_tree_plus * btree){
        int  parent_index, size, i;   
        //key was not found
        if (index == ( - 1)) {
          return 0;
        }
        btree->count_of_values--;
        parent_index = c_b_tree_plus_find_my_index_in_parent(leaf_del);
        size = c_leaf_node_del_key_on_index(leaf_del, index, btree->size_of_key);
        if (size >= ((btree->m - 1) / 2) || btree->root->state_extend == EXTEND_LEAF)
        {
            //size is ok, just check parents keys;
            c_b_tree_plus_check_and_change_key(leaf_del, btree);
            return 1;
        }
        else
        {
            C_node *brother;
            C_leaf_node *brother_leaf;
            C_leaf_node *leaf_del_leaf;
            leaf_del_leaf = (C_leaf_node*)leaf_del->extend;
            //size is too small, we have to resolve this
            if ( parent_index > 0 && (((C_inner_node*)leaf_del->parent->extend)->child[parent_index - 1]->count - 1) > (btree->m - 1) / 2)
            {
                //rotation of value from left brother
                brother = ((C_inner_node*)leaf_del->parent->extend)->child[parent_index - 1];
                brother_leaf = (C_leaf_node*)brother->extend;
                for (i = leaf_del->count - 2; i >= 0; i-- )
                {
                    //leaf_del->key[i + 1] = leaf_del->key[i];
                    copy_key(leaf_del->key,i + 1 ,leaf_del->key ,i , btree->size_of_key);
                    leaf_del_leaf->value[i + 1] = leaf_del_leaf->value[i];
                }
                leaf_del->count++;
                //leaf_del->key[0] = brother->key[brother->count - 2];
                copy_key(leaf_del->key,0 ,brother->key, brother->count - 2, btree->size_of_key);
                leaf_del_leaf->value[0] = brother_leaf->value[brother->count - 2];
                brother->count-- ;
                c_b_tree_plus_check_and_change_key(brother, btree);
                if(index == leaf_del->count-2){
                    c_b_tree_plus_check_and_change_key(leaf_del, btree);
                  }

            }
            else if ( parent_index < leaf_del->parent->count - 1 && ((((C_inner_node*)leaf_del->parent->extend)->child[parent_index + 1]->count) - 1) > (btree->m - 1) / 2)
            {

                //rotation of value from rigth brother
                brother = ((C_inner_node*)leaf_del->parent->extend)->child[parent_index + 1];
                brother_leaf = (C_leaf_node*)brother->extend;

                leaf_del->count++;
                //leaf_del->key[leaf_del->count - 2] = brother->key[0];
                copy_key(leaf_del->key,leaf_del->count - 2 ,brother->key, 0, btree->size_of_key);
                leaf_del_leaf->value[leaf_del->count - 2] = brother_leaf->value[0];
                brother->count-- ;
                for (i = 0; i < brother->count - 1;i++ )
                {
                    //brother->key[i] = brother->key[i + 1];
                    copy_key(brother->key, i ,brother->key, i+1, btree->size_of_key);
                    brother_leaf->value[i] = brother_leaf->value[i + 1];
                }
                c_b_tree_plus_check_and_change_key(leaf_del, btree);
            }
            else if ( parent_index > 0 )
            {
                //merge with left brother
                brother = ((C_inner_node*)leaf_del->parent->extend)->child[parent_index - 1];
                brother_leaf = (C_leaf_node*)brother->extend;

                //copy_key(brother->key, (brother->count) - 1, leaf_del->key, 0, btree->size_of_key * (leaf_del->count - 1));
                for (i = 0; i < leaf_del->count - 1;i++ )
                {
                    ++brother->count;
                    //brother->key[(brother->count) - 2] = leaf_del->key[i];
                    copy_key(brother->key, (brother->count) - 2, leaf_del->key, i, btree->size_of_key);
                    brother_leaf->value[brother->count - 2] = leaf_del_leaf->value[i];

                }
                brother_leaf->right = leaf_del_leaf->right;
                if (leaf_del_leaf->right)
                     ((C_leaf_node*)leaf_del_leaf->right->extend)->left = brother;
                //move indexs in perent
                for (i = parent_index; i < leaf_del->parent->count - 2; i++ )
                {
                    //leaf_del->parent->key[i] = leaf_del->parent->key[i + 1];
                    copy_key(leaf_del->parent->key, i, leaf_del->parent->key, i + 1, btree->size_of_key);
                }
                for (i = parent_index; i < leaf_del->parent->count - 1; i++ )
                {
                    ((C_inner_node*)leaf_del->parent->extend)->child[i] = ((C_inner_node*)leaf_del->parent->extend)->child[i + 1];
                }
                leaf_del->parent->count-- ;
                c_b_tree_plus_check_and_change_key(brother, btree);
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                c_b_tree_plus_check_inner_node(brother->parent, btree);
                leaf_del->count = 0;
                c_node_destroy(leaf_del);


            }
            else if (parent_index < leaf_del->parent->count - 1)
            {
                //slouceni s pravym bratrem
                brother = ((C_inner_node*)leaf_del->parent->extend)->child[parent_index + 1];
                brother_leaf = (C_leaf_node*)brother->extend;
                //copy values
                //copy_key(leaf_del->key, (leaf_del->count) - 1, brother->key, i, btree->size_of_key * (brother->count - 1));
                for (i = 0; i < brother->count - 1;i++ )
                {
                    ++ leaf_del->count;
                    //leaf_del->key[(++ leaf_del->count) - 2] = brother->key[i];
                    copy_key(leaf_del->key, (leaf_del->count) - 2, brother->key, i, btree->size_of_key);
                    leaf_del_leaf->value[leaf_del->count - 2] = brother_leaf->value[i];
                }
                leaf_del_leaf->right = brother_leaf->right;
                if (brother_leaf->right)
                     ((C_leaf_node*)brother_leaf->right->extend)->left = leaf_del;
                for (i = parent_index + 1; i < leaf_del->parent->count - 2; i++ )
                {
                    //leaf_del->parent->key[i] = leaf_del->parent->key[i + 1];
                    copy_key(leaf_del->parent->key, i, leaf_del->parent->key, i + 1, btree->size_of_key);
                }
                for (i = parent_index + 1; i < leaf_del->parent->count - 1; i++ )
                {
                    ((C_inner_node*)leaf_del->parent->extend)->child[i] = ((C_inner_node*)leaf_del->parent->extend)->child[i + 1];
                }
                leaf_del->parent->count-- ;
                c_b_tree_plus_check_and_change_key(leaf_del, btree);
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                c_b_tree_plus_check_inner_node(leaf_del->parent, btree);
                brother->count = 0;
                c_node_destroy(brother);
            }
        }
        //c_b_tree_plus_check_repair(btree);
        return 1;



    }
 
    void c_b_tree_plus_check_inner_node (C_node * check, C_b_tree_plus *btree)
    {
        int parent_index, i;
        C_node *brother;
        C_inner_node *brother_inner;
        C_inner_node *check_inner;
        if (check->count - 1 >= ((btree->m - 1) / 2))
        {
            //size id ok, end;
            return ;
        }
        //if just one child, let child to be root
        if (check == btree->root)
        {   
            if (check->count <= 1)
            {
                btree->root = ((C_inner_node*)btree->root->extend)->child[0];
                btree->root->parent = NULL;
                check->count = 0;
                c_node_destroy(check);
            }
             return;
        }
        parent_index = c_b_tree_plus_find_my_index_in_parent(check);
        check_inner = (C_inner_node*)check->extend;
        if ( parent_index > 0 && (((C_inner_node*)check->parent->extend)->child[parent_index - 1]->count - 1) > (btree->m - 1) / 2)
            {

                //rotace z leveho bratra
                brother = ((C_inner_node*)check->parent->extend)->child[parent_index - 1];
                brother_inner = (C_inner_node*)brother->extend;
                for (i = check->count - 1; i >= 0; i-- )
                {
                    check_inner->child[i + 1] = check_inner->child[i];
                }
                for (i = check->count - 2; i >= 0; i-- )
                {
                    //check->key[i + 1] = check->key[i];
                    copy_key(check->key, i + 1, check->key, i, btree->size_of_key);
                }
                check->count++;
                //check->key[0] = brother->key[brother->count - 2];
                copy_key(check->key ,0 , check->parent->key, parent_index - 1, btree->size_of_key); //add
                copy_key(check->parent->key, parent_index - 1, brother->key ,brother->count - 2 , btree->size_of_key); //add
                check_inner->child[0] = brother_inner->child[brother->count - 1];
   /*zmena*/    check_inner->child[0]->parent = check;
                brother->count-- ;
                //c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(brother), btree);
                //c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(check_inner->child[0]), btree);



            }
            else if ( parent_index < check->parent->count - 1 && (((C_inner_node*)check->parent->extend)->child[parent_index + 1]->count - 1) > (btree->m - 1) / 2)
            {
                //rotace z praveho bratra
                brother = ((C_inner_node*)check->parent->extend)->child[parent_index + 1];
                brother_inner = (C_inner_node*)brother->extend;

                check->count++;
                //check->key[check->count - 2] = brother->key[0];
                copy_key(check->key ,check->count - 2 , check->parent->key, parent_index, btree->size_of_key); //add
                copy_key(check->parent->key, parent_index, brother->key ,0 , btree->size_of_key); //add
                //copy_key(check->key,check->count - 2, brother->key,0, btree->size_of_key);
                check_inner->child[check->count - 1] = brother_inner->child[0];
   /*zmena*/    check_inner->child[check->count - 1]->parent = check;
                brother->count-- ;
                for (i = 0; i < brother->count - 1;i++ )
                {
                    //brother->key[i] = brother->key[i + 1];
                    copy_key(brother->key, i, brother->key, i + 1, btree->size_of_key);
                }
                for (i = 0; i < brother->count;i++ )
                {
                    brother_inner->child[i] = brother_inner->child[i + 1];
                }

                //c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(check_inner->child[check->count - 2]), btree);
                //c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(check), btree);
            }
            else if ( parent_index > 0 )
            {
                //slouceni s levym bratrem
                int previous;
                brother = ((C_inner_node*)check->parent->extend)->child[parent_index - 1];
                brother_inner = (C_inner_node*)brother->extend;

                previous = brother->count - 1;
                for (i = 0; i < check->count;i++ )
                {
                    brother_inner->child[(++ brother->count) - 1] = check_inner->child[i];
                    check_inner->child[i]->parent = brother;
                    //++ brother->count;
                    //cout << "jedu tu jednou" << brother->count << endl;
                }

                for (i = parent_index; i < check->parent->count - 2; i++ )
                {
                    //check->parent->key[i] = check->parent->key[i + 1];
                    copy_key(check->parent->key, i, check->parent->key, i + 1, btree->size_of_key);
                }
                for (i = parent_index; i < check->parent->count - 1; i++ )
                {
                    ((C_inner_node*)check->parent->extend)->child[i] = ((C_inner_node*)check->parent->extend)->child[i + 1];
                }
                check->parent->count-- ;
//*********KONTROLA
                for (i = previous ; i < brother->count;i++ )
                    c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(brother_inner->child[i]), btree);
                check->count = 0;
                c_node_destroy(check);
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                c_b_tree_plus_check_inner_node(brother->parent, btree);
                return;

            }
            else if (parent_index < check->parent->count - 1)
            {
                int previous, i;
                //slouceni s pravym bratrem
                brother = ((C_inner_node*)check->parent->extend)->child[parent_index + 1];
                brother_inner = (C_inner_node*)brother->extend;
                previous = check->count - 1;
                for (i = 0; i < brother->count; i++)
                {
                    check_inner->child[(++ check->count) - 1] = brother_inner->child[i];
                    brother_inner->child[i]->parent = check;
                }

                for (i = parent_index + 1; i < check->parent->count - 2; i++ )
                {
                    //check->parent->key[i] = check->parent->key[i + 1];
                    copy_key(check->parent->key, i, check->parent->key, i + 1, btree->size_of_key);
                }
                for (i = parent_index + 1; i < check->parent->count - 1; i++ )
                {
                    ((C_inner_node*)check->parent->extend)->child[i] = ((C_inner_node*)check->parent->extend)->child[i + 1];
                }
                check->parent->count-- ;
                for (i = previous ; i < check->count;i++ )
                    c_b_tree_plus_check_and_change_key(c_b_tree_plus_get_rightest_leaf(check_inner->child[i]), btree);

                brother->count = 0;
                c_node_destroy(brother);
                //check Inner node !  !  !  !  !  !  !  !  !  ! 
                c_b_tree_plus_check_inner_node(check->parent, btree);
                return;
            }
        }


    void c_b_tree_plus_check_repair(C_b_tree_plus *btree)
    {
      int i=0;
        C_node *node;
        if (btree->root->state_extend == EXTEND_LEAF) 
          return;

        node = c_b_tree_plus_get_most_left_leaf(btree->root);
        while(node)
        { 
            //printf("je to tu %d\n",i++);
            c_b_tree_plus_check_and_change_key(node, btree);
            node = ((C_leaf_node*)node->extend)->right;
        }
    }



 
    C_node * c_b_tree_plus_get_most_left_leaf( C_node  *item) 
    {

    while (item->state_extend == EXTEND_INNER)
        item = ((C_inner_node*)item->extend)->child[0];
    return item;

    }

 
    /*void C_b_tree_plus::read2( C_node  *item) const
    {cout << endl << "vypis je ";
        C_leaf_node *first = get_most_left_leaf(item);
        while(first)
        {
            for (int i = 0; i < first->count - 1;i++ )
               // cout << first->key[i]->get_value()[1] << " ";
            first = first->get_next_leaf();
        }

    }
    */
   /* bool C_b_tree_plus::check( C_node  *item, C_node *par) const
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
*/
 





void * inicialize_b_plus_tree(unsigned int size_of_btree_node, int (*comp)(void *, void *), unsigned int size_of_value, unsigned int size_of_key)
{
  C_b_tree_plus *tree = c_b_tree_plus_create(size_of_btree_node, comp, size_of_value, size_of_key);
  return ((void*)tree);
}

void * create_or_find_struct_b_plus_tree(void * btree, void * key)
{
  return c_b_tree_plus_b_tree_plus_insert(key, (C_b_tree_plus*)btree);
}




void  destroy_b_plus_tree(void * tree)
{
  c_b_tree_plus_destroy((C_b_tree_plus*)tree);
}

int  delete_item_b_plus_tree(void * btree, b_plus_tree_item * delete_item )
{

    C_node * leaf_del;
    int is_there_next, index_of_delete_item;
    leaf_del = delete_item->leaf;
    //key_to_del = delete_item->key;
    index_of_delete_item = delete_item->index_of_value;
    //get next value
    //printf("%lu\n",((unsigned long int*)delete_item->key)[1] );
    is_there_next = get_next_item_from_list(btree,delete_item);
//printf(" detele item %lu\n",((unsigned long int*)key_to_del)[1] );

    c_b_tree_plus_b_tree_plus_delete_know_leaf(index_of_delete_item, leaf_del,(C_b_tree_plus*)btree);
    if(is_there_next == 0)
      return is_there_next;
    //c_b_tree_plus_check_repair((C_b_tree_plus*)btree);
//printf(" index %d ip %lu %lu\n", delete_item->index_of_value ,((unsigned long int*)delete_item->key)[0] ,((unsigned long int*)delete_item->key)[1] );
    delete_item->leaf = c_b_tree_plus_find_leaf(delete_item->key, (C_b_tree_plus*)btree);
    delete_item->index_of_value = c_node_find_index_key(delete_item->key, delete_item->leaf, (C_b_tree_plus*)btree);
int i;
   /* for(i=0; i<delete_item->leaf->count-1;i++){
      printf("\t index %d i %d ip %lu\n",delete_item->index_of_value, i,((unsigned long int*)delete_item->leaf->key)[2*i+1] );
    }
    */

    return is_there_next;
}


unsigned long int get_count_of_values(void * btree){
  return ((C_b_tree_plus*)btree)->count_of_values;
}

int  get_list(void * t, b_plus_tree_item * item)
{
  C_b_tree_plus * tree;
  C_node *node;
  tree = (C_b_tree_plus*)t;
  node = c_b_tree_plus_get_most_left_leaf(tree->root);
  if(node == NULL || node->count==1)
    return 0;
  item->index_of_value = 0;
  item->value = ((C_leaf_node*)node->extend)->value[0];
  copy_key(item->key,0, node->key,0, tree->size_of_key);
  item->leaf = node;
  return 1;
}

b_plus_tree_item * create_list_item (void * btree)
{
  b_plus_tree_item *item;
  item = (b_plus_tree_item*)calloc(sizeof(b_plus_tree_item), 1);
  item->key = (void*)calloc(((C_b_tree_plus*)btree)->size_of_key, 1);
  return item;
}

void destroy_list_item(b_plus_tree_item * item)
{
  free(item->key);
  free(item);
}

int get_next_item_from_list(void * t, b_plus_tree_item * item)
{
  C_node *node;
  C_leaf_node *leaf;
  node = item->leaf;
  leaf = (C_leaf_node*)node->extend;
  if(item->index_of_value < node->count - 2){
    ++item->index_of_value;
    copy_key(item->key,0,node->key, item->index_of_value, ((C_b_tree_plus*)t)->size_of_key);
    item->value = leaf->value[item->index_of_value];
    return 1;
  }
  else if(c_leaf_node_get_next_leaf(node) != NULL){
    node = c_leaf_node_get_next_leaf(node);
    copy_key(item->key,0,node->key, 0, ((C_b_tree_plus*)t)->size_of_key);
    item->value = ((C_leaf_node*)node->extend)->value[0];
    item->leaf = node;
    item->index_of_value = 0;
    return 1;
  } 
  return 0;

}
