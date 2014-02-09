#include <cstdlib> 
#include <cstdio> 
#include <ctime> 
#include <iostream> 
#include <fstream> 
#include <cassert> 
#include "b_plus_tree.h"
using namespace std;






  C_key::C_key (uint32_t v) 
  {
    value = &v;
  }

  C_key::C_key (uint32_t *v) {
    value = v;
  }

  C_key::~C_key () {}

  uint32_t C_key::get_value () const { return *this->value; }
  void C_key::set_value (int v) { *value = v; }

// ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  ==  == 
  C_value::C_value (uint32_t v)    : value ((ip_address_t *) calloc(sizeof(ip_address_t),1)) 
  {
    value->state = STATE_NEW;
    value->ip = v;
    value->paret_in_b_plus_tree = this;
  }
  C_value::C_value (const C_key & i) : value ((ip_address_t *) calloc(sizeof(ip_address_t),1)) 
  {
    value->ip =  i.get_value ();
    value->state = STATE_NEW;
  }
  C_value::C_value (const C_key & i,  const C_leaf_node * leaf)    : value ((ip_address_t *) calloc(sizeof(ip_address_t),1)) 
  {
    value->state = STATE_NEW;
    value->ip =  i.get_value ();
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

  C_key * C_value::create_key(){
    return new C_key(&(value->ip));
  }






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
      value = new C_value * [m];
      left = 0;
      right = 0;
      leaf = 1;

  }
//------------------------------------------------------------------------------------------- 
  C_leaf_node::~C_leaf_node()
  {

      for (int i = 0; i < count - 1;i++ )
      {
      delete key[i];
      delete value[i];
      }
      delete [] key;
      delete [] value;

  }
//------------------------------------------------------------------------------------------- 
  C_value& C_leaf_node::get_value(int index) const 
  {
    return *value[index - 1];
  }
//------------------------------------------------------------------------------------------- 
  C_leaf_node* C_leaf_node::get_next_leaf() const {
    return right;
  }  
//------------------------------------------------------------------------------------------- 

  int C_leaf_node::del_key_on_index(const int &index)
  {
      delete key[index];
      delete value[index];

      for (int i = index; i < count - 2; i++ )
      {
          key[i] = key[i + 1];
          value[i] = value[i + 1];
      }
      count-- ;
      return count - 1;

  }

//------------------------------------------------------------------------------------------- 
  C_value * C_leaf_node::add_key_value ( const C_key & a_key )
  {
      int i;
      i = find_index_key(a_key);

      if (i != - 1) //klic se jiz v listu nachazi
      {
          new_key_added = false;
          return value[i];
      }
        //nalezne kam vlozit klic a hodnotu a vlozime
      i = count - 2; //index posledniho prvku

      while (i >= 0 && *key[i] > a_key)
      {
         key[i + 1] = key[i];
         value[i + 1] = value[i];
         i-- ;


      }
      value[i + 1] = new C_value(a_key, this);
      key[i + 1] = value[i + 1]->create_key();
      new_key_added = true;
      count++;

      return value[i + 1];
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

  C_b_tree_plus::C_b_tree_plus(int m):m(m)
  {
      root = new C_leaf_node(m);
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
                if (f_key <= *pos2->key[i])
                    {
                        pos = pos2->child[i];
                        goRight = 1;
                        break;
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
    C_value * C_b_tree_plus::b_tree_plus_insert(const C_key& key)
    {
        C_leaf_node * leaf_to_insert;
        int size;
        C_value * added_or_found_value;
        leaf_to_insert = find_leaf(key);
        added_or_found_value = leaf_to_insert->add_key_value(key);
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
            r_leaf->key[insert] = leaf_to_insert->key[i];
            r_leaf->value[insert++ ] = leaf_to_insert->value[i];
            leaf_to_insert->value[i]->change_parent((void*)r_leaf);
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
            //check_repair( );
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
                    leaf_del->value[i + 1] = leaf_del->value[i];
                }
                leaf_del->count++;
                leaf_del->key[0] = brother->key[brother->count - 2];
                leaf_del->value[0] = brother->value[brother->count - 2];
                leaf_del->value[0]->change_parent((void*)leaf_del);
                brother->count-- ;
                check_and_change_key(brother);

            }
            else if ( parent_index < leaf_del->parent->count - 1 && ((leaf_del->parent->child[parent_index + 1]->count) - 1) > (m - 1) / 2)
            {

                //rotace z praveho bratra
                brother = static_cast < C_leaf_node* > (leaf_del->parent->child[parent_index + 1]);

                leaf_del->count++;
                leaf_del->key[leaf_del->count - 2] = brother->key[0];
                leaf_del->value[leaf_del->count - 2] = brother->value[0];
                leaf_del->value[leaf_del->count - 2]->change_parent((void*)leaf_del);
                brother->count-- ;
                for (int i = 0; i < brother->count - 1;i++ )
                {
                    brother->key[i] = brother->key[i + 1];
                    brother->value[i] = brother->value[i + 1];
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
                    brother->value[brother->count - 2] = leaf_del->value[i];
                    brother->value[brother->count - 2]->change_parent((void*)brother);
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
                    leaf_del->value[leaf_del->count - 2] = brother->value[i];
                    leaf_del->value[leaf_del->count - 2]->change_parent((void*)leaf_del);
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
        check_repair( );
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

        cout << item->key[i]->get_value() << " ";

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
                cout << first->key[i]->get_value() << " ";
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


void * inicialize_b_plus_tree(unsigned int size){
  C_b_tree_plus *tree = new C_b_tree_plus(size);
  return ((void*)tree);
}

ip_address_t * create_or_find_struct_b_plus_tree(void * tree, uint32_t ip){
  return((C_b_tree_plus*)tree)->b_tree_plus_insert(ip)->get_value();
}




void  destroy_b_plus_tree(void * tree){
  delete ((C_b_tree_plus*)tree);
}

void  delete_item_b_plus_tree(void * tree, ip_address_t * delete_item ){

  ((C_b_tree_plus*)tree)->b_tree_plus_delete_know_leaf(delete_item->ip, (C_leaf_node*)delete_item->paret_in_b_plus_tree);
/*
  C_b_tree_plus *new_tree,
            *oldtree;
    oldtree = (C_b_tree_plus*)tree;
   new_tree = new C_b_tree_plus( oldtree->get_dimension_of_tree());
   while(list_of_suspision != NULL){
    new_tree->b_tree_plus_insert()
   }*/
}




ip_address_t * get_list(void * t){
        C_b_tree_plus * tree;
        ip_address_t * ip;
        ip_address_t * previous = NULL;
        tree = (C_b_tree_plus*)t;

        C_leaf_node *node;
        C_leaf_node *first;

        first = tree->get_most_left_leaf(tree->root);
        node = first;
        while(node)
        {

            for(int i = 0; i < node->count - 1; i++ ){
              ip = node->value[i]->get_value();
              if(previous != NULL){
                previous->next = ip;
              }
              previous = ip;
            }
            
            node = node->get_next_leaf();
        }

  return first->value[0]->get_value();    
}













