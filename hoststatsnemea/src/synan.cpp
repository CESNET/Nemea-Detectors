#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>

#include "synan.h"
#include "lexan.h"

#ifdef STREAM_VERSION
#include "stream_version/hoststats.h"
#else
#include "timeslot_version/hoststats.h"
#endif

#define DECIMAL_BASE 10

#define NULL_CHECK(ptr) do { \
   if ( ptr == NULL ) { \
      printf("!!!NULL FOUND!!!\n"); \
      errno = E_INTERNAL; \
      return EXIT_FAILURE; \
   } \
} while ( 0 )

#define CALL_CHECK(f) do { \
   if ( f == EXIT_FAILURE ) { \
      printf("!!!FUNCTION CALL FAILED!!!\n"); \
      return EXIT_FAILURE; \
   } \
} while ( 0 )

#define EOF_CHECK do { \
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str()); \
   if ( lex->last_rc == TOKEN_EOF ) { \
      printf("TOKEN recognized as an EOF\n"); \
      if ( pars == 0 ) { \
         printf("EOF FOUND\n"); \
         return EXIT_SUCCESS; \
      } \
      else { \
         printf("PARS CHECKSUM FAILED\n"); \
         errno = E_PARENTHESES; \
         return EXIT_FAILURE; \
      } \
   } \
} while ( 0 )

#define DIR_CHECK do { \
   if ( dir() == EXIT_SUCCESS ) \
      lex->get_token(); \
   else { \
      if ( errno == E_FIRST_LVL ) \
         errno = E_OK; \
      else { \
         printf("DIR FAILED\n");\
         return EXIT_FAILURE; \
      } \
   } \
} while ( 0 )

#define OP_CHECK do { \
   if ( log_op() == EXIT_SUCCESS ) { \
      lex->get_token(); \
      printf("CALLING stat3\n"); \
      return stat3(); \
   } \
   else { \
      if ( errno == E_FIRST_LVL ) \
         errno = E_OK; \
      else { \
         printf("OP FAILED\n");\
         return EXIT_FAILURE; \
      } \
   } \
   printf("Calling op()\n"); \
   CALL_CHECK(op()); \
   printf("Calling op() -- NP\n"); \
   lex->get_token(); \
   printf("CALLING stat2\n");\
   return stat2(); \
} while ( 0 )

#define LBRACKET_CHECK(f) do { \
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str()); \
   if( lex->last_rc == TOKEN_LBRACKET ) { \
      printf("TOKEN recognized as a left bracket\n"); \
      pars++; \
      current->par_break = true; \
      lex->get_token(); \
      return f; \
   } \
} while ( 0 )

#define SET_DATA(p) do { \
   if ( mode == MODE_BOTH ) \
      data = rec.in_##p + rec.out_##p; \
   \
   else if ( mode == MODE_IN ) \
      data = rec.in_##p; \
   \
   else if ( mode == MODE_OUT ) \
      data = rec.out_##p; \
} while ( 0 )

#define PLACE_OP do { \
   if ( current->IsFull() ) { \
      DrTreeNode *tmp = new DrTreeNode; \
      tmp->type = TYPE_OP; \
      tmp->data = lex->last_rc; \
      int insert_rc = current->Insert(tmp); \
      if ( insert_rc == INSERT_FAILED ) { \
         printf("INSERT FAILED\n"); \
         return EXIT_FAILURE; \
      } \
      else if ( insert_rc == INSERT_ROOT ) \
         tree = tree->root; \
      current = tmp; \
   } \
   else { \
      if ( current->type == TYPE_EMPTY ) { \
         current->type = TYPE_OP; \
         current->data = lex->last_rc; \
      } \
      else { \
         printf("PLACE FAILED\n"); \
         errno = E_INTERNAL; \
         return EXIT_FAILURE; \
      } \
   } \
} while ( 0 )

enum insert_codes {
   INSERT_FAILED,
   INSERT_BRANCH,
   INSERT_ROOT
};

// Priority of operators
int ops_map[] = {
   0,0,0,2,2,1,1,0,0,0,0,3,3,3,3,3,3,0,4,4,4 //see lexan_ret enum in lexan.h
};

// D r T r e e N o d e **************************************
// P U B L I C **********************************************

int DrTreeNode::AddNewRoot(DrTreeNode *new_root)
{
   printf("AddNewRoot START\n");
   NULL_CHECK(new_root);

   if ( new_root->IsFull() ) {
      errno = E_INTERNAL;
      return EXIT_FAILURE;
   }

   // If "this" already has a root, make the roots branch point to the new_root
   if ( root != NULL ) {
      if ( root->l_ptr == this )
         root->l_ptr = new_root;

      else if ( root->r_ptr == this )
         root->r_ptr = new_root;

      else {
         errno = E_INTERNAL;
         return EXIT_FAILURE;
      }
   }

   root = new_root; // Set root of "this" to the new_root
   *(new_root->active) = this; // Set active branch of new_root to "this"
   new_root->MoveActive();

   printf("AddNewRoot END\n");
   return EXIT_SUCCESS;
}

int DrTreeNode::AddNewBranch(DrTreeNode *new_branch)
{
   printf("AddNewBranch START\n");
   NULL_CHECK(new_branch);

   if ( new_branch->IsFull() ) {
      errno = E_INTERNAL;
      return EXIT_FAILURE;
   }

   // Takes one branch out of "this", adds it into new_branch and replaces old branch with the new_branch
   if ( this->IsFull() ) {
      *(new_branch->active) = this->r_ptr;
      new_branch->MoveActive();
      this->r_ptr->root = new_branch;
      this->r_ptr = new_branch;
   }

   else {
      *active = new_branch;
      MoveActive();
   }

   new_branch->root = this;

   printf("AddNewBranch END\n");
   return EXIT_SUCCESS;
}

int DrTreeNode::Copy(DrTreeNode *new_tree)
{
   NULL_CHECK(new_tree);

   memcpy(new_tree, this, sizeof(DrTreeNode));

   if ( l_ptr != NULL ) {
      new_tree->l_ptr = new DrTreeNode;
      l_ptr->Copy(new_tree->l_ptr);
   }

   if ( r_ptr != NULL ) {
      new_tree->r_ptr = new DrTreeNode;
      r_ptr->Copy(new_tree->r_ptr);
   }

   return EXIT_SUCCESS;
}

void DrTreeNode::Delete()
{
   if ( l_ptr != NULL )
      l_ptr->Delete();

   if ( r_ptr != NULL )
      r_ptr->Delete();

   if ( root != NULL ) {
      if ( root->l_ptr == this ) {
         //delete root->l_ptr;
         root->l_ptr = NULL;
      }

      else if ( root->r_ptr == this ) {
         //delete root->r_ptr;
         root->r_ptr = NULL;
      }
   }
}

int DrTreeNode::Insert(DrTreeNode *node)
{
   printf("Insert START\n");
   NULL_CHECK(node);

   DrTreeNode *tmp = this;
   DrTreeNode *prev = tmp;

   while ( tmp != NULL ) {
      if ( tmp->type != TYPE_OP || node->type != TYPE_OP ) {
         errno = E_INTERNAL;
         return INSERT_FAILED;
      }

      if ( node->data >= sizeof(ops_map) || tmp->data >= sizeof(ops_map) ) {
         errno = E_INTERNAL;
         return INSERT_FAILED;
      }
      if ( ops_map[node->data] < ops_map[tmp->data] || tmp->par_break == true )
         break;

      prev = tmp;
      tmp = tmp->root;
   }

   if ( prev == this ) {
      this->AddNewBranch(node);
      return INSERT_BRANCH;
   }

   else {
      prev->AddNewRoot(node);
      return INSERT_ROOT;
   }
   printf("Insert END\n");
}

bool DrTreeNode::IsFull()
{
   return full;
}

int DrTreeNode::MoveActive()
{
   printf("MoveActive START\n");
   if ( this->IsFull() )
      return EXIT_FAILURE;

   if ( *active == l_ptr )
      active = &r_ptr;

   else if ( *active == r_ptr ) {
      active = NULL;
      full = true;
   }

   printf("MoveActive END\n");
   return EXIT_SUCCESS;
}

int DrTreeNode::Optimize()
{
   if ( l_ptr != NULL && l_ptr->type == TYPE_OP )
      l_ptr->Optimize();

   if ( r_ptr != NULL && r_ptr->type == TYPE_OP )
      r_ptr->Optimize();

   if ( l_ptr != NULL && r_ptr != NULL && l_ptr->type == TYPE_NUM && r_ptr->type == TYPE_NUM )
      return Resolve();

   return EXIT_SUCCESS;
}

void DrTreeNode::Print()
{
   printf("Data: %d\n", data);

   if (l_ptr != NULL) {
      printf("LPTR\n");
      l_ptr->Print();
   }

   if (r_ptr != NULL) {
      printf("RPTR\n");
      r_ptr->Print();
   }
}

int DrTreeNode::RemovePar()
{
   printf("RemovePar START\n");
   for ( DrTreeNode *tmp = this; tmp != NULL; tmp = tmp->root ) {
      if ( tmp->par_break == true ) {
         tmp->par_break = false;
         printf("RemovePar END\n");
         return EXIT_SUCCESS;
      }
   }

   errno = E_PARENTHESES;
   return EXIT_FAILURE;
}

int DrTreeNode::Resolve()
{
   if ( l_ptr != NULL && l_ptr->type == TYPE_OP )
      CALL_CHECK(l_ptr->Resolve());

   if ( r_ptr != NULL && r_ptr->type == TYPE_OP )
      CALL_CHECK(r_ptr->Resolve());

   if ( l_ptr != NULL && r_ptr != NULL
       &&
       l_ptr->type == TYPE_NUM && r_ptr->type == TYPE_NUM && this->type == TYPE_OP )
   {
      switch ( data ) {
      case TOKEN_PLUS:
         data = l_ptr->data + r_ptr->data;
      break;

      case TOKEN_MINUS:
         data = l_ptr->data - r_ptr->data;
      break;

      case TOKEN_STAR:
         data = l_ptr->data * r_ptr->data;
      break;

      case TOKEN_SLASH:
         data = l_ptr->data / r_ptr->data;
      break;

      case TOKEN_EQUAL:
         data = ( l_ptr->data == r_ptr->data );
      break;

      case TOKEN_UNEQUAL:
         data = ( l_ptr->data != r_ptr->data );
      break;

      case TOKEN_BIGGER:
         data = ( l_ptr->data > r_ptr->data );
      break;

      case TOKEN_SMALLER:
         data = ( l_ptr->data < r_ptr->data );
      break;

      case TOKEN_SMEQUAL:
         data = ( l_ptr->data <= r_ptr->data );
      break;

      case TOKEN_BEQUAL:
         data = ( l_ptr->data >= r_ptr->data );
      break;

      case TOKEN_AND:
         data = ( l_ptr->data && r_ptr->data );
      break;

      case TOKEN_OR:
         data = ( l_ptr->data || r_ptr->data );
      break;

      default:
         errno = E_INTERNAL;
         return EXIT_FAILURE;
      }

      type = TYPE_NUM;
      delete l_ptr;
      delete r_ptr;
      l_ptr = NULL;
      r_ptr = NULL;
      return EXIT_SUCCESS;
   }

   errno = E_INTERNAL;
   return EXIT_FAILURE;
}

int DrTreeNode::Update(const hosts_record_t &rec)
{
   if ( l_ptr != NULL )
      CALL_CHECK(l_ptr->Update(rec));

   if ( r_ptr != NULL )
      CALL_CHECK(r_ptr->Update(rec));

   if ( type == TYPE_ITEM ) {
      switch ( data ) {
      case TOKEN_FLOWS:
         SET_DATA(flows);
      break;

      case TOKEN_PACKETS:
         SET_DATA(packets);
      break;

      case TOKEN_BYTES:
         SET_DATA(bytes);
      break;

      case TOKEN_SYN:
         SET_DATA(syn_cnt);
      break;
      case TOKEN_ACK:
         SET_DATA(ack_cnt);
      break;

      case TOKEN_FIN:
         SET_DATA(fin_cnt);
      break;

      case TOKEN_RST:
         SET_DATA(rst_cnt);
      break;

      case TOKEN_PSH:
         SET_DATA(psh_cnt);
      break;

      case TOKEN_URG:
         SET_DATA(urg_cnt);
      break;

      default:
         errno = E_INTERNAL;
         return EXIT_FAILURE;
      }

      type = TYPE_NUM;
   }
   return EXIT_SUCCESS;
}

// S y n a n ************************************************
// P R O T E C T E D ****************************************

int Synan::stat()
{
   printf("stat START\n");
   lex->get_token();

   // <stat> -> ( <stat>
   LBRACKET_CHECK(stat());

   // <stat> -> <dir> ...
   DIR_CHECK;

   // <stat> -> <item> <op> <stat2>
   printf("Calling item()\n");
   CALL_CHECK(item());
   printf("Calling item() -- NP\n");

   lex->get_token();

   printf("Calling op()\n");
   CALL_CHECK(op());
   printf("Calling op() -- NP\n");

   lex->get_token();
   printf("stat END\n");
   return stat2();
}

int Synan::stat2()
{
   printf("stat2 START\n");
   // <stat2> -> ( <stat2>
   LBRACKET_CHECK(stat2());

   // <stat2> -> ) ...
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   if ( lex->last_rc == TOKEN_RBRACKET ) {
      printf("TOKEN recognized as a right bracket\n");
      if ( pars > 0 ) {
         pars--;
         if ( tree->RemovePar() == EXIT_FAILURE ) {
            errno = E_INTERNAL;
            return EXIT_FAILURE;
         }
      }
      else {
         errno = E_PARENTHESES;
         return EXIT_FAILURE;
      }

      // <stat2> -> ) EOF
      EOF_CHECK;

      // <stat2> -> ) <log-op> <stat2>
      // <stat2> -> ) <op> <stat2>
      OP_CHECK;
   }

   // <stat2> -> number ...
   else if ( lex->last_rc == TOKEN_NUMBER ) {
      printf("TOKEN recognized as a number\n");
      if ( current->IsFull() ) {
         errno = E_INTERNAL;
         return EXIT_FAILURE;
      }

      else {
         DrTreeNode *tmp = new DrTreeNode;
         if ( lex->last_token.find("e") != string::npos || lex->last_token.find(".") != string::npos ) {
            double number = strtod(lex->last_token.c_str(), NULL);
            tmp->data = number;
         }
         else {
            int number = strtol(lex->last_token.c_str(), '\0', DECIMAL_BASE);
            tmp->data = number;
         }
         tmp->type = TYPE_NUM;
         *(current->active) = tmp;
         current->MoveActive();
      }

      lex->get_token();

      // <stat2> -> number EOF
      EOF_CHECK;

      //<stat2> -> number <log-op> <stat3>
      //<stat2> -> number <op> <stat2>
      OP_CHECK;
   }

   // <stat2> -> <dir> ...
   DIR_CHECK;

   // <stat2> -> <item> ...
   printf("Calling item()\n");
   CALL_CHECK(item());
   printf("Calling item() -- NP\n");

   lex->get_token();

   // <stat2> -> <item> EOF
   EOF_CHECK;

   //<stat2> -> <item> <log-op> <stat3>
   //<stat2> -> <item> <op> <stat2>
   OP_CHECK;
}

int Synan::stat3()
{
    printf("stat3 START\n");
   // <stat3> -> ( <stat2>
   LBRACKET_CHECK(stat2());

   // <stat3> -> <dir> ...
   DIR_CHECK;

   // <stat3> -> <item> <op> <stat2>
   if ( item() == EXIT_SUCCESS ) {
      lex->get_token();
      printf("Calling op()\n");
      CALL_CHECK(op());
      printf("Calling op() -- NP\n");

      lex->get_token();
      printf("stat3 END\n");
      return stat2();
   }
   else {
      if ( errno == E_FIRST_LVL )
         errno = E_OK;
      else
         return EXIT_FAILURE;
   }

   // <stat3> -> <links> ...
   printf("Calling links()\n");
   CALL_CHECK(links());
   printf("Calling links() -- NP\n");

   // <stat3> -> <links> EOF
   lex->get_token();
   EOF_CHECK;

   // <stat3> -> <links> <log-op> <stat3>
   printf("Calling log_op()\n");
   CALL_CHECK(log_op());
   printf("Calling log_op() -- NP\n");

   printf("stat3 END\n");
   return stat3();
}

int Synan::dir()
{
   printf("dir START\n");
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   if ( lex->last_rc == TOKEN_IN ) {
      printf("TOKEN recognized as a direction IN\n");
      mode = MODE_IN;
      printf("dir END\n");
      return EXIT_SUCCESS;
   }
   else if ( lex->last_rc == TOKEN_OUT ) {
      printf("TOKEN recognized as a direction OUT");
      mode = MODE_OUT;
      printf("dir END\n");
      return EXIT_SUCCESS;
   }

   errno = E_FIRST_LVL;
   return EXIT_FAILURE;
}

int Synan::item()
{
   printf("item START\n");
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   switch ( lex->last_rc ) {
   case TOKEN_FLOWS:
   case TOKEN_PACKETS:
   case TOKEN_BYTES:
   case TOKEN_SYN:
   case TOKEN_ACK:
   case TOKEN_FIN:
   case TOKEN_RST:
   case TOKEN_PSH:
   case TOKEN_URG:
      printf("TOKEN recognized as on of the keywords FLOWS/PACKETS/BYTES/SYN/ACK/FIN/RST/PSH/URG\n");
      if ( current->IsFull() ) {
         errno = E_INTERNAL;
         return EXIT_FAILURE;
      }

      else {
         DrTreeNode *tmp = new DrTreeNode;
         tmp->type = TYPE_ITEM;
         tmp->data = lex->last_rc;
         tmp->mode = mode;
         *(current->active) = tmp;
         current->MoveActive();
         mode = MODE_BOTH; // internal mode reset, tree has already has the right value
      }
   break;

   default:
      errno = E_FIRST_LVL;
      return EXIT_FAILURE;
   }

   printf("item END\n");
   return EXIT_SUCCESS;
}

int Synan::op()
{
   printf("op START\n");
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   switch ( lex->last_rc ) {
   case TOKEN_BIGGER:
   case TOKEN_SMALLER:
   case TOKEN_EQUAL:
   case TOKEN_UNEQUAL:
   case TOKEN_BEQUAL:
   case TOKEN_SMEQUAL:
   case TOKEN_PLUS:
   case TOKEN_MINUS:
   case TOKEN_STAR:
   case TOKEN_SLASH:
      printf("TOKEN recognized as one of the operators >,<,=,!=,>=,<=,+,-,*,/\n");
      PLACE_OP;
   break;

   default:
      errno = E_FIRST_LVL;
      return EXIT_FAILURE;
   }

   printf("op END\n");
   return EXIT_SUCCESS;
}

int Synan::log_op()
{
   printf("log_op START\n");
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   switch ( lex->last_rc ) {
   case TOKEN_AND:
   case TOKEN_OR:
   case TOKEN_NOT:
      printf("TOKEN recognized as one of the operators AND/OR/NOT\n");
      PLACE_OP;
   break;

   default:
      errno = E_FIRST_LVL;
      return EXIT_FAILURE;
   }

   printf("log_op END\n");
   return EXIT_SUCCESS;
}

// TODO
int Synan::links()
{
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   if ( lex->last_rc == TOKEN_LINKS || lex->last_rc == TOKEN_NOT ) {
      printf("TOKEN recognized as one of the keywords LINKS/NOT\n");
      if ( lex->get_token() == TOKEN_IN ) {
         if ( lex->get_token() == TOKEN_LSBRACKET ) {
            lex->get_token();
            printf("Calling link_item()\n");
            CALL_CHECK(link_item());
            printf("Calling link_item() -- NP\n");

            lex->get_token();
            return link_list();
         }
      }

      errno = E_SYNTACTIC_ERROR;
      return EXIT_FAILURE;
   }

   else {
      errno = E_FIRST_LVL;
      return EXIT_FAILURE;
   }
}

int Synan::link_list()
{
   printf("TOKEN: \"%s\"\n", lex->last_token.c_str());
   if ( lex->last_rc == TOKEN_RSBRACKET ) {
      printf("TOKEN recognized as a right square bracket\n");
      return EXIT_SUCCESS;
   }

   else if ( lex->last_rc == TOKEN_COMMA ) {
      printf("TOKEN recognized as a comma\n");
      lex->get_token();
      printf("Calling link_item()\n");
      CALL_CHECK(link_item());
      printf("Calling link_item() -- NP\n");

      lex->get_token();
      return link_list();
   }

   return EXIT_FAILURE;
}

int Synan::link_item()
{
   return EXIT_FAILURE;
}

// S y n a n ************************************************
// P U B L I C **********************************************

int Synan::Execute(const stat_map_t &in_stat_map, vector<pair<hosts_key_t, hosts_record_t> > &out_stat_map)
{
   CALL_CHECK(stat());
   tree->Optimize();

   DrTreeNode *tmp = new DrTreeNode;
   out_stat_map.clear();

   int i = 0;
   for ( stat_map_citer it = in_stat_map.begin(); it != in_stat_map.end(); it++ ) {
      tree->Copy(tmp);
      tmp->Update(it->second);
      tmp->Resolve();
      if ( tmp->data ) {
         out_stat_map.push_back(make_pair(it->first, it->second));
      if (i > 10)
         break;
      else
         i++;
      }
   }

   //delete tmp;
   return EXIT_SUCCESS;
}
