/*
<stat> -> ( <stat>
<stat> -> <dir> <item> <op> <stat2>
<stat> -> <item> <op> <stat2>

<stat2> -> ( <stat2>
<stat2> -> ) EOF
<stat2> -> ) <log-op> <stat3>
<stat2> -> ) <op> <stat2>
<stat2> -> number EOF
<stat2> -> number <log-op> <stat3>
<stat2> -> number <op> <stat2>
<stat2> -> <dir> <item> EOF
<stat2> -> <dir> <item> <log-op> <stat3>
<stat2> -> <dir> <item> <op> <stat2>
<stat2> -> <item> EOF
<stat2> -> <item> <log-op> <stat3>
<stat2> -> <item> <op> <stat2>

<stat3> -> ( <stat2>
<stat3> -> <dir> <item> <op> <stat2>
<stat3> -> <item> <op> <stat2>
<stat3> -> <links> <log-op> <stat3>
<stat3> -> <links> EOF

<dir> -> in|out

<item> -> bytes|packets|flows|syn|fin|rst|psh|urg|ack

<op> -> >
<op> -> <
<op> -> =
<op> -> !=
<op> -> >=
<op> -> <=
<op> -> +
<op> -> -
<op> -> *
<op> -> /

<log-op> -> and
<log-op> -> or
<log-op> -> not

<links> -> links in [ <link-item> <link-list>
<links> -> not in [ <link-item> <link-list>

<link-list> -> ]
<link-list> -> , <link-item> <link-list>

<link-item> -> aconet|amsix|geant|nix2|nix3|pioneer|sanet|telia|telia2
*/

#ifndef SYNAN_H
#define SYNAN_H

#include "lexan.h"

#ifdef STREAM_VERSION
#include "stream_version/hoststats.h"
#else
#include "timeslot_version/hoststats.h"
#endif

enum errors {
   E_OK,
   E_FIRST_LVL,
   E_PARENTHESES,
   E_SYNTACTIC_ERROR,
   E_INTERNAL
};

enum dr_tree_types {
   TYPE_EMPTY,
   TYPE_NUM,
   TYPE_ITEM,
   TYPE_OP
};

enum modes {
   MODE_BOTH,
   MODE_IN,
   MODE_OUT
};

// Priority of operators
extern int ops_map[];

class DrTreeNode {
protected:
   bool full;

public:
   bool par_break;

   int type;
   int mode;
   int data;

   DrTreeNode *l_ptr;
   DrTreeNode *r_ptr;

   DrTreeNode *root;
   DrTreeNode **active;

   DrTreeNode() {
      full = false;
      par_break = false;
      type = TYPE_EMPTY;
      mode = MODE_BOTH;
      root = NULL;
      l_ptr = NULL;
      r_ptr = NULL;
      active = &l_ptr;
   };
   ~DrTreeNode() {
      Delete();
   }

   int AddNewRoot(DrTreeNode *new_root);
   int AddNewBranch(DrTreeNode *new_branch);
   int Copy(DrTreeNode *new_tree);
   void Delete();
   int Insert(DrTreeNode *node);
   bool IsFull();
   int MoveActive();
   int Optimize();
   void Print();
   int RemovePar();
   int Resolve();
   int Update(const hosts_record_t &rec);
};

class Synan {
protected:
   int pars;
   int mode;

   DrTreeNode *tree;
   DrTreeNode *current;
   Lexan *lex;

   int stat();
   int stat2();
   int stat3();
   int dir();
   int item();
   int op();
   int log_op();
   int links();
   int link_list();
   int link_item();

public:
   Synan(string request) {
      lex = new Lexan(request);
      pars = 0;
      mode = MODE_BOTH;
      tree = new DrTreeNode;
      current = tree;
   };
   ~Synan() {
      delete tree;
      delete lex;
   };

   int Execute(const stat_map_t &in_stat_map, vector<pair<hosts_key_t, hosts_record_t> > &out_stat_map);
};

#endif
