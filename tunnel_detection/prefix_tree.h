#ifndef _PREFIX_TREE_
#define _PREFIX_TREE_



#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "tunnel_detection_dns_structs.h"



int map_chatecter_to_number(char  letter);

prefix_tree_t * inicialize_prefix_tree();

void destroy_prefix_tree_recursive(prefix_tree_inner_node_t *  node);

void destroy_prefix_tree(prefix_tree_t * tree);

prefix_tree_domain_t * add_exception_prefix_tree(char * string, char * begin);

void recursive_plus_domain(prefix_tree_domain_t * domain_parent, prefix_tree_t * tree);

prefix_tree_domain_t * new_domain(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, prefix_tree_t * tree);

prefix_tree_inner_node_t * new_node(prefix_tree_inner_node_t * parent, int map_number);

prefix_tree_inner_node_t * add_children_array(prefix_tree_inner_node_t * parent);

prefix_tree_inner_node_t * new_node_parent_is_domain(prefix_tree_domain_t * domain);

int count_to_dot(char * string, int length);

prefix_tree_domain_t * add_new_item(prefix_tree_inner_node_t * node ,prefix_tree_domain_t * domain , char * string, int length, prefix_tree_t * tree);

prefix_tree_inner_node_t * merge_node_into_two(prefix_tree_inner_node_t * node, int index);

char * read_doamin(prefix_tree_domain_t * domain, char * string);

prefix_tree_domain_t * add_to_prefix_tree_recursive(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, char * string, int length, prefix_tree_t * tree);

prefix_tree_domain_t * add_to_prefix_tree(prefix_tree_t * tree, char * string, int length,  character_statistic_t * char_stat);







 #endif /* _PREFIX_TREE_ */
