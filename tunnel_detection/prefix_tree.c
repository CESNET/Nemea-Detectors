/*!
 * \file prefix_tree.c
 * \brief Prefix tree data structure for saving informaticons about domains.
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
#include "prefix_tree.h"



int map_chatecter_to_number(char  letter){
	//numbers are on position 0 to 9 from 48 -57
	if(letter >= ' ' && letter <= '~'){
		return (letter) -' ';
	}
	/*//big letters are on position 10-34 from 65-90
	else if (letter >='A' && letter <='Z'){
		return (letter) - 'A' + 10;
	}
	//big letters are on position 35+ from 65-90
	else if (letter >='a' && letter <='z'){
		return (letter) - 'a' + 36;
	}
	else if(letter =='-'){
		return 62;
	}
	else if(letter =='>'){
		return 63;
	}
	else if(letter =='_'){
		return 64;
	}
	else if(letter ==','){
		return 65;
	}
	else if(letter ==' '){
		return 66;
	}*/
	else{
		printf("this letter canot be used in domain: %c, in dec %d\n", letter ,letter);
		return COUNT_OF_LETTERS_IN_DOMAIN-1;
	}

}

prefix_tree_t * prefix_tree_inicialize(){
	prefix_tree_t * tree;
	tree = (prefix_tree_t *) calloc(sizeof(prefix_tree_t),1);
	tree->root = (prefix_tree_inner_node_t *) calloc(sizeof(prefix_tree_inner_node_t),1);
	tree->root->domain = (prefix_tree_domain_t *) calloc(sizeof(prefix_tree_domain_t),1);
	tree->root->domain->count_of_insert=1;
	tree->list_of_most_subdomains = (prefix_tree_domain_t**) calloc(sizeof(prefix_tree_domain_t*), MAX_SIZE_OF_DEEGRE);
	tree->list_of_most_subdomains_end = (prefix_tree_domain_t**) calloc(sizeof(prefix_tree_domain_t*), MAX_SIZE_OF_DEEGRE);
	//tree->list_of_most_used_domains = tree->list_of_most_used_domains_end = tree->root->domain;
	return tree;
}



void prefix_tree_destroy_recursive(prefix_tree_inner_node_t *  node){
	//for all nodes
	if(node!=NULL){
		//for all children in node
		if(node->child != NULL){
			int i;
			for(i=0; i<COUNT_OF_LETTERS_IN_DOMAIN;i++){
				if(node->child[i] != NULL){
					prefix_tree_destroy_recursive(node->child[i]);
				}
			}
			free(node->child);
		}
		//for domain and domain's child
		if(node->domain != NULL){
			if(node->domain->child != NULL){
				prefix_tree_destroy_recursive(node->domain->child);
			}
			free(node->domain);
		}
		//node string
		if(node->string != NULL){
			free(node->string);
		}	
		free(node);
	}
}

void prefix_tree_destroy(prefix_tree_t * tree){
	prefix_tree_destroy_recursive(tree->root);
	free(tree->list_of_most_subdomains);
	free(tree->list_of_most_subdomains_end);
	free(tree);
}







void recursive_plus_domain(prefix_tree_domain_t * domain_parent, prefix_tree_t * tree){
	while(domain_parent !=NULL){
		int index;
		//+1 to subdomain
		domain_parent->count_of_different_subdomains++;
		

		
		index = domain_parent->deegree;
		if(index >= MAX_SIZE_OF_DEEGRE){
			index=MAX_SIZE_OF_DEEGRE-1;
		}
		//add or sort in list count_of_insert
		if(domain_parent->count_of_different_subdomains > ADD_TO_LIST_FROM_COUNT_OF_DIFFERENT_SUBDOMAINS){
			//on the begeing set the best, and the worse
			if(tree->list_of_most_subdomains[index] == NULL && tree->list_of_most_subdomains_end[index] == NULL ){
				tree->list_of_most_subdomains[index] = domain_parent;
				tree->list_of_most_subdomains_end[index] = domain_parent;
			}
			else{
				//new domain in tree, set it to the end of the list
				if (domain_parent->most_subdomains_more  == NULL && domain_parent->most_subdomains_less  == NULL){
					if(tree->list_of_most_subdomains_end[index] != domain_parent){
						tree->list_of_most_subdomains_end[index]->most_subdomains_less = domain_parent;
						domain_parent->most_subdomains_more = tree->list_of_most_subdomains_end[index];
						tree->list_of_most_subdomains_end[index]=domain_parent;
					}
				}

				//if it is more used than other, than move forward
				while(domain_parent->most_subdomains_more != NULL && domain_parent->most_subdomains_more->count_of_different_subdomains < domain_parent->count_of_different_subdomains ){
					//printf("posun\n");
					prefix_tree_domain_t * help;
					help = domain_parent->most_subdomains_more;
					domain_parent->most_subdomains_more = help->most_subdomains_more;
					help->most_subdomains_less = domain_parent->most_subdomains_less;
					help->most_subdomains_more = domain_parent;
					domain_parent->most_subdomains_less = help;
					if(domain_parent->most_subdomains_more != NULL){
						domain_parent->most_subdomains_more->most_subdomains_less = domain_parent;
					}
					else{
						//on the top
						tree->list_of_most_subdomains[index] = domain_parent;
					}

					if(help->most_subdomains_less != NULL){
						help->most_subdomains_less->most_subdomains_more = help;
					}
					if(help->most_subdomains_less == NULL)
						tree->list_of_most_subdomains_end[index] = help;
				}


			}
		}
		//move to next item
		domain_parent = domain_parent->parent_domain;

	}
}

prefix_tree_domain_t * new_domain(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, prefix_tree_t * tree){
	node->domain = (prefix_tree_domain_t*) calloc(sizeof(prefix_tree_domain_t),1);
	node->domain->parent_domain = domain_parent;
	node->domain->parent = node;
	if(domain_parent){
		node->domain->deegree = domain_parent->deegree+1;
	}
	//plus new domain
	recursive_plus_domain(domain_parent, tree);
	return node->domain;	
}

prefix_tree_inner_node_t * new_node(prefix_tree_inner_node_t * parent, int map_number){
	parent->child[map_number] = (prefix_tree_inner_node_t*) calloc(sizeof(prefix_tree_inner_node_t),1);
	parent->child[map_number]->parent = parent;	
	return parent->child[map_number];
}

prefix_tree_inner_node_t * add_children_array(prefix_tree_inner_node_t * parent){
	parent->child = (prefix_tree_inner_node_t **) calloc(sizeof(prefix_tree_inner_node_t*),COUNT_OF_LETTERS_IN_DOMAIN);
	return parent;
}

prefix_tree_inner_node_t * new_node_parent_is_domain(prefix_tree_domain_t * domain){
	domain->child = (prefix_tree_inner_node_t*) calloc(sizeof(prefix_tree_inner_node_t),1);
	domain->child->parent_is_domain = domain;
	add_children_array(domain->child);
	return domain->child;
}

int count_to_dot(char * string, int length){
	int i;
	for(i=length-1; i >=0 ; i-- ){
		if(string[i] == '.'){
			return length - i - 1;
		}
	}
	return length;
}

//just because of dependece
prefix_tree_domain_t * prefix_tree_add_domain_recursive(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, char * string, int length, prefix_tree_t * tree);

prefix_tree_domain_t * add_new_item(prefix_tree_inner_node_t * node ,prefix_tree_domain_t * domain , char * string, int length, prefix_tree_t * tree){
	int count, i;
	count = count_to_dot(string,length);
	node->string = (char*) calloc(sizeof(char),count);
	//copy invert
	for(i=0; i<count;i++){
		node->string[i] = string[length-i-1];
	}
	node->length = count;
	new_domain(node, domain, tree);
	if(length > count){
		return prefix_tree_add_domain_recursive(new_node_parent_is_domain(node->domain), node->domain, string, length - count - 1, tree);
	}

	return node->domain;
}

prefix_tree_inner_node_t * split_node_into_two(prefix_tree_inner_node_t * node, int index){
	prefix_tree_inner_node_t * first_node;
	char * second_string;
	int map_number;
	//first node, must be created
	first_node = new_node(node->parent, map_chatecter_to_number(*(node->string)));	
	add_children_array(first_node);
	first_node->string = (char*) calloc(sizeof(char), index);
	memcpy(first_node->string, node->string, sizeof(char) * (index));
	first_node->length = index;
	//second node must be edited
	second_string = (char*) calloc(sizeof(char), node->length - index);
	memcpy(second_string, node->string+index,sizeof(char) * (node->length - index));
	free(node->string);
	node->string = second_string;
	node->length = node->length - index;
	node->parent = first_node;
	//conect first node to second 
	first_node->child[map_chatecter_to_number(*second_string)]=node;
	return first_node;
}


char * read_doamin(prefix_tree_domain_t * domain, char * string){
	char  *pointer_to_string;
	prefix_tree_inner_node_t *node;
	int i;
	//string = (char*) calloc(sizeof(char),MAX_SIZE_OF_DOMAIN);
	pointer_to_string=string;
	node = domain->parent;
	if(node->parent==NULL){

	}
	while (domain!=NULL && domain->parent!=NULL){
		node = domain->parent;
		while(node->parent != NULL){
			for(i = node->length-1; i>=0; i--){
				*pointer_to_string = node->string[i];
				pointer_to_string++;
			}
			node = node->parent;

		}
		*pointer_to_string = '.';
		pointer_to_string++;
		domain = node->parent_is_domain;

	}
	pointer_to_string--;
	*pointer_to_string=0;
	return string;
}

prefix_tree_domain_t * prefix_tree_add_domain_recursive(prefix_tree_inner_node_t * node, prefix_tree_domain_t * domain_parent, char * string, int length, prefix_tree_t * tree){
	//read common part;
	int i, index;
	index = length-1;
	for(i=0; i < node->length; i++){
		if(index >= 0 && node->string[i] == string[index]){
			index--;
		}
		else{
			break;
		}
	}

	//common part does not exist at all
	if(i==0){
		int map_number;
		map_number = map_chatecter_to_number(string[index]);

		//new record, create new nodes
		if(node->child ==NULL){
			add_children_array(node);
		}
		if(node->child[map_number] == NULL){
			new_node(node, map_number);
			return add_new_item(node->child[map_number],domain_parent , string, length, tree); 
		}
		//link exists
		else{
			return prefix_tree_add_domain_recursive(node->child[map_number], domain_parent, string, length, tree);
		}
	}
	//common part exist but is too short
	else if(i < node->length){
		//split node into two nodes, on index where it is not common
		node = split_node_into_two(node, i);
		//domain
		if(index == -1 || string[index] == '.'){
			if(node->domain == NULL){
				new_domain(node, domain_parent, tree);
			}
			if(index <= 0){
				return (node->domain);
			}
			else{
				return prefix_tree_add_domain_recursive(new_node_parent_is_domain(node->domain), node->domain, string, index, tree);
			}
		}
		//continue with other nodes
		else{
			int map_number;
			map_number = map_chatecter_to_number(string[index]);
			if(node->child == NULL){
				add_children_array(node);
			}
			if(node->child[map_number] == NULL){
				new_node(node,map_number);
				return add_new_item(node->child[map_number],domain_parent, string, index+1, tree);
			}
			return prefix_tree_add_domain_recursive(node->child[map_number], domain_parent, string, index+1, tree);
		}
	}
	//node is fully used and it continues to other node
	else if(i == node->length){
		int map_number;
		if(index < 0 || string[index]=='.'){
			if(node->domain == NULL){
				new_domain(node, domain_parent, tree);
			}
			else if(node->domain->exception){
				return NULL;		
			}
			if(index < 0){
				return (node->domain);
			}
			else if(node->domain->child == NULL){
				return prefix_tree_add_domain_recursive(new_node_parent_is_domain(node->domain), node->domain, string, index, tree);
			}
			else{
				return prefix_tree_add_domain_recursive(node->domain->child, node->domain, string, index, tree);
			}			
		}
		
		map_number = map_chatecter_to_number(string[index]);
		if(node->child == NULL){
			add_children_array(node);
		}
		if(node->child[map_number] == NULL){
			new_node(node,map_number);
			return add_new_item(node->child[map_number],domain_parent, string, index+1, tree);
		}
		else{
			return prefix_tree_add_domain_recursive(node->child[map_number], domain_parent, string, index+1, tree);
		}
	}
	else{
		printf("error\n");
		return NULL;
	}
	
}

int prefix_tree_is_domain_in_exception(prefix_tree_t * tree, char * string, int length){
	int i, index, map_number;
	prefix_tree_inner_node_t *node;
	node = tree->root;
	index = length - 1;
	
	while(node != NULL){
			for(i=0; i < node->length; i++){
				if(index >= 0 && node->string[i] == string[index]){
					index--;
				}
				else{
					return 0;
				}
			}
			if(index < 0 || string[index]=='.'){
				if(node->domain == NULL){
					return 0;
				}
				else if(node->domain->exception == 1){
					return 1;
				}
				else if(index < 0){
					return 0;
				}
				index--;
				node = node->domain->child;	
			}
			else{
				if(node->child == NULL){
					return 0;
				}
				map_number = map_chatecter_to_number(string[index]);
				node = node->child[map_number];
			}
	}
	return 0;

}


double most_used_domain_percent_of_subdomains(prefix_tree_t * tree, int depth){
	prefix_tree_domain_t *dom;
	dom = tree->root->domain;
	if(depth >= MAX_SIZE_OF_DEEGRE)
		return 0;

	if(tree->list_of_most_subdomains[depth]!= NULL){
		return (double)tree->list_of_most_subdomains[depth]->count_of_different_subdomains / (double)tree->root->domain->count_of_different_subdomains; 
	}
	return 0;
}


prefix_tree_domain_t * prefix_tree_add_domain(prefix_tree_t * tree, char * string, int length,  character_statistic_t * char_stat){
	prefix_tree_domain_t * found, * iter;
	int index;
//*************
	if(length <=0){
		printf("zde je chyba %d\n", length );
	}
//*************		

	found = prefix_tree_add_domain_recursive(tree->root, tree->root->domain, string, length, tree);
	//exception or error
	if(found == NULL){
		return NULL;
	}
	
	found->count_of_insert++;
	tree->count_of_inserting++;
	iter=found;
	//just one search
	//Because of the speed, it is better to devide used and unused list. The unused list is not sorted, and used is sorted
	if(found->count_of_insert == 1){
		if(char_stat != NULL){
			found->count_of_different_letters = char_stat->count_of_different_letters;
		}
		tree->count_of_domain_searched_just_ones++;
		tree->count_of_different_domains++;
		tree->count_of_inserting_for_just_ones++;
		//first candidate
		if(tree->list_of_most_unused_domains == NULL ){
			tree->list_of_most_unused_domains=iter;
		}
		else{	
			iter->most_used_domain_less = tree->list_of_most_unused_domains;
			tree->list_of_most_unused_domains->most_used_domain_more = iter;
			tree->list_of_most_unused_domains=iter;
		}
	}
	else if(found->count_of_insert == MAX_COUNT_TO_BE_IN_JUST_ONE_SEARCHER){
		tree->count_of_inserting_for_just_ones += MAX_COUNT_TO_BE_IN_JUST_ONE_SEARCHER-1;
		tree->count_of_domain_searched_just_ones--;
		//delete from the most unused list
		if(iter->most_used_domain_more  != NULL){
			iter->most_used_domain_more->most_used_domain_less = iter->most_used_domain_less;
		}
		else{
			tree->list_of_most_unused_domains = iter->most_used_domain_less;
		}
		if(iter->most_used_domain_less != NULL){
			iter->most_used_domain_less->most_used_domain_more = iter->most_used_domain_more;
		}
		iter->most_used_domain_less = iter->most_used_domain_more = NULL;
	}else if(found->count_of_insert > MAX_COUNT_TO_BE_IN_JUST_ONE_SEARCHER){
		tree->count_of_inserting_for_just_ones++;
	}

	//add or sort in list count_of_insert
	if(found->count_of_insert > ADD_TO_LIST_FROM_COUNT_OF_SEARCH){
		//on the begeing set the best, and the worse
		if(tree->list_of_most_used_domains == NULL && tree->list_of_most_used_domains_end == NULL ){
			tree->list_of_most_used_domains=iter;
			tree->list_of_most_used_domains_end=iter;
		}
		else{
			//new domain in tree, set it to the end of the list
			if (iter->most_used_domain_more  == NULL && iter->most_used_domain_less  == NULL && iter != tree->list_of_most_used_domains_end){
				tree->list_of_most_used_domains_end->most_used_domain_less = iter;
				iter->most_used_domain_more = tree->list_of_most_used_domains_end;
				tree->list_of_most_used_domains_end=iter;
			}

			//if it is more used than other, than move forward
			while(iter->most_used_domain_more != NULL && iter->most_used_domain_more->count_of_insert < iter->count_of_insert ){
				//printf("posun\n");
				prefix_tree_domain_t * help;
				help = iter->most_used_domain_more;
				iter->most_used_domain_more = help->most_used_domain_more;
				help->most_used_domain_less = iter->most_used_domain_less;
				help->most_used_domain_more = iter;
				iter->most_used_domain_less = help;
				if(iter->most_used_domain_more != NULL){
					iter->most_used_domain_more->most_used_domain_less = iter;
				}
				else{
					//on the top
					tree->list_of_most_used_domains=iter;
				}

				if(help->most_used_domain_less != NULL){
					help->most_used_domain_less->most_used_domain_more = help;
				}
				if(help->most_used_domain_less == NULL)
					tree->list_of_most_used_domains_end = help;
			}


		}
	}

	//add or sort in list count_of_different_subdomains
	return found;
}



prefix_tree_domain_t * prefix_tree_add_domain_exception(prefix_tree_t * tree, char * string, int length){
	prefix_tree_domain_t * found, * iter;
	int index;
	found = prefix_tree_add_domain_recursive(tree->root, tree->root->domain, string, length, tree);
	found->exception = 1;
}