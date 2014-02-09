/*!
 * \file tunnel_detection_dns_structs.h
 * \brief Modul that detects DNS tunnels.
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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

#ifndef _TUNNEL_DETECTION_DNS_STRUCTS_
#define _TUNNEL_DETECTION_DNS_STRUCTS_




typedef struct character_statistic_t character_statistic_t ;
 struct character_statistic_t {
    unsigned int count_of_different_letters;
    unsigned int count_of_numbers_in_string;
    unsigned int length;
} ;

//********* prefix tree *********
#define COUNT_OF_LETTERS_IN_DOMAIN 68
#define MAX_SIZE_OF_DOMAIN 256
#define MAX_SIZE_OF_DEEGRE 5
#define ADD_TO_LIST_FROM_COUNT_OF_SEARCH 20
#define ADD_TO_LIST_FROM_COUNT_OF_DIFFERENT_SUBDOMAINS 10
#define MAX_COUNT_TO_BE_IN_JUST_ONE_SEARCHER 10

 typedef struct prefix_tree_domain_t prefix_tree_domain_t ;

 typedef struct prefix_tree_inner_node_t prefix_tree_inner_node_t ;
 struct prefix_tree_inner_node_t {
	unsigned char length;
	char * string;
	prefix_tree_inner_node_t * parent;
	prefix_tree_domain_t * parent_is_domain;
	prefix_tree_inner_node_t ** child;
	prefix_tree_domain_t * domain;
} ;


 struct prefix_tree_domain_t {
 	unsigned char deegree;
	unsigned int count_of_search;
	unsigned int count_of_different_subdomains;
	unsigned char count_of_different_letters;
    character_statistic_t * char_stat;
	prefix_tree_inner_node_t * parent;
	prefix_tree_domain_t * parent_domain;
	prefix_tree_inner_node_t *child;

	prefix_tree_domain_t * most_used_domain_less;
	prefix_tree_domain_t * most_used_domain_more;
	prefix_tree_domain_t * most_subdomains_less;
	prefix_tree_domain_t * most_subdomains_more;

} ;

typedef struct prefix_tree_t prefix_tree_t ;
 struct prefix_tree_t {
	prefix_tree_inner_node_t * root;
	unsigned int count_of_domain_searched_just_ones;
	unsigned int count_of_searching;
    unsigned int count_of_searching_for_just_ones;
	unsigned int count_of_different_domains;
	prefix_tree_domain_t * list_of_most_used_domains;
	prefix_tree_domain_t * list_of_most_used_domains_end;
	prefix_tree_domain_t * list_of_most_unused_domains;
	prefix_tree_domain_t ** list_of_most_subdomains;
	prefix_tree_domain_t ** list_of_most_subdomains_end;

} ;


//********* ip address record *********

/*!
 * \name Default values
 *  Defines macros used by DNS tunel detection 
 * \{ */

#define HISTOGRAM_SIZE_REQUESTS 30 /*< Default number of client intefaces. */
#define HISTOGRAM_SIZE_RESPONSE 150 /*< Default number of client intefaces. */

#define STATE_NEW 0
#define STATE_OK 1
#define STATE_SUSPISION 2
#define STATE_TUNNEL 3
#define STATE_OTHER_ANOMALY 4
#define STATE_TUNNEL_AND_OTHER_ANOMALY 5



 typedef struct ip_address_suspision_t ip_address_suspision_t ;
 struct ip_address_suspision_t {
    unsigned char  state_request_size [HISTOGRAM_SIZE_REQUESTS]; /*!< state, which prefix tree should be used */
    prefix_tree_t * tunnel_suspision;
    prefix_tree_t * other_suspision;
 } ;


/*!
 * \brief Structure containing inforamtion about each IP adress
 * Structure used to keep information about each Ip address.
 * histogram of size of packets.
 * It is a list of IP.
 */
 typedef struct ip_address_t ip_address_t ;
 struct ip_address_t {
	uint32_t ip;
   	unsigned long histogram_dns_requests [HISTOGRAM_SIZE_REQUESTS]; /*!< histogram values, requests */
   	unsigned long histogram_dns_response [HISTOGRAM_SIZE_RESPONSE]; /*!< histogram values, responses */
    unsigned long histogram_dns_request_sum_for_cout_of_used_letter [HISTOGRAM_SIZE_REQUESTS]; /*!< histogram values, requests */
    unsigned long histogram_dns_request_ex_sum_of_used_letter [HISTOGRAM_SIZE_REQUESTS]; /*!< histogram values, ex of new letters, for size. 
                                                                                            At first it is sum, but on the end it has to be devided
                                                                                            by count of requests */
    ip_address_suspision_t * suspision;
   	unsigned long dns_response_count; /*!< count of responses */
    unsigned long dns_request_count; /*!< count of requests */
    unsigned long dns_request_string_count; /*!< count of requests string */
    unsigned long sum_Xi_response; /*!< Sum of sizes respone */
    unsigned long sum_Xi_request; /*!< Sum of sizes request */
    unsigned long sum_Xi2_response; /*!< Sum of sizes^2 respone */
    unsigned long sum_Xi2_request; /*!< Sum of sizes^2 request */
    unsigned long sum_Xi3_response; /*!< Sum of sizes^3 respone */
    unsigned long sum_Xi3_request; /*!< Sum of sizes^3 request */
    unsigned long sum_Xi4_response; /*!< Sum of sizes^4 respone */
    unsigned long sum_Xi4_request; /*!< Sum of sizes^4 request */
    float ex_response; /*!< middle value respone */
    float ex_request; /*!< middle value respone */
    float ex_request_count_of_different_letters; /*!< middle value of count letters */
    float var_response; /*!< diffusion respone */
    float var_request; /*!< diffusion request */
    float var_request_count_letters; /*!< middle value of count letters */
    float skewness_request; /*!< skewness request */
    float skewness_response; /*!< skewness response */
    float kurtosis_request; /*!< kurtosis request */
    float kurtosis_response; /*!< kurtosis response */
    unsigned char state; /*!< state of finding tunnel*/
    unsigned char round_in_suspiction; /*!< number of round which Ip is in suspiction */
   	ip_address_t * next; /*!< pointer to next value */
   	void * paret_in_b_plus_tree; /*!< parent value in b_plus tree */
} ;

typedef struct calulated_result_t calulated_result_t ;
 struct calulated_result_t {
    unsigned long histogram_dns_request_ex_cout_of_used_letter [HISTOGRAM_SIZE_REQUESTS]; /*!< histogram values, ex of new letters, for size. 
                                                                                            At first it is sum, but on the end it has to be devided
                                                                                            by count of requests */
    float ex_response; /*!< middle value respone */
    float ex_request; /*!< middle value respone */
    float ex_request_count_of_different_letters; /*!< middle value of count letters */
    float var_response; /*!< diffusion respone */
    float var_request; /*!< diffusion request */
    float var_request_count_letters; /*!< middle value of count letters */
    float skewness_request; /*!< skewness request */
    float skewness_response; /*!< skewness response */
    float kurtosis_request; /*!< kurtosis request */
    float kurtosis_response; /*!< kurtosis response */
} ;




#endif /* _TUNNEL_DETECTION_DNS_STRUCTS_ */