/*!
 * \file tunnel_detection_dns.h
 * \brief Modul that detects DNS tunnels.
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

#ifndef _TUNNEL_DETECTION_DNS_
#define _TUNNEL_DETECTION_DNS_

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "prefix_tree.h"
#include "parser_pcap_dns.h"
#include "b_plus_tree.h"
#include "tunnel_detection_dns_structs.h"


/*!
 * \name Default values
 *  Defines macros used by DNS tunel detection 
 * \{ */
#define TIME_OF_ONE_SESSION 60  /*< Time of scaning the network before any decision */
#define MAX_COUNT_OF_ROUND_IN_SUSPICTION 3 /*< Maximum round to be IP in suspiction */
#define PERCENT_OF_COMMUNICATION_TO_BE_SUSPISION 0.3 /*< Percent of communication to be set to suspision state */

#define FILE_NAME_FOUND_ANOMALY "founded_anomaly.txt" /*< Name of file with fouded anomaly described */
#define FILE_NAME_SUMMARY_REQUESTS "summary_requests.dat" /*< Name of file with summary requests. */
#define TITLE_SUMMARY_REQUESTS "DNS requests histogram of communication" /*< Title of data for DNS summary requests. */
#define FILE_NAME_SUMMARY_RESPONSES "summary_responses.dat" /*< Name of file with SUMMARY responses. */
#define TITLE_SUMMARY_RESPONSES "DNS responses histogram of communication" /*< Title of data for DNS summary responses. */
#define FILE_NAME_REQUEST_COUNT_LETTERS "request_letters_count.dat" /*< Name of file with count of letters. */
#define TITLE_REQUEST_COUNT_LETTERS "Count of letters per ip" /*< Title of data for DNS summary responses. */
#define FILE_NAME_REQUESTS "requests.dat" /*< Name of file with requests. */
#define TITLE_REQUESTS "DNS requests histogram of communication devided by IP" /*< Title of data for DNS requests devided by IP. */ 
#define FILE_NAME_RESPONSES "responses.dat" /*< Name of file with responses. */
#define TITLE_RESPONSES "DNS responses histogram of communication devided by IP" /*< Title of data for DNS responses devided by IP. */ 
#define FILE_NAME_SUSPISION_LIST "suspision_list.txt"/*< Name of file with suspisions. */
#define TITLE_SUSPISION_LIST "IP in SUSPISION STATE"/*< Title of suspision list. */ 
#define SAVE_DIRECTORY "log" /*< Name of file with SUMMARY responses. */


#define EX_REQUEST_MAX 100 /*< Maximal value of request middle value */
#define EX_REQUEST_MIN 70 /*< Minimal value of request middle value */
#define EX_RESPONSE_MAX 600 /*< Maximal value of response middle value */
#define EX_RESPONSE_MIN 70 /*< Minimal value of response middle value */
#define VAR_REQUEST_MAX 150 /*< Maximal value of request var */
#define VAR_REQUEST_MIN 30 /*< Minimal value of request var*/
#define VAR_RESPONSE_MAX 50000 /*< Maximal value of response var */
#define VAR_RESPONSE_MIN 200 /*< Minimal value of response var*/
#define KURTOSIS_REQUEST_MIN 0 /*< Maximal value of request var */
#define MIN_DNS_REQUEST_COUNT 200 /*< Minimal value of dns count of packets */
#define MIN_DNS_REQUEST_COUNT_TUNNEL 50 /*< Minimal value of dns count in payload analysis for tunnel */
#define MIN_DNS_REQUEST_COUNT_OTHER_ANOMALY 200 /*< Minimal value of dns count in payload analysis for other anomaly */
#define MIN_DNS_RESPONSE_COUNT_TUNNEL 50 /*< Minimal value of dns count in payload analysis for tunnel */
#define MIN_DNS_RESPONSE_COUNT_OTHER_ANOMALY 200 /*< Minimal value of dns count of packets */
#define REQUEST_MAX_COUNT_OF_USED_LETTERS 24  /*< Maximum number of used leeters for domain */
#define RESPONSE_MAX_COUNT_OF_USED_LETTERS 30  /*< Maximum number of used leeters for domain */
#define MAX_PERCENT_OF_NEW_SUBDOMAINS 0.7 /*< Maximum percent of new subdomain, more than this can be tunel */
#define MIN_PERCENT_OF_NEW_SUBDOMAINS 0.2 /*< Minimum percent of new subdomain, less than this can be anomaly */
#define MIN_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE 0.2 /*< Minimum percent of searching unique domains, less than that can be anomaly */
#define MAX_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE 0.7 /*< Maximum percent of searching unique domains, more than that can be tunnel */
#define MIN_PERCENT_OF_UNIQUE_DOMAINS 0.2 /*< Minimum percent unique domains, less than that can be anomaly */
#define MAX_PERCENT_OF_UNIQUE_DOMAINS 0.8 /*< Maximum percent of searching unique domains, more than that can be tunne l*/
#define MAX_PERCENT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER 0.2 /*< Maximum percent of numbers in domain, more than that can be tunnel */
#define MAX_PERCENT_OF_MALLFORMED_PACKET_REQUEST 0.3 /*< Maximum percent of mallformed packet in requests */
#define MAX_COUNT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER 12 /*< Maximum count of numbers in domain, more than that can be tunnel */
#define REQUEST_PART_TUNNEL         0b00000001 /*< Define request part for suspision */
#define REQUEST_PART_OTHER          0b00000010 /*< Define request part for suspision */
#define RESPONSE_PART_TUNNEL        0b00000100 /*< Define request part for suspision */
#define RESPONSE_PART_OTHER         0b00001000 /*< Define request part for suspision */

#define REQUEST_AND_RESPONSE_PART   0b00001111 /*< Define request and response part for suspision*/
/* /} */


/*!
 * \brief Signal function.
 * Function to catch signal termination or interrupt and set the global variable.
 * \param[in] signal Number of signal which have been caught.
 */
void signal_handler(int signal);

/*!
 * \brief Create item of a list
 * Function which creates item of a list. Add next possitin from parameter.
 * \param[in] ip address to save.
 * \param[in] next pointer to next item
 * \return new item of a list 
 */
ip_address_t * crete_new_ip_address_struc( uint64_t * ip, ip_address_t * next);

/*!
 * \brief Find IP address in list
 * It is recursive function which finds IP address in given list. When it doesn't find 
 * ip, it will return NULL.
 * \param[in] ip address to search.
 * \param[in] struc pointer to list.
 * \return struc of item. Null if address is not found
 */
ip_address_t * find_ip(uint64_t * search_ip, ip_address_t * struc);

/*!
 * \brief Update counters function
 * When packet on port 53 came, function saves to histogram information about address and size
 * of packet.
 * \param[in] listOfIp poinet to list.
 * \param[in] ip_in_packet pointer to ip address to save information about.
 * \param[in] size of packet.
 * \param[in] request, if it is 1, then it is request, if it is 0, then response. 
 * \return address to updated list.
 */
ip_address_t * add_to_list( ip_address_t * list_of_ip, uint64_t * ip_in_packet, int size, char request);

/*!
 * \brief Clean function
 * It will free alocated structure of list.
 * \param[in] list pointer to list.
 */
void free_ip_list(ip_address_t * list);

/*!
 * \brief Write summary function
 * It will write summary information of DNS communication to a file.
 * It is histogram of DNS requests and responses of all IPs
 * \param[in] histogram_dns_requests pointer to array of a histogram with requests.
 * \param[in] histogram_dns_response pointer to array of a histogram with responses.
 */
void write_summary_result(char * record_folder, unsigned long * histogram_dns_requests, unsigned long * histogram_dns_response);

/*!
 * \brief Write detail results function
 * It will write details of DNS communication to a file.
 * It is histogram of DNS requests and responses of each ip address separately.
 * \param[in] list_of_ip pointer list of ip histogram structure.
 */
void write_detail_result(char * record_folder_name, void ** b_plus_tree, int count_of_btree);




void calculate_character_statistic(char * string, character_statistic_t * stat);

void print_suspision_ip(char *ip_address, ip_address_t *ip_item, FILE *file);

void print_founded_anomaly(char * ip_address, ip_address_t *item, FILE *file);

/*!
 * \brief Main function.
 * Main function to parse given arguments and run the DNS tunnel detection.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
//int main(int argc, char **argv);

 #endif /* _TUNNEL_DETECTION_DNS_ */
