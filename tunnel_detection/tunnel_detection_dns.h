/*!
 * \file tunnel_detection_dns.h
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

/*!
 * \name Default values
 *  Defines macros used by DNS tunel detection 
 * \{ */
#define HISTOGRAM_SIZE_REQUESTS 30 /*< Default number of client intefaces. */
#define HISTOGRAM_SIZE_RESPONSE 150 /*< Default number of client intefaces. */
#define FILE_NAME_SUMMARY_REQUESTS "summary_requests.dat" /*< Name of file with summary requests. */
#define TITLE_SUMMARY_REQUESTS "DNS requests histogram of communication" /*< Title of data for DNS summary requests. */
#define FILE_NAME_SUMMARY_RESPONSES "summary_responses.dat" /*< Name of file with SUMMARY responses. */
#define TITLE_SUMMARY_RESPONSES "DNS responses histogram of communication" /*< Title of data for DNS summary responses. */
#define FILE_NAME_REQUESTS "requests.dat" /*< Name of file with requests. */
#define TITLE_REQUESTS "DNS requests histogram of communication devided by IP" /*< Title of data for DNS requests devided by IP. */ 
#define FILE_NAME_RESPONSES "responses.dat" /*< Name of file with responses. */
#define TITLE_RESPONSES "DNS responses histogram of communication devided by IP" /*< Title of data for DNS responses devided by IP. */ 
#define SAVE_DIRECTORY "log" /*< Name of file with SUMMARY responses. */

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
   	ip_address_t * next; /*!< pointer to next value */
} ;

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
ip_address_t * crete_new_ip_address_struc( uint32_t * ip, ip_address_t * next);

/*!
 * \brief Find IP address in list
 * It is recursive function which finds IP address in given list. When it doesn't find 
 * ip, it will return NULL.
 * \param[in] ip address to search.
 * \param[in] struc pointer to list.
 * \return struc of item. Null if address is not found
 */
ip_address_t * find_ip(uint32_t * search_ip, ip_address_t * struc);

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
ip_address_t * add_to_list( ip_address_t * listOfIp, uint32_t * ip_in_packet, int size, char request);

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
void write_detail_result(char * record_folder, ip_address_t * list_of_ip);

/*!
 * \brief Main function.
 * Main function to parse given arguments and run the DNS tunnel detection.
 * \param[in] argc Number of given parameters.
 * \param[in] argv Array of given parameters.
 * \return EXIT_SUCCESS on success, otherwise EXIT_FAILURE.
 */
int main(int argc, char **argv);

 #endif /* _TUNNEL_DETECTION_DNS_ */
