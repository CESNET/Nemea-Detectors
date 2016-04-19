/*!
 * \file tunnel_detection_dns.h
 * \brief Modul that detects DNS tunnels.
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
 * \date 2015
 */
/*
 * Copyright (C) 2015 CESNET
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
#include "parser_pcap_dns.h"
#include <b_plus_tree.h>
#include "tunnel_detection_dns_structs.h"



/*!
 * \name Default strings values
 *  Defines macros used for output.
 * \{ */
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
#define FILE_NAME_SUSPICION_LIST "suspision_list.txt"/*< Name of file with suspisions. */
#define TITLE_SUSPICION_LIST "IP in SUSPICION STATE"/*< Title of suspision list. */
#define SAVE_DIRECTORY "log" /*< Name of file with SUMMARY responses. */
#define FILE_NAME_EVENT_ID "/data/dnstunnel_detection/event_id.txt" /*< Name of file with last used event ID. */
/* /} */

/*!
 * \name SDM output setting
 *  Defines count of packets and timeout which will be set on output.
 * \{ */
#define SDM_COUNT_OF_PACKETS 1000 /*< Count of packet which will be recorded by SDM */
#define SDM_TIMEOUT 300 /*< Timeout, after that the rule will be discard from SDM */
 /* /} */
/*!
 * \name Default values
 *  Defines macros used by DNS tunel detection
 * \{ */
#define COUNT_OF_ITEM_IN_LEAF 5 /*< Count of item in leaf of B+ tree. M value of B+ tree */
#define READ_FROM_FILE 1 /*< Specify module configuration. Modul will read packets from FILE */
#define READ_FROM_UNIREC 2 /*< Specify module configuration. Modul will read packets from UNIREC */
#define MEASURE_PARAMETERS 4 /*< Specify module configuration. Modul will measure detection parameters */
#define TIME_OF_ONE_SESSION 60  /*< Time of scaning the network before any decision */
#define MAX_COUNT_OF_ROUND_IN_SUSPICTION 3 /*< Maximum count of round to be IP in suspicion */
#define MAX_COUNT_OF_ROUND_IN_ATTACK 5 /*< Maximum count of round to stay IP in ATTACK MODE without noticing anomaly */
#define PERCENT_OF_COMMUNICATION_TO_BE_SUSPICION 0.3 /*< Percent of communication to be set to suspision state */
#define MEASURE_TOLERANCE 0.1

#define DEPTH_TUNNEL_SUSPICTION 2 /*< Depth of domain to be tunnel*/
#define MAX_PERCENT_OF_SUBDOMAINS_IN_MAIN_DOMAIN 0.8 /*< Max percent of subdomains in main domain */
#define EX_REQUEST_MAX 100 /*< Maximal value of request middle value */
#define EX_REQUEST_MIN 70 /*< Minimal value of request middle value */
#define EX_RESPONSE_MAX 600 /*< Maximal value of response middle value */
#define EX_RESPONSE_MIN 70 /*< Minimal value of response middle value */
#define VAR_REQUEST_MAX 150 /*< Maximal value of request var */
#define VAR_REQUEST_MIN 30 /*< Minimal value of request var*/
#define VAR_RESPONSE_MAX 50000 /*< Maximal value of response var */
#define VAR_RESPONSE_MIN 200 /*< Minimal value of response var*/
#define KURTOSIS_REQUEST_MIN 0 /*< Maximal value of request var */
#define MIN_DNS_REQUEST_COUNT 1000 /*< Minimal value of dns count of packets */
#define MIN_DNS_REQUEST_COUNT_TUNNEL 150 /*< Minimal value of dns count in payload analysis for tunnel */
#define MIN_DNS_REQUEST_COUNT_TUNNEL_CLOSER 30 /*< Minimal value of dns count in payload analysis for tunnel, closer interval */
#define MIN_DNS_REQUEST_COUNT_OTHER_ANOMALY 10000 /*< Minimal value of dns count in payload analysis for other anomaly */
#define MIN_DNS_RESPONSE_COUNT_TUNNEL 50 /*< Minimal value of dns count in payload analysis for tunnel */
#define MIN_DNS_RESPONSE_COUNT_OTHER_ANOMALY 10000 /*< Minimal value of dns count of packets */
#define MIN_LENGTH_OF_TUNNEL_STRING 100 /*< Minimal length of string containing tunnel */
#define REQUEST_MAX_COUNT_OF_USED_LETTERS 25  /*< Maximum number of used leeters for domain */
#define REQUEST_MAX_COUNT_OF_USED_LETTERS_CLOSER 60  /*< Maximum number of used leeters for domain, closer interval */
#define RESPONSE_MAX_COUNT_OF_USED_LETTERS 30  /*< Maximum number of used leeters for domain */
#define MAX_PERCENT_OF_NEW_SUBDOMAINS 0.8 /*< Maximum percent of new subdomain, more than this can be tunel */
#define MIN_PERCENT_OF_NEW_SUBDOMAINS 0.005 /*< Minimum percent of new subdomain, less than this can be anomaly */
#define MIN_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE 0.005 /*< Minimum percent of searching unique domains, less than that can be anomaly */
#define MAX_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE 0.9 /*< Maximum percent of searching unique domains, more than that can be tunnel */
#define MAX_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE_CLOSER 0.98 /*< Maximum percent of searching unique domains, more than that can be tunnel, closer interval */
#define MIN_PERCENT_OF_UNIQUE_DOMAINS 0.005 /*< Minimum percent unique domains, less than that can be anomaly */
#define MAX_PERCENT_OF_UNIQUE_DOMAINS 0.9 /*< Maximum percent of searching unique domains, more than that can be tunne l*/
#define MAX_PERCENT_OF_UNIQUE_DOMAINS_CLOSER 0.98 /*< Maximum percent of searching unique domains, more than that can be tunnel, closer interval*/
#define MAX_PERCENT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER 0.3 /*< Maximum percent of numbers in domain, more than that can be tunnel */
#define MAX_PERCENT_OF_MALLFORMED_PACKET_REQUEST 0.3 /*< Maximum percent of mallformed packet in requests */
#define MAX_COUNT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER 15 /*< Maximum count of numbers in domain, more than that can be tunnel */
#define REQUEST_PART_TUNNEL         0b00000001 /*< Define request part for suspision */
#define REQUEST_PART_OTHER          0b00000010 /*< Define request part for suspision */
#define RESPONSE_PART_TUNNEL        0b00000100 /*< Define request part for suspision */
#define RESPONSE_PART_OTHER         0b00001000 /*< Define request part for suspision */
#define REQUEST_AND_RESPONSE_PART   0b00001111 /*< Define request and response part for suspision*/
/* /} */

//TUNNEL_TYPE   Type of detected event
#define TUN_T_REQUEST_TUNNEL        1             //Request anomaly - detected tunnel
#define TUN_T_REQUEST_OTHER         2             //Request anomaly - detected other anomaly than tunnel
#define TUN_T_REQUEST_MALFORMED_P   3             //Request anomaly - malformed packets
#define TUN_T_RESPONSE_TUNNEL_REQ   4             //Response anomaly - detected tunnel in request string field
#define TUN_T_RESPONSE_TUNNEL_TXT   5             //Response anomaly - detected tunnel in TXT field
#define TUN_T_RESPONSE_TUNNEL_CNAME 6             //Response anomaly - detected tunnel in CNAME field
#define TUN_T_RESPONSE_TUNNEL_MX    7             //Response anomaly - detected tunnel in MX field
#define TUN_T_RESPONSE_TUNNEL_NS    8             //Response anomaly - detected tunnel in NS field
#define TUN_T_RESPONSE_OTHER        9             //Response anomaly - detected other anomaly than tunnel
#define TUN_T_RESPONSE_MALFORMED_P  10            //Response anomaly - malformed packets


/*!
 * \brief Signal function.
 * Function to catch signal termination or interrupt and set the global variable.
 * \param[in] signal Number of signal which have been caught.
 */
void signal_handler(int signal);

/*!
 * \brief Turns IP address from b_plus_tree to ip_addr_t
 * Turns IP address from b_plus_tree to ip_addr_t structure.
 * \param[in] item  value structure from b_plus_tree
 * \param[in] key key from b_plus_tree
 * \return ip_addr_t structure
 */
static inline ip_addr_t get_ip_addr_t_from_ip_struct(ip_address_t *item, void *key);

/*!
 * \brief Turns IP address from b_plus_tree to string
 * Turns IP address from b_plus_tree to string in dot format.
 * \param[in] item  value structure from b_plus_tree
 * \param[in] key key from b_plus_tree
 * \param[in] ip_buff space where to store the string
 */
void get_ip_str_from_ip_struct(ip_address_t * item, void * key,  char * ip_buff);

/*!
 * \brief Reads the last used event ID from file
 * It tries to read the last event ID from file. When the file
 * cannot be opened it will return 0.
 * \param[in] file_name string with file name.
 * \return last event id from file. Or 0.
 */
unsigned int read_event_id_from_file(char * file_name);

/*!
 * \brief Write summary function
 * It will write summary information of DNS communication to a file.
 * It is histogram of DNS requests and responses of all IPs
 * \param[in] record_folder name of folder where to save results
 * \param[in] histogram_dns_requests pointer to array of a histogram with requests.
 * \param[in] histogram_dns_response pointer to array of a histogram with responses.
 */
void write_summary_result(char * record_folder, unsigned long * histogram_dns_requests, unsigned long * histogram_dns_response);

/*!
 * \brief Write detail results function
 * It will write details of DNS communication to a file.
 * It is histogram of DNS requests and responses of each ip address separately.
 * \param[in] record_folder_name name of folder where to save results
 * \param[in] b_plus_tree pointer to array of b_plus_tree structures, where the IP address are stored.
 * \param[in] count_of_btree count of trees in the array.
 */
void write_detail_result(char * record_folder_name, void ** b_plus_tree, int count_of_btree);

/*!
 * \brief Send alerts of detected tunnel to SDM
 * It will send informations about detected tunnel to SDM.
 * \param[in] ip_address IP address with anomaly.
 * \param[in] item value from b_plus_tree.
 * \param[in] unirec_out structure with information about UniRec output.
 */
void send_unirec_alert_to_sdm(ip_addr_t * ip_address, ip_address_t *item, unirec_tunnel_notification_t * unirec_out_sdm);

/*!
 * \brief Send alerts of detected anomalies.
 * It will send informations about detected anomalies.
 * \param[in] ip_address IP address with anomaly.
 * \param[in] item value from b_plus_tree.
 * \param[in] unirec_out structure with information about UniRec output.
 */
void send_unirec_alert_and_reset_records(ip_addr_t * ip_address, ip_address_t *item, unirec_tunnel_notification_t * unirec_out);

/*!
 * \brief Prefix tree filter
 * Function filters strings which are  likely to be without anomalz.
 * \param[in] char_stat character statistic struct.
 * \return 1 on anomally, otherwise 0.
 */
int filter_trafic_to_save_in_prefix_tree_tunnel_suspicion(character_statistic_t * char_stat);

/*!
 * \brief Save information about IP
 * Function saves new information from packets and analyzes basic payload anomaly.
 * \param[in] tree pointer to B+ tree.
 * \param[in] ip_in_packet ip address from packet.
 * \param[in] packet recieved packet.
 */
void collection_of_information_and_basic_payload_detection(void * tree, void * ip_in_packet, packet_t * packet);


/*!
 * \brief Calcutate information about string and convert string to lower case
 * Function create statistic about string. Information about length, count of unique chatacters in string,....
 * The string is converted to lower case, it helps to detect same high level domain, because domains does not
 * have to be case sensitive.
 * \param[in] string pointer to string.
 * \param[in] stat pointer to structure, where to save data.
 * \param[in] packet recieved packet.
 */
void calculate_character_statistic_conv_to_lowercase(char * string, character_statistic_t * stat);

/*!
 * \brief Calcutate information about IP address
 * Function create statistic about IP address flows. It calculate ex, var, ....
 * \param[in] ip_rec IP address structure.
 * \param[in] result pointer to structure with results.
 */
void calculate_statistic(ip_address_t * ip_rec, calulated_result_t * result);

/*!
 * \brief check state of types detection and delete useless
 * Type detections which are in OK state will be deleted
 * \param[in] item_to_delete IP address structure.
 * \param[in] part number of type detection which should be deleted.
 */
void check_and_delete_suspision(ip_address_t * item_to_delete, unsigned char part);


/*!
 * \brief Traffic analyis test for request other anomaly
 * Function checks parametters like ex var and change state of IP detection type
 * \param[in] item  IP address structure.
 * \param[in] result information abou IP, like ex, var...
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_traffic_on_ip_ok_request_other(ip_address_t * item, calulated_result_t * result);

/*!
 * \brief Traffic analyis test for request tunnel
 * Function checks parametters like ex var and change state of IP detection type
 * \param[in] item  IP address structure.
 * \param[in] result information abou IP, like ex, var...
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_traffic_on_ip_ok_request_tunnel(ip_address_t * item, calulated_result_t * result);


/*!
 * \brief Traffic analyis test for response other anomaly
 * Function checks parametters like ex var and change state of IP detection type
 * \param[in] item  IP address structure.
 * \param[in] result information abou IP, like ex, var...
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_traffic_on_ip_ok_response_other(ip_address_t * item, calulated_result_t * result);

/*!
 * \brief Payload analyis test for request other anomaly
 * Function checks domain, if they could be anomally.
 * \param[in] item  IP address structure.
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_payload_on_ip_ok_request_other(ip_address_t * item);

/*!
 * \brief Payload analyis test for response other anomaly
 * Function checks domain, TXT, CNAME, MX, NS if they could be anomally.
 * \param[in] item  IP address structure.
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_payload_on_ip_ok_response_other(ip_address_t * item);

/*!
 * \brief Payload analyis test for response tunnel
 * Function checks domain, if they could be anomally.
 * \param[in] item  IP address structure.
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_payload_on_ip_ok_request_tunnel(ip_address_t * item);

/*!
 * \brief Payload analyis test for response tunnel
 * Function checks domain, TXT, CNAME, MX, NS if they could be anomally.
 * \param[in] item  IP address structure.
 * \param[in] result information abou IP, like ex, var...
 * \return STATE_SUSPICION on anomally, otherwise STATE_NEW.
 */
int is_payload_on_ip_ok_response_tunnel(ip_address_t * item);


/*!
 * \brief Detection function
 * One of main function on module.
 * Function tests every IP address on anomaly. When anomaly is founded it is written into file.
 * If there is no anomaly, the IP address is deleted from B+ tree.
 * \param[in] b_plus_tree pointer to B+ tree structure
 * \param[in] file pointer to file with results
 * \param[in] ur_notification structure with unirec output datas
 */
void calculate_statistic_and_choose_anomaly(void * b_plus_tree, FILE *file, unirec_tunnel_notification_t * ur_notification);

/*!
 * \brief Print annomaly during detection
 * Function write info about anomaly to file, which is given in parametter.
 * It prits info about one IP address.
 * \param[in] ip_address ip address string
 * \param[in] item ip address with anomaly
 * \param[in] file pointer to file with results
 * \param[in] print_time 1 - time is printed, 0 - time is not printed
 */
void print_founded_anomaly_immediately(char * ip_address, ip_address_t *item, FILE *file, unsigned char print_time);

/*!
 * \brief Print annomaly on the end of module
 * Function write info about all anomalies to file, which is given in parametter.
 * It is about IP address which id givven in parametter
 * \param[in] ip_address ip address string
 * \param[in] item ip address with anomaly
 * \param[in] file pointer to file with results
 */
void print_founded_anomaly(char *ip_address, ip_address_t *item, FILE *file);

/*!
 * \brief Print ip which is in suspicion state
 * Function write info about ip which is in suspicion state.
 * \param[in] ip_address ip address string
 * \param[in] ip_item ip address with anomaly
 * \param[in] file pointer to file with other suspicion address
 */
void print_suspision_ip(char *ip_address, ip_address_t *ip_item, FILE *file);

/*!
 * \brief Write summary results
 * Write summary results about detection, all ip addresses together.
 * \param[in] record_folder_name folder with results
 * \param[in] histogram_dns_requests data for histogram
 * \param[in] histogram_dns_response data for histogram
 */
void write_summary_result(char * record_folder_name, unsigned long * histogram_dns_requests, unsigned long * histogram_dns_response);


/*!
 * \brief Write histogram values
 * Write histogram values about IP address to files for request, response, request count letters.
 * \param[in] ip_address ip address string
 * \param[in] item ip address with anomaly
 * \param[in] file_requests file pointer
 * \param[in] file_responses file pointer
 * \param[in] file_requests_count_letters file pointer
 */
void print_histogram_values (char *ip_address, ip_address_t *ip_item, FILE *file_requests, FILE *file_responses, FILE *file_requests_count_letters);


/*!
 * \brief Write result function
 * Write information about all ip addresses to given folder
 * \param[in] record_folder_name folder with results
 * \param[in] b_plus_tree pointer to B+ tree structures
 * \param[in] count_of_btree count of tree structures (for ipv4, ipv6 ...)
 */
void write_detail_result(char * record_folder_name, void ** b_plus_tree, int count_of_btree);


/*!
 * \brief Compare function for IPv6
 * Compare which ip is <, >, ==
 * \param[in] a first IP address
 * \param[in] b seccond IP address
 * \return if a<b LESS, a>b MORE, a==b EQUAL
 */
int compare_ipv6(void * a, void * b);

/*!
 * \brief Compare function for IPv4
 * Compare which ip is <, >, ==
 * \param[in] a first IP address
 * \param[in] b seccond IP address
 * \return if a<b LESS, a>b MORE, a==b EQUAL
 */
int compare_ipv4(void * a, void * b);


/*!
 * \brief Load default values
 * Load default values from header. This values are used, when they are not specified in parametters for program.
 */
void load_default_values();

/*!
 * \brief Send notifications to UniRec
 * Sends notification data stored in structure unirec_tunnel_notification_t to UniRec.
 * \param[in] notification structure with data, which are send to UniRec
 */
void send_unirec_out(unirec_tunnel_notification_t * notification);

/*!
 * \brief Send notifications to SDM to UniRec
 * Sends notification data stored in structure unirec_tunnel_notification_t to UniRec.
 * This function sends just SRC IP and DST PORT (Export to SDM).
 * \param[in] notification structure with data, which are send to UniRec
 */
void send_unirec_out_sdm(unirec_tunnel_notification_t * notification);

 #endif /* _TUNNEL_DETECTION_DNS_ */
