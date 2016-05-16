/*!
 * \file tunnel_detection_dns.c
 * \brief Modul that detects DNS tunnels.
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
 * \author Tomas Cejka <cejkat@cesnet.cz>
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

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <math.h>
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include "tunnel_detection_dns.h"
#include "parser_pcap_dns.h"
#include "fields.h"

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 EVENT_ID,
   uint32 PACKETS,
   uint32 TIMEOUT,
   uint32 TUNNEL_CNT_PACKET,
   float TUNNEL_PER_NEW_DOMAIN,
   float TUNNEL_PER_SUBDOMAIN,
   uint16 DNS_QTYPE,
   uint16 DST_PORT,
   uint8 TUNNEL_TYPE,
   string DNS_NAME,
   string DNS_RDATA,
   string SDM_CAPTURE_FILE_ID,
   string TUNNEL_DOMAIN
)

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("DNS-tunnel-detection module","Module that detects DNS tunnels on the network. Input interface needs DNS FLOW data. \
There can be two output interfaces. First output interface sends alerts from the detector. Second output interface sends rules to SDMCAP to catch reel traffic.",1,-1)

#define MODULE_PARAMS(PARAM) \
  PARAM('i', "ifc", "Specification of interface types and their parameters", required_argument, "string") \
  PARAM('p', "print", "Show progress - print a dot every N flows.", required_argument, "int32") \
  PARAM('a', "whitelist_domain", "File with whitelist of domain which will not be analyzed.", required_argument, "string") \
  PARAM('b', "whitelist_ip", "File with whitelist of IPs which will not be analyzed.", required_argument, "string") \
  PARAM('c', "measure_param_file", "Read packet from file - MEASURE_PARAMETERS mode", required_argument, "string") \
  PARAM('s', "save_folder", "Folder with results and other information about detection (on the end of module). Specify folder for data saving.", required_argument, "string") \
  PARAM('S', "SDM_setting", "SDM setting. Set count of packet which will be recorded by SDM and timeout, after that the rule will be discard from SDM [COUNT of packets, TIMEOUT].", required_argument, "string") \
  PARAM('d', "anomaly_file", "File with results of detection anomaly (during module runtime).", required_argument, "string") \
  PARAM('f', "packet_file", "Read packets from file", required_argument, "string") \
  PARAM('g', "suspicion_request", "Set Max and Min EX and VAR for suspicion in requests, [MIN EX, MAX EX, MIN VAR, MAX VAR].", required_argument, "string") \
  PARAM('r', "suspicion_response", "Set Max and Min EX and VAR for suspicion in responses, [MIN EX, MAX EX, MIN VAR, MAX VAR].", required_argument, "string") \
  PARAM('j', "suspicion_max_letters", "Set Max count of used letters not to be in suspicion mode, [MAX number for Request, MAX number for response].", required_argument, "string") \
  PARAM('k', "subdomain_percent", "Max and Min percent of subdomain, [MAX, MIN].", required_argument, "string") \
  PARAM('l', "suspicion_max_numbers", "Max count and percent of numbers in domain not to be in suspicion mode, [MAX count, MAX percent].", required_argument, "string") \
  PARAM('m', "max_malformed", "Max percent of malformed packet to be in traffic anomaly [MAX].", required_argument, "float") \
  PARAM('n', "min_suspected_requests", "MIN count of suspected requests to be traffic anomaly or tunnel [MIN for traffic anomaly, MIN for tunnel].", required_argument, "string") \
  PARAM('o', "min_suspected_responses", "MIN count of suspected responses to be traffic anomaly or tunnel [MIN for traffic anomaly, MIN for tunnel].", required_argument, "string") \
  PARAM('q', "searching", "Max and Min percent of searching just ones [MAX, MIN].", required_argument, "string") \
  PARAM('t', "max_round", "MAX round in SUSPICION MODE and ATTACK MODE [SUSPICION, ATTACK]", required_argument, "string") \
  PARAM('w', "tunnel_length", "MIN length of string to be tunnel [MIN].", required_argument, "int32") \
  PARAM('z', "collect_length", "Length of collecting packets before analysis in sec [time in sec]", required_argument, "int32") \
  PARAM('E', "file_event_id", "Path to file with last used event id (Id of an alert). Default path is /data/dnstunnel_tunnel/event_id.txt", required_argument, "string")

static int stop = 0;
static int stats = 0;
static int progress = 0;
static values_t values;

#ifdef TIME
   static int add_to_bplus = 0;
   static int search_in_bplus = 0;
   static int delete_from_blus =0;
   static int add_to_prefix = 0;
#endif /*TIME*/

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

void signal_handler(int signal)
{
   /*if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   } else*/ if (signal == SIGUSR1) {
      stats = 1;
   }
}

void calculate_limits_by_confidential_interval( double sum, double sum_2, int count, double * min, double * max) {
   double ex, var, std;
   ex = sum / (double)count;
   var = (sum_2 - ex * ex * (double)count)/(double)(count-1);
   std = sqrtf(var);
   if (min != NULL) {
      *min = ex - std;
   }
   if (max != NULL) {
      *max = ex + std;
   }
   printf("hola ex %f, var %f, std %f \n", ex,var,std);
}

void calculate_limits_from_measuring(measure_parameters_t * measure)
{
   calculate_limits_by_confidential_interval(measure->sum_size_request, measure->sum_2_size_request, measure->requests, &(measure->ex_request_min), &(measure->ex_request_max));
   calculate_limits_by_confidential_interval(measure->sum_size_response, measure->sum_2_size_response, measure->responses, &(measure->ex_response_min), &(measure->ex_response_max));
   calculate_limits_by_confidential_interval(measure->sum_count_of_unique_letters_request, measure->sum_2_count_of_unique_letters_request, measure->requests, &(measure->request_max_count_of_used_letters), NULL);
   calculate_limits_by_confidential_interval(measure->sum_count_of_unique_letters_response, measure->sum_2_count_of_unique_letters_response, measure->responses, &(measure->response_max_count_of_used_letters), NULL);
   calculate_limits_by_confidential_interval(measure->sum_count_of_unique_letters_response, measure->sum_2_count_of_unique_letters_response, measure->responses, &(measure->response_max_count_of_used_letters), NULL);
   //calculate_limits_by_confidential_interval(measure->sum_count_of_numbers, measure->sum_2_count_of_numbers, measure->requests, &(measure->max_count_of_numbers_in_domain_prefix_tree_filter), NULL);
   //calculate_limits_by_confidential_interval(measure->sum_percent_of_numbers, measure->sum_2_percent_of_numbers, measure->requests, &(measure->max_percent_of_numbers_in_domain_prefix_tree_filter), NULL);
   measure->max_count_of_numbers_in_domain_prefix_tree_filter = measure->sum_count_of_numbers / measure->requests;
   measure->max_percent_of_numbers_in_domain_prefix_tree_filter = measure->sum_percent_of_numbers / (double)measure->requests;
   printf(" sum percent of numbers: %f\n", measure->sum_percent_of_numbers);
}

static inline ip_addr_t get_ip_addr_t_from_ip_struct(ip_address_t *item, void *key)
{
   ip_addr_t ip_to_translate;
   if (item->ip_version == IP_VERSION_4) {
      uint32_t * ip = (uint32_t *)key;
      ip_to_translate = ip_from_int(*ip);
   } else {
      uint64_t * ip = (uint64_t *)key;
      ip_to_translate = ip_from_16_bytes_be((char*)&ip[0]);
   }
   return ip_to_translate;
}

void get_ip_str_from_ip_struct(ip_address_t * item, void * key,  char * ip_buff)
{
   ip_addr_t addr = get_ip_addr_t_from_ip_struct(item,key);
   ip_to_str(&addr ,ip_buff);
}

static inline unsigned int get_event_id()
{
   return values.event_id_counter++;
}

int filter_trafic_to_save_in_prefix_tree_tunnel_suspicion(character_statistic_t * char_stat)
{
   if (char_stat->length >= values.min_length_of_tunnel_string &&
      (char_stat->count_of_different_letters > values.request_max_count_of_used_letters ||     //just domains which have a lot of letters
      ((double)char_stat->count_of_numbers_in_string / (double)char_stat->length > values.max_percent_of_numbers_in_domain_prefix_tree_filter && //just domains which have a lot of numbers
      char_stat->count_of_numbers_in_string > values.max_count_of_numbers_in_domain_prefix_tree_filter)))
   {
      return 1;
   }
   return 0;
}

void collection_of_information_and_basic_payload_detection(void * tree, void * ip_in_packet, packet_t * packet)
{
   ip_address_t * found;
   float size2;
   int index_to_histogram;
   character_statistic_t char_stat;
   size2=packet->size*packet->size;
   //found or create in b plus tree
   found = (ip_address_t*)b_plus_tree_insert_or_find_item(tree,ip_in_packet);
   if (found == NULL) {
      return;
   }
   found->ip_version = packet->ip_version;
   found->time_last = time(NULL);

   #ifdef TIME
      if (found->counter_request.dns_request_count == 0 && found->counter_response.dns_response_count ==0) {
         add_to_bplus++;
      }
      else {
         search_in_bplus++;
      }
   #endif /*TIME*/
   //add to request or response
   if (packet->is_response == 0) {
      //calculate index in histogram
      index_to_histogram = packet->size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? packet->size / 10 : HISTOGRAM_SIZE_REQUESTS - 1;
      found->counter_request.histogram_dns_requests[index_to_histogram]++;
      found->counter_request.dns_request_count++;
      //calculate sums for statistic
      found->counter_request.sum_Xi_request += packet->size;
      found->counter_request.sum_Xi2_request += size2;
      //this variables could be used for improving the module
         //found->counter_request.sum_Xi3_request += size2*packet->size;
         //found->counter_request.sum_Xi4_request += size2*size2;
         //packet has request string
         if (packet->request_length > 0) {
            found->counter_request.dns_request_string_count++;
            found->counter_request.histogram_dns_request_sum_for_cout_of_used_letter[index_to_histogram]++;
            calculate_character_statistic_conv_to_lowercase(packet->request_string, &char_stat);
            found->counter_request.histogram_dns_request_ex_sum_of_used_letter[index_to_histogram] += char_stat.count_of_different_letters;
            //filter to immediatly save into prefix tree, if there is proofed tunnel, than dont capture more
            if (filter_trafic_to_save_in_prefix_tree_tunnel_suspicion(&char_stat)) {
               if (found->suspision_request_tunnel == NULL) {
                  found->suspision_request_tunnel = (ip_address_suspision_request_tunnel_t*)calloc(sizeof(ip_address_suspision_request_tunnel_t),1);
               }
               if (found->suspision_request_tunnel != NULL && found->suspision_request_tunnel->tunnel_suspision == NULL) {
                  found->suspision_request_tunnel->tunnel_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
                  time(&(found->suspision_request_tunnel->time_first));
               }
               if (found->suspision_request_tunnel != NULL && found->suspision_request_tunnel->tunnel_suspision != NULL) {
                  found->suspision_request_tunnel->sum_of_inserting++;
                  prefix_tree_insert(found->suspision_request_tunnel->tunnel_suspision, packet->request_string, char_stat.length);
               }
               #ifdef TIME
                  add_to_prefix++;
               #endif /*TIME*/
               if (found->state_request_tunnel == STATE_NEW) {
                  found->state_request_tunnel = STATE_SUSPICION;
               }
            }
            else if (found->state_request_tunnel != STATE_NEW && found->suspision_request_tunnel && found->suspision_request_tunnel->state_request_size[index_to_histogram] == STATE_ATTACK) {
               found->suspision_request_tunnel->sum_of_inserting++;
               prefix_tree_insert(found->suspision_request_tunnel->tunnel_suspision, packet->request_string, char_stat.length);
               #ifdef TIME
                  add_to_prefix++;
               #endif /*TIME*/
            }
            //add to prefix tree, if ip is in suspision state, other anomaly
            if (found->state_request_other != STATE_NEW && found->suspision_request_other && found->suspision_request_other->state_request_size[index_to_histogram] == STATE_ATTACK) {
               found->suspision_request_other->sum_of_inserting++;
               prefix_tree_insert(found->suspision_request_other->other_suspision, packet->request_string, char_stat.length);
               #ifdef TIME
                  add_to_prefix++;
               #endif /*TIME*/
            }
         }
         else {
            found->counter_request.request_without_string++;
         }
      }
   else {
      //calculate index in histogram
      index_to_histogram = packet->size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? packet->size / 10 : HISTOGRAM_SIZE_RESPONSE - 1;
      found->counter_response.histogram_dns_response[packet->size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? packet->size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
      found->counter_response.dns_response_count++;
      //calculate sums for statistic
      found->counter_response.sum_Xi_response += packet->size;
      found->counter_response.sum_Xi2_response += size2;
      //this variables could be used for improving the module
         //found->counter_response.sum_Xi3_response += size2*packet->size;
         //found->counter_response.sum_Xi4_response += size2*size2;
      if (found->state_response_other != STATE_NEW && found->suspision_response_other && found->suspision_response_other->state_response_size[index_to_histogram] == STATE_ATTACK) {
         if (packet->request_length > 0) {
            calculate_character_statistic_conv_to_lowercase(packet->request_string, &char_stat);
            found->suspision_response_other->sum_of_inserting++;
            prefix_tree_insert(found->suspision_response_other->other_suspision, packet->request_string, char_stat.length);
            #ifdef TIME
               add_to_prefix++;
            #endif /*TIME*/
         }
         else {
            found->suspision_response_other->without_string++;
         }
         found->suspision_response_other->packet_in_suspicion++;
      }
      //response tunnel detection
      if (packet->request_length > 0) {
         calculate_character_statistic_conv_to_lowercase(packet->request_string, &char_stat);
         if (char_stat.count_of_different_letters > values.response_max_count_of_used_letters) {
            if (found->suspision_response_tunnel == NULL) {
               found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->request_suspision == NULL) {
               found->suspision_response_tunnel->request_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
               if (found->suspision_response_tunnel->request_suspision) {
                  time(&(found->suspision_response_tunnel->request_suspision_time_first));
               }
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->request_suspision != NULL) {
               found->suspision_response_tunnel->sum_of_inserting_request++;
               prefix_tree_insert(found->suspision_response_tunnel->request_suspision, packet->request_string, char_stat.length);
            }
            #ifdef TIME
               add_to_prefix++;
            #endif /*TIME*/
            if (found->state_response_tunnel == STATE_NEW) {
               found->state_response_tunnel = STATE_SUSPICION;
            }
         }
      }

      if (packet->txt_response[0]!=0) {
         calculate_character_statistic_conv_to_lowercase(packet->txt_response, &char_stat);
         if (char_stat.count_of_different_letters > values.response_max_count_of_used_letters) {
            if (found->suspision_response_tunnel == NULL) {
               found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->txt_suspision == NULL) {
               found->suspision_response_tunnel->txt_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
               if (found->suspision_response_tunnel->txt_suspision) {
                  time(&(found->suspision_response_tunnel->txt_suspision_time_first));
               }
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->txt_suspision != NULL) {
               found->suspision_response_tunnel->sum_of_inserting_txt++;
               prefix_tree_insert(found->suspision_response_tunnel->txt_suspision, packet->txt_response, char_stat.length);
            }
            #ifdef TIME
               add_to_prefix++;
            #endif /*TIME*/
            if (found->state_response_tunnel == STATE_NEW) {
               found->state_response_tunnel = STATE_SUSPICION;
            }
         }
      }
      if (packet->cname_response[0]!=0) {
         calculate_character_statistic_conv_to_lowercase(packet->cname_response, &char_stat);
         if (char_stat.count_of_different_letters > values.response_max_count_of_used_letters) {
            if (found->suspision_response_tunnel == NULL) {
               found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->cname_suspision == NULL) {
               found->suspision_response_tunnel->cname_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
               if (found->suspision_response_tunnel->cname_suspision) {
                  time(&(found->suspision_response_tunnel->cname_suspision_time_first));
               }
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->cname_suspision != NULL) {
               found->suspision_response_tunnel->sum_of_inserting_cname++;
               prefix_tree_insert(found->suspision_response_tunnel->cname_suspision, packet->cname_response, char_stat.length);
            }
            #ifdef TIME
               add_to_prefix++;
            #endif /*TIME*/
            if (found->state_response_tunnel == STATE_NEW) {
               found->state_response_tunnel = STATE_SUSPICION;
            }
         }
      }
      if (packet->mx_response[0]!=0) {
         calculate_character_statistic_conv_to_lowercase(packet->mx_response, &char_stat);
         if (char_stat.count_of_different_letters > values.response_max_count_of_used_letters) {
            if (found->suspision_response_tunnel == NULL) {
               found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
            }
            if (found->suspision_response_tunnel !=NULL && found->suspision_response_tunnel->mx_suspision == NULL) {
               found->suspision_response_tunnel->mx_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
               if (found->suspision_response_tunnel->mx_suspision) {
                  time(&(found->suspision_response_tunnel->mx_suspision_time_first));
               }
            }
            if (found->suspision_response_tunnel !=NULL && found->suspision_response_tunnel->mx_suspision != NULL) {
               found->suspision_response_tunnel->sum_of_inserting_mx++;
               prefix_tree_insert(found->suspision_response_tunnel->mx_suspision, packet->mx_response, char_stat.length);
            }
            #ifdef TIME
               add_to_prefix++;
            #endif /*TIME*/
            if (found->state_response_tunnel == STATE_NEW) {
               found->state_response_tunnel = STATE_SUSPICION;
            }
         }
      }
      if (packet->ns_response[0]!=0) {
         calculate_character_statistic_conv_to_lowercase(packet->ns_response, &char_stat);
         if (char_stat.count_of_different_letters > values.response_max_count_of_used_letters) {
            if (found->suspision_response_tunnel == NULL) {
               found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->ns_suspision == NULL) {
               found->suspision_response_tunnel->ns_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
               if (found->suspision_response_tunnel->ns_suspision) {
                  time(&(found->suspision_response_tunnel->ns_suspision_time_first));
               }
            }
            if (found->suspision_response_tunnel != NULL && found->suspision_response_tunnel->ns_suspision != NULL) {
               found->suspision_response_tunnel->sum_of_inserting_ns++;
               prefix_tree_insert(found->suspision_response_tunnel->ns_suspision, packet->ns_response, char_stat.length);
            }
            #ifdef TIME
               add_to_prefix++;
            #endif /*TIME*/
            if (found->state_response_tunnel == STATE_NEW) {
               found->state_response_tunnel = STATE_SUSPICION;
            }
         }
      }
   }
}

void calculate_character_statistic_conv_to_lowercase(char * string, character_statistic_t * stat)
{
   char used[255];
   int i;
   memset(used, 0, 255);
   stat->count_of_different_letters = 0;
   stat->count_of_numbers_in_string = 0;
   stat->length = 0;
   while (*string != 0) {
      used[(unsigned char)(*string)]++;
      if (*string>='0' && *string<='9') {
         stat->count_of_numbers_in_string++;
      }
      //convert to lover case
      *string = tolower(*string);
      string++;
      stat->length++;
   }
   //count used letters
   for (i=0; i<255; i++) {
      if (used[i]!=0) {
         stat->count_of_different_letters++;
      }
   }
}

void calculate_statistic(ip_address_t * ip_rec, calulated_result_t * result)
{
   float xn2_request;
   float xn2_response;
   //calculate ex
   //ex = Sum(Xi) / n
   result->ex_request = (float)ip_rec->counter_request.sum_Xi_request / (float)ip_rec->counter_request.dns_request_count;
   result->ex_response = (float)ip_rec->counter_response.sum_Xi_response / (float)ip_rec->counter_response.dns_response_count;
   xn2_request = result->ex_request * result->ex_request;
   xn2_response = result->ex_response * result->ex_response;
   //calculate var
   //var x = (Sum(Xi^2) - Xn^2 * n) / (n-1)
   result->var_request = (float)(ip_rec->counter_request.sum_Xi2_request - xn2_request * ip_rec->counter_request.dns_request_count ) / (float)(ip_rec->counter_request.dns_request_count - 1);
   result->var_response = (float)(ip_rec->counter_response.sum_Xi2_response - xn2_response * ip_rec->counter_response.dns_response_count ) / (float)(ip_rec->counter_response.dns_response_count - 1);
   //this variables could be used for improving the module
   /*
      //calculace skewness
      //skewness = n * (Sum(Xi^4) - 4 * Xn * Sum(Xi^3)  +  6 * Xn^2 * Sum(Xi^2) - 4 * Xn^3 * Sum(Xi) + Xn^4 * n ) / (var x)^2
      result->skewness_request = (float)((ip_rec->counter_request.sum_Xi4_request -
                                 4 * result->ex_request * ip_rec->counter_request.sum_Xi3_request  +
                                 6 * xn2_request * ip_rec->counter_request.sum_Xi2_request -
                                 4 * result->ex_request * xn2_request  * ip_rec->counter_request.sum_Xi_request +
                                 xn2_request * xn2_request * ip_rec->counter_request.dns_request_count) *
                                 ip_rec->counter_request.dns_request_count) /
                                 (float)(result->var_request * result->var_request);
      result->skewness_response = (float)((ip_rec->counter_response.sum_Xi4_response -
                                 4 * result->ex_response * ip_rec->counter_response.sum_Xi3_response  +
                                 6 * xn2_response * ip_rec->counter_response.sum_Xi2_response -
                                 4 * result->ex_response * xn2_response  * ip_rec->counter_response.sum_Xi_response +
                                 xn2_response * xn2_response * ip_rec->counter_response.dns_response_count) *
                                 ip_rec->counter_response.dns_response_count) /
                                 (float)(result->var_response * result->var_response);
      //calculace kurtosis
      //kurtosis = n^(1/2) * (Sum(Xi^3) - 3 * Sum(Xi^2) * Xn  +  3 * Xn^2 * Sum(Xi) - Xn^3 * n ) / (var x)^(3/2)
      result->kurtosis_request = (float)((ip_rec->counter_request.sum_Xi3_request -
                                 3 * ip_rec->counter_request.sum_Xi2_request * result->ex_request +
                                 3 * xn2_request * ip_rec->counter_request.sum_Xi_request -
                                 xn2_request * result->ex_request * ip_rec->counter_request.dns_request_count) *
                                 sqrtf((float)ip_rec->counter_request.dns_request_count)) /
                                 sqrtf((float)(result->var_request * result->var_request * result->var_request));
      result->kurtosis_response = (float)((ip_rec->counter_response.sum_Xi3_response -
                                 3 * ip_rec->counter_response.sum_Xi2_response * result->ex_response +
                                 3 * xn2_response * ip_rec->counter_response.sum_Xi_response -
                                 xn2_response * result->ex_response * ip_rec->counter_response.dns_response_count) *
                                 sqrtf((float)ip_rec->counter_response.dns_response_count)) /
                                 sqrtf((float)(result->var_response * result->var_response * result->var_response));
   */
   //calculate ex of used letters
   result->ex_request_count_of_different_letters = 0;
   result->var_request_count_letters = 0;
   for (int i=0; i < HISTOGRAM_SIZE_REQUESTS; i++) {
      if (ip_rec->counter_request.histogram_dns_request_sum_for_cout_of_used_letter[i] > 0) {
         result->histogram_dns_request_ex_cout_of_used_letter[i] = (float)ip_rec->counter_request.histogram_dns_request_ex_sum_of_used_letter[i] / (float)ip_rec->counter_request.histogram_dns_request_sum_for_cout_of_used_letter [i];
         result->ex_request_count_of_different_letters += result->histogram_dns_request_ex_cout_of_used_letter[i];
         result->var_request_count_letters += result->histogram_dns_request_ex_cout_of_used_letter[i] * result->histogram_dns_request_ex_cout_of_used_letter[i];
      }
      else {
         result->histogram_dns_request_ex_cout_of_used_letter[i] =0;
      }
   }
   result->ex_request_count_of_different_letters /= (float)ip_rec->counter_request.dns_request_string_count;
   result->var_request_count_letters /= (float)ip_rec->counter_request.dns_request_string_count;
   result->var_request_count_letters -=  result->ex_request_count_of_different_letters * result->ex_request_count_of_different_letters;
}

void check_and_delete_suspision(ip_address_t * item_to_delete, unsigned char part)
{
   if (part & REQUEST_PART_TUNNEL) {
      if (item_to_delete->suspision_request_tunnel != NULL) {
         if (item_to_delete->suspision_request_tunnel->tunnel_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_request_tunnel->tunnel_suspision);
         }
         free(item_to_delete->suspision_request_tunnel);
         item_to_delete->suspision_request_tunnel = NULL;
      }
   }
   if (part & REQUEST_PART_OTHER) {
      if (item_to_delete->suspision_request_other != NULL) {
         if (item_to_delete->suspision_request_other->other_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_request_other->other_suspision);
         }
         free(item_to_delete->suspision_request_other);
         item_to_delete->suspision_request_other = NULL;
      }
      memset(&item_to_delete->counter_request, 0, sizeof(counter_request_t));
   }
   if (part & RESPONSE_PART_OTHER) {
      if (item_to_delete->suspision_response_other != NULL) {
         if (item_to_delete->suspision_response_other->other_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_response_other->other_suspision);
         }
         free(item_to_delete->suspision_response_other);
         item_to_delete->suspision_response_other = NULL;
      }
      memset(&item_to_delete->counter_response, 0, sizeof(counter_response_t));
   }
   if (part & RESPONSE_PART_TUNNEL) {
      if (item_to_delete->suspision_response_tunnel != NULL) {
         if (item_to_delete->suspision_response_tunnel->request_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->request_suspision);
         }
         if (item_to_delete->suspision_response_tunnel->cname_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->cname_suspision);
         }
         if (item_to_delete->suspision_response_tunnel->txt_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->txt_suspision);
         }
         if (item_to_delete->suspision_response_tunnel->ns_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->ns_suspision);
         }
         if (item_to_delete->suspision_response_tunnel->mx_suspision != NULL) {
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->mx_suspision);
         }
         free(item_to_delete->suspision_response_tunnel);
         item_to_delete->suspision_response_tunnel = NULL;
      }
   }
   if (part & RESPONSE_PART_OTHER) {
      memset(&item_to_delete->counter_response, 0, sizeof(counter_response_t));
   }
}

int is_traffic_on_ip_ok_request_other(ip_address_t * item, calulated_result_t * result)
{
   int i;
   //if there is more traffic than minimum
   if (item->state_request_other != STATE_ATTACK && item->counter_request.dns_request_count > values.min_dns_request_count_other_anomaly) {
      //other anomaly can be caused, then select the peaks, which have most of communication
      if ( result->ex_request < values.ex_request_min || result->var_request < values.var_request_min || result->var_request > values.var_request_max || result->ex_request > values.ex_request_max /*|| result->kurtosis_request < values.kurtosis_request_min*/) {
         int max;
         item->state_request_other = STATE_SUSPICION;
         //if it is first suspision
         if (item->suspision_request_other == NULL) {
            item->suspision_request_other = (ip_address_suspision_request_other_t*)calloc(sizeof(ip_address_suspision_request_other_t),1);
         }
         //if it is first other suspision
         if (item->suspision_request_other != NULL && item->suspision_request_other->other_suspision == NULL) {
            time(&(item->suspision_request_other->time_first));
            item->suspision_request_other->other_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
         }
         max = 0;
         for (i = max; i < HISTOGRAM_SIZE_REQUESTS ; i++) {
            //select the biggest peak
            if (item->counter_request.histogram_dns_requests[i] > item->counter_request.histogram_dns_requests[max]) {
               max = i;
            }
            //select everything what have more than certain amount of traffic and is not in tunnel detection tree
            if ((float)item->counter_request.histogram_dns_requests[i] / (float)item->counter_request.dns_request_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPICION &&
               result->histogram_dns_request_ex_cout_of_used_letter[i] < values.request_max_count_of_used_letters ) {
                  item->suspision_request_other->state_request_size[i] = STATE_ATTACK;
            }
         }
         //the biggest peak
         item->suspision_request_other->state_request_size[max] = STATE_ATTACK;
      }
   }
   if (item->state_request_other == STATE_NEW) {
      return STATE_NEW;
   }
   return STATE_SUSPICION;
}

int is_traffic_on_ip_ok_request_tunnel(ip_address_t * item, calulated_result_t * result)
{
   int i;
   //if there is more traffic than minimum
   if (item->state_request_tunnel != STATE_ATTACK && item->counter_request.dns_request_count > values.min_dns_request_count_other_anomaly) {
      //other anomaly can be caused, then select the peaks, which have most of communication
      if ( result->var_request < values.var_request_min || result->var_request > values.var_request_max || result->ex_request > values.ex_request_max /*|| result->kurtosis_request < values.kurtosis_request_min*/) {
         int max;
         item->state_request_tunnel = STATE_SUSPICION;
         //if it is first suspision
         if (item->suspision_request_tunnel == NULL) {
            item->suspision_request_tunnel = (ip_address_suspision_request_tunnel_t*)calloc(sizeof(ip_address_suspision_request_tunnel_t),1);
         }
         //if it is first other suspision
         if (item->suspision_request_tunnel != NULL && item->suspision_request_tunnel->tunnel_suspision == NULL) {
            time(&(item->suspision_request_tunnel->time_first));
            item->suspision_request_tunnel->tunnel_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
         }
         max = 0;
         for (i = max; i < HISTOGRAM_SIZE_REQUESTS ; i++) {
            //selecet everything what have more than certain amount of traffic and is not in tunnel detection tree
            if ((float)item->counter_request.histogram_dns_requests[i] / (float)item->counter_request.dns_request_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPICION &&
               result->histogram_dns_request_ex_cout_of_used_letter[i] < values.request_max_count_of_used_letters ) {
                  item->suspision_request_tunnel->state_request_size[i] = STATE_ATTACK;
            }
         }
      }
   }
   if (item->state_request_tunnel == STATE_NEW) {
      return STATE_NEW;
   }
   return STATE_SUSPICION;
}

int is_traffic_on_ip_ok_response_other(ip_address_t * item, calulated_result_t * result)
{
   int i;
   //responses
   if ( item->state_response_other != STATE_ATTACK && item->counter_response.dns_response_count > values.min_dns_response_count_other_anomaly) {
      if ( result->ex_response < values.ex_response_min || result->var_response < values.var_response_min || result->var_response > values.var_response_max || result->ex_response > values.ex_response_max /*|| result->kurtosis_request < values.kurtosis_request_min*/) {
        int max;
         item->state_response_other = STATE_SUSPICION;
         //if it is first suspision
         if (item->suspision_response_other == NULL) {
            item->suspision_response_other = (ip_address_suspision_response_other_t*)calloc(sizeof(ip_address_suspision_response_other_t),1);
         }
         //if it is first other suspision
         if (item->suspision_response_other != NULL && item->suspision_response_other->other_suspision == NULL) {
            time(&(item->suspision_response_other->time_first));
            item->suspision_response_other->other_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
         }
         max = 0;
         for (i = max; i < HISTOGRAM_SIZE_RESPONSE ; i++) {
            //select the biggest peak
            if (item->counter_response.histogram_dns_response[i] > item->counter_response.histogram_dns_response[max]) {
               max = i;
            }
            //selecet everything what have more than certain amount of traffic and is not in tunnel detection tree
            if ((float)item->counter_response.histogram_dns_response[i] / (float)item->counter_response.dns_response_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPICION) {
                  item->suspision_response_other->state_response_size[i] = STATE_ATTACK;
            }
         }
         //the biggest peak
         item->suspision_response_other->state_response_size[max] = STATE_ATTACK;
      }
   }
   if (item->state_response_other == STATE_NEW) {
       check_and_delete_suspision(item, RESPONSE_PART_OTHER);
      return STATE_NEW;
   }
   return STATE_SUSPICION;
}

int is_payload_on_ip_ok_request_other(ip_address_t * item)
{
   prefix_tree_t *tree;
      //other anomaly detection request
      if (item->suspision_request_other != NULL && item->suspision_request_other->other_suspision != NULL) {
        if (item->state_request_other == STATE_ATTACK) {
         //anomaly state
            tree = item->suspision_request_other->other_suspision;
            if (tree->count_of_inserting > values.min_dns_request_count_other_anomaly &&
               (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
               (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_unique_domains   //percent of unique domains
            ) {
               item->suspision_request_other->round_in_suspicion=0;
               #ifdef DEBUG
                  printf("CONTINUOUS REQUEST OTHER ANOMALY\n");
               #endif /*DEBUG*/
            }
            else {
              //maximum round in suspicion
               item->suspision_request_other->round_in_suspicion++;
               #ifdef DEBUG
                  printf("NOT PROVED REQUEST OTHER ANOMALY\n");
               #endif /*DEBUG*/
               if (item->suspision_request_other->round_in_suspicion >  values.max_count_of_round_in_attack) {
                  check_and_delete_suspision(item, REQUEST_PART_OTHER);
                  item->state_request_other = STATE_NEW;
                  #ifdef DEBUG
                     printf("END OF REQUEST OTHER ANOMALY\n");
                  #endif /*DEBUG*/
               }
            }
        }
        else
        {
         //suspicin state
            tree = item->suspision_request_other->other_suspision;
            if (tree->count_of_inserting > values.min_dns_request_count_other_anomaly &&
               (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
               (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_unique_domains   //percent of unique domains
            ) {
               item->state_request_other = STATE_ATTACK;
               item->suspision_request_other->event_id = get_event_id();
               item->print |= REQUEST_PART_OTHER;
               item->suspision_request_other->round_in_suspicion = 0;
               #ifdef DEBUG
                  printf("START OF REQUEST OTHER ANOMALY\n");
               #endif /*DEBUG*/
            }
            else {
               //if there wasnt any payload problem
               item->suspision_request_other->round_in_suspicion++;
              //maximum round in suspicion
              if (item->suspision_request_other->round_in_suspicion > values.max_count_of_round_in_suspiction) {
                 //item->suspision_request_tunnel->round_in_suspicion = 0;
                 check_and_delete_suspision(item, REQUEST_PART_OTHER);
                 item->state_request_other = STATE_NEW;
              }
            }
         }
      }
   if (item->state_request_other == STATE_NEW) {
      return STATE_NEW;
   }
   return STATE_SUSPICION;
}

int is_payload_on_ip_ok_response_other(ip_address_t * item)
{
   prefix_tree_t *tree;
   //other anomaly detection response
   if (item->suspision_response_other != NULL && item->suspision_response_other->other_suspision != NULL ) {
      if (item->state_response_other == STATE_ATTACK) {
         tree = item->suspision_response_other->other_suspision;
         if (tree->count_of_inserting > values.min_dns_response_count_other_anomaly &&
            (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
            (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_unique_domains   //percent of unique domains
         ) {
            item->suspision_response_other->round_in_suspicion = 0;
            #ifdef DEBUG
               printf("CONTINUOUS REESPONSE OTHER ANOMALY\n");
            #endif /*DEBUG*/
         }
         else if ((double)item->suspision_response_other->without_string / (double)item->suspision_response_other->packet_in_suspicion > values.max_percent_of_mallformed_packet_request) {
            item->suspision_response_other->round_in_suspicion = 0;
            #ifdef DEBUG
               printf("CONTINUOUS REESPONSE OTHER ANOMALY\n");
            #endif /*DEBUG*/
         }
         else {
            //if there wasnt any payload problem
           item->suspision_response_other->round_in_suspicion++;
            #ifdef DEBUG
               printf("NOT PROVED RESPONSE OTHER ANOMALY\n");
            #endif /*DEBUG*/
           //maximum round in suspicion
           if (item->suspision_response_other->round_in_suspicion > values.max_count_of_round_in_attack) {
              check_and_delete_suspision(item, RESPONSE_PART_OTHER);
              item->state_response_other = STATE_NEW;
               #ifdef DEBUG
                  printf("END OF RESPONSE OTHER ANOMALY\n");
               #endif /*DEBUG*/
           }
         }
      }
      else {
         tree = item->suspision_response_other->other_suspision;
         if (tree->count_of_inserting > values.min_dns_response_count_other_anomaly &&
            (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
            (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_unique_domains   //percent of unique domains
         ) {
            item->state_response_other = STATE_ATTACK;
            item->suspision_response_other->event_id = get_event_id();
            item->suspision_response_other->round_in_suspicion = 0;
            item->print |= RESPONSE_PART_OTHER;
            #ifdef DEBUG
               printf("START OF RESPONSE OTHER ANOMALY\n");
            #endif /*DEBUG*/
         }
         // else if ((double)item->suspision_response_other->without_string / (double)item->suspision_response_other->packet_in_suspicion > values.max_percent_of_mallformed_packet_request) {
         //    item->state_response_other = STATE_ATTACK;
         //    item->suspision_response_other->event_id = get_event_id();
         //    item->print |= RESPONSE_PART_OTHER;
         //    item->suspision_response_other->round_in_suspicion = 0;
         // }
         else {
            //if there wasnt any payload problem
           item->suspision_response_other->round_in_suspicion++;
           //maximum round in suspicion
           if (item->suspision_response_other->round_in_suspicion > values.max_count_of_round_in_suspiction) {
              //item->suspision_response_tunnel->round_in_suspicion = 0;
              check_and_delete_suspision(item, RESPONSE_PART_OTHER);
              item->state_response_other = STATE_NEW;
           }
         }
      }
   }
   if (item->state_response_other == STATE_NEW) {
      return STATE_NEW;
   }
   return STATE_SUSPICION;
}

int is_payload_on_ip_ok_request_tunnel(ip_address_t * item)
{
   prefix_tree_t *tree;
   //tunnel detection request
   if (item->suspision_request_tunnel != NULL && item->suspision_request_tunnel->tunnel_suspision != NULL) {
       if ((item->state_request_tunnel == STATE_ATTACK) ) {
      //attack state
         tree = item->suspision_request_tunnel->tunnel_suspision;
         //percent of count of subdomains, is bigger than x percent
         if (/*tree->count_of_inserting > values.min_dns_request_count_tunnel &&*/
             (
             (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
             (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_unique_domains   //percent of unique domains
             )) {  //percent of unique search
             item->suspision_request_tunnel->round_in_suspicion = 0;
            #ifdef DEBUG
               printf("CONTINUOUS REQUEST TUNNEL\n");
            #endif /*DEBUG*/
         }
         //if there wasnt any problem
         else {
               //maximum round in suspicion
               item->suspision_request_tunnel->round_in_suspicion++;
               #ifdef DEBUG
                  printf("NOT PROVED REQUEST TUNNEL\n");
                  printf("Count of inserting: %d\n", tree->count_of_inserting);
                  printf("Percent of domain searched just once: %f\n", (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones));
                  printf("Max percent of subdomains: %f\n", prefix_tree_most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION));
               #endif /*DEBUG*/
               if (item->suspision_request_tunnel->round_in_suspicion > values.max_count_of_round_in_suspiction) {
                 check_and_delete_suspision(item, REQUEST_PART_TUNNEL);
                 item->state_request_tunnel = STATE_NEW;
               #ifdef DEBUG
                  printf("END OF REQUEST TUNNEL\n");
               #endif /*DEBUG*/
               }
          }
      }
      else {
      //suspision state
         tree = item->suspision_request_tunnel->tunnel_suspision;
         //percent of count of subdomains, is bigger than x percent
         if (tree->count_of_inserting > values.min_dns_request_count_tunnel &&
             ((
             (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
             (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_unique_domains   //percent of unique domains
             )&&
             (prefix_tree_most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION) > values.max_percent_of_subdomains_in_main_domain)
             )) {  //percent of unique search
             item->state_request_tunnel = STATE_ATTACK;
             item->suspision_request_tunnel->event_id = get_event_id();
             item->print |= REQUEST_PART_TUNNEL;
             item->suspision_request_tunnel->round_in_suspicion = 0;
            #ifdef DEBUG
               printf("START OF REQUEST TUNNEL\n");
            #endif /*DEBUG*/
         }
          else if (tree->count_of_inserting > values.min_dns_request_count_tunnel_closer &&
              ((
              (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_domain_searching_just_once_closer &&      //percent of searching unique domains
              (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_unique_domains_closer   //percent of unique domains
              )
              )) {
            char buff[1000];
               prefix_tree_domain_t *dom = item->suspision_request_tunnel->tunnel_suspision->domain_extension->list_of_most_unused_domains;
            if (dom != NULL) {
               prefix_tree_read_string(item->suspision_request_tunnel->tunnel_suspision, dom, buff);
            }
            if (strlen(buff) > values.request_max_count_of_used_letters_closer) {
               item->state_request_tunnel = STATE_ATTACK;
               item->suspision_request_tunnel->event_id = get_event_id();
               item->print |= REQUEST_PART_TUNNEL;
               item->suspision_request_tunnel->round_in_suspicion = 0;
                #ifdef DEBUG
                   printf("START OF REQUEST TUNNEL\n");
                #endif /*DEBUG*/
            }
         }
         //if there wasnt any problem
           else {
              #ifdef DEBUG
                 printf("NOT PRUVED ANOMALY\n");
                 char buff[1000];
              prefix_tree_domain_t *dom = item->suspision_request_tunnel->tunnel_suspision->domain_extension->list_of_most_unused_domains;
               if (dom != NULL) {
                  prefix_tree_read_string(item->suspision_request_tunnel->tunnel_suspision, dom, buff);
               }
                 printf("domain %s\tcount %d,  \t max_percent_of_domain_searching_just_once: %f, \t max_percent_of_unique_domains: %f, \t max_percent_of_subdomains_in_main_domain: %f\n", buff,tree->count_of_inserting, (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones), (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones), (prefix_tree_most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION)));
             #endif /*DEBUG*/
              item->suspision_request_tunnel->round_in_suspicion++;
              //maximum round in suspicion
              if (item->suspision_request_tunnel->round_in_suspicion > values.max_count_of_round_in_attack) {
                 check_and_delete_suspision(item, REQUEST_PART_TUNNEL);
                 item->state_request_tunnel = STATE_NEW;
              }
          }
        }
   }
   if (item->state_request_tunnel == STATE_NEW) {
      return STATE_NEW;
   }
   return STATE_SUSPICION;
}

int is_payload_on_ip_ok_response_tunnel(ip_address_t * item)
{
   prefix_tree_t *tree;
   //tunnel detection response
   if (item->state_response_tunnel != STATE_NEW) {
      tree = item->suspision_response_tunnel->request_suspision;
      //percent of count of subdomains, is bigger than x percent
      if (tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ) {  //percent of unique search
         if (!(item->suspision_response_tunnel->state_type & REQUEST_STRING_TUNNEL)) {
            item->print |= RESPONSE_PART_TUNNEL;
            item->state_response_tunnel = STATE_ATTACK;
            item->suspision_response_tunnel->event_id_request = get_event_id();
            item->suspision_response_tunnel->state_type |= REQUEST_STRING_TUNNEL;
         }
      }
      else if (item->suspision_response_tunnel->state_type & REQUEST_STRING_TUNNEL) {
         item->suspision_response_tunnel->state_type &= ~REQUEST_STRING_TUNNEL;
         prefix_tree_destroy(tree);
         item->suspision_response_tunnel->request_suspision = NULL;
      }
      tree = item->suspision_response_tunnel->txt_suspision;
      //percent of count of subdomains, is bigger than x percent
      if (tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ) {  //percent of unique search
         if (!(item->suspision_response_tunnel->state_type & TXT_TUNNEL)) {
            item->suspision_response_tunnel->round_in_suspicion = 0;
            item->state_response_tunnel = STATE_ATTACK;
            item->suspision_response_tunnel->event_id_txt = get_event_id();
            item->print |= RESPONSE_PART_TUNNEL;
            item->suspision_response_tunnel->state_type |= TXT_TUNNEL;
         }
      }
      else if (tree != NULL && item->suspision_response_tunnel->state_type & TXT_TUNNEL) {
         item->suspision_response_tunnel->state_type &= ~TXT_TUNNEL;
         prefix_tree_destroy(tree);
         item->suspision_response_tunnel->txt_suspision = NULL;
      }
      tree = item->suspision_response_tunnel->mx_suspision;
      //percent of count of subdomains, is bigger than x percent
      if (tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ) {  //percent of unique search
         if (!(item->suspision_response_tunnel->state_type & MX_TUNNEL)) {
            item->suspision_response_tunnel->round_in_suspicion = 0;
            item->state_response_tunnel = STATE_ATTACK;
            item->suspision_response_tunnel->event_id_mx = get_event_id();
            item->print |= RESPONSE_PART_TUNNEL;
            item->suspision_response_tunnel->state_type |= MX_TUNNEL;
         }
      }
      else if (tree != NULL && item->suspision_response_tunnel->state_type & MX_TUNNEL) {
         item->suspision_response_tunnel->state_type &= ~MX_TUNNEL;
         prefix_tree_destroy(tree);
         item->suspision_response_tunnel->mx_suspision = NULL;

      }
      tree = item->suspision_response_tunnel->cname_suspision;
      //percent of count of subdomains, is bigger than x percent
      if (tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ) {  //percent of unique search
         if (!(item->suspision_response_tunnel->state_type & CNAME_TUNNEL)) {
            item->suspision_response_tunnel->round_in_suspicion = 0;
            item->state_response_tunnel = STATE_ATTACK;
            item->suspision_response_tunnel->event_id_cname = get_event_id();
            item->print |= RESPONSE_PART_TUNNEL;
            item->suspision_response_tunnel->state_type |= CNAME_TUNNEL;
         }
      }
      else if (tree != NULL && item->suspision_response_tunnel->state_type & CNAME_TUNNEL) {
         item->suspision_response_tunnel->state_type &= ~CNAME_TUNNEL;
         prefix_tree_destroy(tree);
         item->suspision_response_tunnel->cname_suspision = NULL;
      }
      tree = item->suspision_response_tunnel->ns_suspision;
      //percent of count of subdomains, is bigger than x percent
      if (tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ) {  //percent of unique search
         if (!(item->suspision_response_tunnel->state_type & NS_TUNNEL)) {
            item->suspision_response_tunnel->round_in_suspicion = 0;
            item->state_response_tunnel = STATE_ATTACK;
            item->suspision_response_tunnel->event_id_ns = get_event_id();
            item->print |= RESPONSE_PART_TUNNEL;
            item->suspision_response_tunnel->state_type |= NS_TUNNEL;
         }
      }
      else if (tree != NULL && item->suspision_response_tunnel->state_type & NS_TUNNEL) {
         item->suspision_response_tunnel->state_type &= ~NS_TUNNEL;
         prefix_tree_destroy(tree);
         item->suspision_response_tunnel->ns_suspision = NULL;
      }
      //if there wasnt any payload problem
      if (item->state_response_tunnel == STATE_SUSPICION) {
         item->suspision_response_tunnel->round_in_suspicion++;
         //maximum round in suspicion
         if (item->suspision_response_tunnel->round_in_suspicion > values.max_count_of_round_in_suspiction) {
            item->suspision_response_tunnel->round_in_suspicion = 0;
            check_and_delete_suspision(item, RESPONSE_PART_TUNNEL);
            item->state_response_tunnel = STATE_NEW;
         }
      } else if (item->suspision_response_tunnel->state_type == 0) {
         //anomaly is not present
         check_and_delete_suspision(item, RESPONSE_PART_TUNNEL);
         item->state_response_tunnel = STATE_NEW;
      }
   }
   if (item->state_response_tunnel == STATE_NEW) {
      return STATE_OK;
   }
   return STATE_SUSPICION;
}

int get_length_of_string(char * str) {
   int length = 0;
   if (str == NULL) {
      return 0;
   }
   while (*str != 0) {
      str++;
      length++;
   }
   length++;
   return length;
}

void send_unirec_out(unirec_tunnel_notification_t * notification)
{
   if (notification->unirec_out != NULL) {
      ur_set(notification->unirec_out, notification->detection, F_EVENT_ID, notification->event_id);
      ur_set(notification->unirec_out, notification->detection, F_SRC_IP, notification->ip);
      ur_set(notification->unirec_out, notification->detection, F_TUNNEL_PER_NEW_DOMAIN, notification->tunnel_per_new_domain);
      ur_set(notification->unirec_out, notification->detection, F_TUNNEL_PER_SUBDOMAIN, notification->tunnel_per_subdomain);
      ur_set(notification->unirec_out, notification->detection, F_TUNNEL_TYPE, notification->tunnel_type);
      ur_set_string(notification->unirec_out, notification->detection, F_TUNNEL_DOMAIN, notification->tunnel_domain);
      ur_set(notification->unirec_out, notification->detection, F_TUNNEL_CNT_PACKET, notification->tunnel_cnt_packet);
      ur_set(notification->unirec_out, notification->detection, F_TIME_FIRST, ur_time_from_sec_msec(notification->time_first,0));
      ur_set(notification->unirec_out, notification->detection, F_TIME_LAST, ur_time_from_sec_msec(notification->time_last,0));
      trap_send(0, notification->detection, ur_rec_size(notification->unirec_out, notification->detection));
   }
}

void send_unirec_out_sdm(unirec_tunnel_notification_t * notification)
{
   if (notification->unirec_out_sdm != NULL) {
      char sdm_capture_id [MAX_LENGTH_SDM_CAPTURE_FILE_ID];
      sprintf(sdm_capture_id , "tunnel_detection_%d", notification->event_id);
      ur_set(notification->unirec_out_sdm, notification->detection_sdm, F_SRC_IP, notification->ip);
      ur_set(notification->unirec_out_sdm, notification->detection_sdm, F_TIMEOUT, values.sdm_timeout);
      ur_set(notification->unirec_out_sdm, notification->detection_sdm, F_PACKETS, values.sdm_count_of_packets);
      ur_set_string(notification->unirec_out_sdm, notification->detection_sdm, F_SDM_CAPTURE_FILE_ID, sdm_capture_id);
      trap_send(1, notification->detection_sdm, ur_rec_size(notification->unirec_out_sdm, notification->detection_sdm));
   }
}

void calculate_statistic_and_choose_anomaly(void * b_plus_tree, FILE *file, unirec_tunnel_notification_t * ur_notification)
{
   ip_address_t * item;
   ip_addr_t ip_address;
   char ip_address_str [100];
   b_plus_tree_item * b_item;
   int is_there_next = 0, print_time = 1;
   calulated_result_t result;
   b_item = b_plus_tree_create_list_item(b_plus_tree);
   is_there_next = b_plus_tree_get_list(b_plus_tree, b_item);

   while (is_there_next == 1) {
      item = (ip_address_t*)b_item->value;
      calculate_statistic(item, &result);
      #ifdef DEBUG
         if (item->state_request_other == STATE_ATTACK || item->state_request_tunnel == STATE_ATTACK || item->state_response_tunnel == STATE_ATTACK || item->state_response_other == STATE_ATTACK) {
            get_ip_str_from_ip_struct(item, b_item->key, ip_address_str);
            printf("IP: %s\n", ip_address_str);
         }
      #endif /*DEBUG*/
      //request other anomaly
      if (item->state_request_other == STATE_NEW) {
         is_traffic_on_ip_ok_request_other(item, &result);
      } else {
         is_payload_on_ip_ok_request_other(item);
      }
      //request tunnel anomaly
      if (item->state_request_tunnel == STATE_NEW) {
         is_traffic_on_ip_ok_request_tunnel(item, &result);
      }
      else {
         is_payload_on_ip_ok_request_tunnel(item);
      }
      //response payload, tunnel anomaly
      if (item->state_response_tunnel == STATE_SUSPICION || item->state_response_tunnel == STATE_ATTACK) {
        is_payload_on_ip_ok_response_tunnel(item);
      }
      //response traffic, other anomaly
      if (item->state_response_other == STATE_NEW) {
        is_traffic_on_ip_ok_response_other(item, &result);
      }
      else {
         is_payload_on_ip_ok_response_other(item);
      }
      //send alerts of anomalies in ATTACK STATE
      if (item->state_request_other == STATE_ATTACK || item->state_request_tunnel == STATE_ATTACK || item->state_response_tunnel == STATE_ATTACK || item->state_response_other == STATE_ATTACK) {
         ip_address = get_ip_addr_t_from_ip_struct(item, b_item->key);
         //print new anomaly
         if (item->print & 0b11111111 && file != NULL) {
            //translate ip int to str
            ip_to_str(&(ip_address) ,ip_address_str);
            print_founded_anomaly_immediately(ip_address_str, item, file, print_time);
            print_time = 0;
            item->print=0;
            fflush(file);
         }
         send_unirec_alert_and_reset_records(&ip_address, item, ur_notification);
      }
      if (item->sdm_exported == SDM_EXPORTED_FALSE) {
            send_unirec_alert_to_sdm(&ip_address, item, ur_notification);
      }
      //check if it can be deleted
      if (item->state_request_other == STATE_NEW && item->state_request_tunnel == STATE_NEW && item->state_response_other == STATE_NEW && item->state_response_tunnel == STATE_NEW) {
         is_there_next = b_plus_tree_delete_item_from_list(b_plus_tree, b_item);
      #ifdef TIME
         delete_from_blus++;
      #endif /*TIME*/
      }
      else {
         //with anomaly, in can not be deleted
         is_there_next = b_plus_tree_get_next_item_from_list(b_plus_tree, b_item);
      }
   }
   b_plus_tree_destroy_list_item(b_item);
}

void send_unirec_alert_to_sdm(ip_addr_t * ip_address, ip_address_t *item, unirec_tunnel_notification_t * unirec_out)
{
   if (unirec_out == NULL) {
      return;
   }
   if ((item->suspision_request_tunnel && item->state_request_tunnel == STATE_ATTACK && item->suspision_request_tunnel->round_in_suspicion == 0) &&
    (item->suspision_response_tunnel && item->state_response_tunnel == STATE_ATTACK && item->suspision_response_tunnel->round_in_suspicion == 0)) {
      unirec_out->ip = *ip_address;
      unirec_out->event_id = item->suspision_request_tunnel->event_id;
      item->sdm_exported = SDM_EXPORTED_TRUE;
      send_unirec_out_sdm(unirec_out);
   }
}


void send_unirec_alert_and_reset_records(ip_addr_t * ip_address, ip_address_t *item, unirec_tunnel_notification_t * unirec_out) {
   prefix_tree_domain_t * dom;
   if (unirec_out == NULL) {
      return;
   }
   unirec_out->ip = *ip_address;

   //request tunnel
   if (item->suspision_request_tunnel && item->state_request_tunnel == STATE_ATTACK && item->suspision_request_tunnel->round_in_suspicion == 0) {
      unirec_out->event_id = item->suspision_request_tunnel->event_id;
      unirec_out->tunnel_per_new_domain = (double)(item->suspision_request_tunnel->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones);
      unirec_out->tunnel_per_subdomain =  prefix_tree_most_used_domain_percent_of_subdomains(item->suspision_request_tunnel->tunnel_suspision, DEPTH_TUNNEL_SUSPICTION);
      unirec_out->tunnel_cnt_packet = item->suspision_request_tunnel->sum_of_inserting;
      dom = item->suspision_request_tunnel->tunnel_suspision->domain_extension->list_of_most_unused_domains;
      if (dom != NULL) {
         prefix_tree_read_string(item->suspision_request_tunnel->tunnel_suspision, dom, unirec_out->tunnel_domain);
      }
      else {
         unirec_out->tunnel_domain[0] = 0;
      }
      unirec_out->tunnel_type = TUN_T_REQUEST_TUNNEL;
      unirec_out->time_first = item->suspision_request_tunnel->time_first;
      unirec_out->time_last = item->time_last;
      send_unirec_out(unirec_out);
      prefix_tree_destroy(item->suspision_request_tunnel->tunnel_suspision);
      item->suspision_request_tunnel->tunnel_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
   }
   //Request other anomaly
   if (item->suspision_request_other && item->state_request_other == STATE_ATTACK && item->suspision_request_other->round_in_suspicion == 0) {
      unirec_out->event_id = item->suspision_request_other->event_id;
      unirec_out->tunnel_per_new_domain = (double)(item->suspision_request_other->other_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones);
      unirec_out->tunnel_per_subdomain =  (double)item->suspision_request_other->other_suspision->count_of_different_domains/(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones);
      unirec_out->tunnel_cnt_packet = item->suspision_request_other->sum_of_inserting;
      dom = item->suspision_request_other->other_suspision->domain_extension->list_of_most_used_domains;
      if (dom != NULL) {
         prefix_tree_read_string(item->suspision_request_other->other_suspision, dom, unirec_out->tunnel_domain);
      }
      else {
         unirec_out->tunnel_domain[0] = 0;
      }
      unirec_out->tunnel_type = TUN_T_REQUEST_OTHER;
      unirec_out->time_first = item->suspision_request_other->time_first;
      unirec_out->time_last = item->time_last;
      send_unirec_out(unirec_out);
      //reset
      item->counter_request.request_without_string = 0;
      prefix_tree_destroy(item->suspision_request_other->other_suspision);
      item->suspision_request_other->other_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
   }
   //response tunnel
   if (item->suspision_response_tunnel && item->state_response_tunnel == STATE_ATTACK && item->suspision_response_tunnel->round_in_suspicion == 0) {
      //response-request string tunnel
      if (item->suspision_response_tunnel->state_type & REQUEST_STRING_TUNNEL) {
         unirec_out->event_id = item->suspision_response_tunnel->event_id_request;
         unirec_out->tunnel_per_new_domain = (double)(item->suspision_response_tunnel->request_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_per_subdomain =  (double)item->suspision_response_tunnel->request_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_cnt_packet = item->suspision_response_tunnel->sum_of_inserting_request;
         dom = item->suspision_response_tunnel->request_suspision->domain_extension->list_of_most_unused_domains;
         if (dom != NULL) {
            prefix_tree_read_string(item->suspision_response_tunnel->request_suspision, dom, unirec_out->tunnel_domain);
         }
         else {
            unirec_out->tunnel_domain[0] = 0;
         }
         unirec_out->tunnel_type = TUN_T_RESPONSE_TUNNEL_REQ;
         unirec_out->time_first = item->suspision_response_tunnel->request_suspision_time_first;
         unirec_out->time_last = item->time_last;
         send_unirec_out(unirec_out);
         prefix_tree_destroy(item->suspision_response_tunnel->request_suspision);
         item->suspision_response_tunnel->request_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      }
      //txt
      if (item->suspision_response_tunnel->state_type & TXT_TUNNEL) {
         unirec_out->event_id = item->suspision_response_tunnel->event_id_txt;
         unirec_out->tunnel_per_new_domain = (double)(item->suspision_response_tunnel->txt_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_per_subdomain =  (double)item->suspision_response_tunnel->txt_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_cnt_packet = item->suspision_response_tunnel->sum_of_inserting_txt;
         dom =item->suspision_response_tunnel->txt_suspision->domain_extension->list_of_most_unused_domains;
         if (dom != NULL) {
            prefix_tree_read_string(item->suspision_response_tunnel->txt_suspision, dom, unirec_out->tunnel_domain);
         }
         else {
            unirec_out->tunnel_domain[0] = 0;
         }
         unirec_out->tunnel_type = TUN_T_RESPONSE_TUNNEL_TXT;
         unirec_out->time_first = item->suspision_response_tunnel->txt_suspision_time_first;
         unirec_out->time_last = item->time_last;
         send_unirec_out(unirec_out);
         prefix_tree_destroy(item->suspision_response_tunnel->txt_suspision);
         item->suspision_response_tunnel->txt_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      }
      if (item->suspision_response_tunnel->state_type & CNAME_TUNNEL) {
         unirec_out->event_id = item->suspision_response_tunnel->event_id_cname;
         unirec_out->tunnel_per_new_domain = (double)(item->suspision_response_tunnel->cname_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_per_subdomain =  (double)item->suspision_response_tunnel->cname_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_cnt_packet = item->suspision_response_tunnel->sum_of_inserting_cname;
         dom =item->suspision_response_tunnel->cname_suspision->domain_extension->list_of_most_unused_domains;
         if (dom != NULL) {
            prefix_tree_read_string(item->suspision_response_tunnel->cname_suspision, dom, unirec_out->tunnel_domain);
         }
         else {
            unirec_out->tunnel_domain[0] = 0;
         }
         unirec_out->tunnel_type = TUN_T_RESPONSE_TUNNEL_CNAME;
         unirec_out->time_first = item->suspision_response_tunnel->cname_suspision_time_first;
         unirec_out->time_last = item->time_last;
         send_unirec_out(unirec_out);
         prefix_tree_destroy(item->suspision_response_tunnel->cname_suspision);
         item->suspision_response_tunnel->cname_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      }
      if (item->suspision_response_tunnel->state_type & NS_TUNNEL) {
         unirec_out->event_id = item->suspision_response_tunnel->event_id_ns;
         unirec_out->tunnel_per_new_domain = (double)(item->suspision_response_tunnel->ns_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_per_subdomain =  (double)item->suspision_response_tunnel->ns_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_cnt_packet = item->suspision_response_tunnel->sum_of_inserting_ns;
         dom =item->suspision_response_tunnel->ns_suspision->domain_extension->list_of_most_unused_domains;
         if (dom != NULL) {
            prefix_tree_read_string(item->suspision_response_tunnel->ns_suspision, dom, unirec_out->tunnel_domain);
         }
         else {
            unirec_out->tunnel_domain[0] = 0;
         }
         unirec_out->tunnel_type = TUN_T_RESPONSE_TUNNEL_NS;
         unirec_out->time_first = item->suspision_response_tunnel->ns_suspision_time_first;
         unirec_out->time_last = item->time_last;
         send_unirec_out(unirec_out);
         prefix_tree_destroy(item->suspision_response_tunnel->ns_suspision);
         item->suspision_response_tunnel->ns_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      }
      if (item->suspision_response_tunnel->state_type & MX_TUNNEL) {
         unirec_out->event_id = item->suspision_response_tunnel->event_id_mx;
         unirec_out->tunnel_per_new_domain = (double)(item->suspision_response_tunnel->mx_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_per_subdomain =  (double)item->suspision_response_tunnel->mx_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones);
         unirec_out->tunnel_cnt_packet = item->suspision_response_tunnel->sum_of_inserting_mx;
         dom =item->suspision_response_tunnel->mx_suspision->domain_extension->list_of_most_unused_domains;
         if (dom != NULL) {
            prefix_tree_read_string(item->suspision_response_tunnel->mx_suspision, dom, unirec_out->tunnel_domain);
         }
         else {
            unirec_out->tunnel_domain[0] = 0;
         }
         unirec_out->tunnel_type = TUN_T_RESPONSE_TUNNEL_MX;
         unirec_out->time_first = item->suspision_response_tunnel->mx_suspision_time_first;
         unirec_out->time_last = item->time_last;
         send_unirec_out(unirec_out);
         prefix_tree_destroy(item->suspision_response_tunnel->mx_suspision);
         item->suspision_response_tunnel->mx_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      }
   }
   if (item->suspision_response_other && item->state_response_other == STATE_ATTACK && item->suspision_response_other->round_in_suspicion == 0) {
      unirec_out->event_id = item->suspision_response_other->event_id;
      unirec_out->tunnel_per_new_domain = 0;
      unirec_out->tunnel_per_subdomain =  0;
      unirec_out->tunnel_cnt_packet = item->suspision_response_other->sum_of_inserting;
      dom =item->suspision_response_other->other_suspision->domain_extension->list_of_most_used_domains;
      if (dom != NULL) {
         prefix_tree_read_string(item->suspision_response_other->other_suspision, dom, unirec_out->tunnel_domain);
      }
      else {
         unirec_out->tunnel_domain[0] = 0;
      }
      unirec_out->tunnel_type = TUN_T_RESPONSE_OTHER;
      unirec_out->time_first = item->suspision_response_other->time_first;
      unirec_out->time_last = item->time_last;
      send_unirec_out(unirec_out);
      prefix_tree_destroy(item->suspision_response_other->other_suspision);
      item->suspision_response_other->other_suspision = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
   }
}

void print_founded_anomaly_immediately(char * ip_address, ip_address_t *item, FILE *file, unsigned char print_time)
{
   if (print_time) {
      time_t mytime;
      mytime = time(NULL);
      fprintf(file, "\nTIME: %s\n", ctime(&mytime));
   }
   prefix_tree_domain_t *dom;
   char str[1024];
   if (item->print & 0b11111111) {
      //ip address contaion anomaly
      fprintf(file, "\n%s\n", ip_address);
      //print found anomaly tunnel
      if (item->state_request_tunnel == STATE_ATTACK && item->print & REQUEST_PART_TUNNEL) {
         fprintf(file, "%u\tRequest tunnel found:\tDomains searched just once: %f.\tcount of different domains: %f.\tPercent of subdomain in most used domain %f.\tAll recorded requests: %d\n", item->suspision_request_tunnel->event_id, (double)(item->suspision_request_tunnel->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_tunnel->tunnel_suspision->count_of_different_domains/(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), prefix_tree_most_used_domain_percent_of_subdomains(item->suspision_request_tunnel->tunnel_suspision, DEPTH_TUNNEL_SUSPICTION) ,(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting) );
         dom =item->suspision_request_tunnel->tunnel_suspision->domain_extension->list_of_most_unused_domains;
         for (int i=0; i<5;i++) {
            str[0]=0;
            if (dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_request_tunnel->tunnel_suspision ,dom, str), dom->count_of_insert);
            dom= dom->domain_extension->most_used_domain_less;
         }
      }
      //print founded anomaly other in request
      if (item->state_request_other == STATE_ATTACK && item->print & REQUEST_PART_OTHER) {
         if (item->suspision_request_other != NULL) {
            fprintf(file, "%u\tRequest traffic anomaly found:\tDomains searched just once: %f.\tCount of different domains: %f.\tAll recorded requests: %d.\tCount of malformed requests: %d.\n\t\tFound in sizes: ", item->suspision_request_other->event_id, (double)(item->suspision_request_other->other_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_other->other_suspision->count_of_different_domains/(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones),(item->suspision_request_other->other_suspision->count_of_inserting), item->counter_request.request_without_string  );
            for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++) {
               if (item->suspision_request_other->state_request_size[i] & STATE_ATTACK)
               fprintf(file, "%d-%d\t", i*10,i*10+10);
            }
            fprintf(file, "\n");
            dom =item->suspision_request_other->other_suspision->domain_extension->list_of_most_used_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_request_other->other_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         else {
            fprintf(file, "\tMallformed packets found:\tCount of malformed responses: %u.\n", item->counter_request.request_without_string);
         }
      }
      //response tunnel
      if (item->state_response_tunnel == STATE_ATTACK && item->print & RESPONSE_PART_TUNNEL) {
         if (item->suspision_response_tunnel->state_type & REQUEST_STRING_TUNNEL) {
            fprintf(file, "%u\tReponse tunnel found by request strings :\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", item->suspision_response_tunnel->event_id_request, (double)(item->suspision_response_tunnel->request_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->request_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->request_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->request_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->request_suspision ,dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //txt
         if (item->suspision_response_tunnel->state_type & TXT_TUNNEL) {
            fprintf(file, "%u\tReponse TXT tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", item->suspision_response_tunnel->event_id_request, (double)(item->suspision_response_tunnel->txt_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->txt_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->txt_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->txt_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->txt_suspision ,dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //cname
         if (item->suspision_response_tunnel->state_type & CNAME_TUNNEL) {
            fprintf(file, "%u\tReponse CNAME tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", item->suspision_response_tunnel->event_id_txt, (double)(item->suspision_response_tunnel->cname_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->cname_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->cname_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->cname_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->cname_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //ns
         if (item->suspision_response_tunnel->state_type & NS_TUNNEL) {
            fprintf(file, "%u\tReponse NS tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", item->suspision_response_tunnel->event_id_cname, (double)(item->suspision_response_tunnel->ns_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->ns_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->ns_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->ns_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->ns_suspision ,dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //mx
         if (item->suspision_response_tunnel->state_type & MX_TUNNEL) {
            fprintf(file, "%u\tReponse MX tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", item->suspision_response_tunnel->event_id_ns, (double)(item->suspision_response_tunnel->mx_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->mx_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->mx_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->mx_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->mx_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
      }
      //print founded anomaly other in responses
      if (item->state_response_other == STATE_ATTACK && item->print & RESPONSE_PART_OTHER) {
         calulated_result_t result;
         calculate_statistic(item, &result);
         fprintf(file, "%u\tReseponse anomaly found:\tEX: %f.\tVAR: %f. \tPercent without request string %f. \tCount of responses %lu.\n", item->suspision_response_other->event_id, result.ex_response, result.var_response, (double)item->suspision_response_other->without_string / (double)item->suspision_response_other->packet_in_suspicion ,item->counter_response.dns_response_count);
         dom =item->suspision_response_other->other_suspision->domain_extension->list_of_most_used_domains;
         for (int i=0; i<5;i++) {
            str[0]=0;
            if (dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_other->other_suspision, dom, str), dom->count_of_insert);
            dom= dom->domain_extension->most_used_domain_less;
         }
      }
      item->print = 0;
    }
}

void print_founded_anomaly(char * ip_address, ip_address_t *item, FILE *file)
{
   prefix_tree_domain_t *dom;
   char str[1024];

   if (item->state_request_other == STATE_ATTACK || item->state_request_tunnel == STATE_ATTACK || item->state_response_other == STATE_ATTACK || item->state_request_tunnel == STATE_ATTACK) {
      fprintf(file, "\n%s\n", ip_address);
      //print found anomaly tunnel
      if (item->state_request_tunnel == STATE_ATTACK) {
         fprintf(file, "\tRequest tunnel found:\tDomains searched just once: %f.\tcount of different domains: %f.\tPercent of subdomain in most used domain %f.\tAll recorded requests: %d\n", (double)(item->suspision_request_tunnel->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_tunnel->tunnel_suspision->count_of_different_domains/(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), prefix_tree_most_used_domain_percent_of_subdomains(item->suspision_request_tunnel->tunnel_suspision, DEPTH_TUNNEL_SUSPICTION) ,(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting) );

         dom =item->suspision_request_tunnel->tunnel_suspision->domain_extension->list_of_most_unused_domains;
         for (int i=0; i<5;i++) {
            str[0]=0;
            if (dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_request_tunnel->tunnel_suspision, dom, str), dom->count_of_insert);
            dom= dom->domain_extension->most_used_domain_less;
         }
      }
      //print founded anomaly other in request
      if (item->state_request_other == STATE_ATTACK) {
         if (item->suspision_request_other != NULL) {
            fprintf(file, "\tRequest traffic anomaly found:\tDomains searched just once: %f.\tCount of different domains: %f.\tAll recorded requests: %d.\tCount of malformed requests: %d.\n\t\tFound in sizes: ", (double)(item->suspision_request_other->other_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_other->other_suspision->count_of_different_domains/(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones),(item->suspision_request_other->other_suspision->count_of_inserting), item->counter_request.request_without_string  );
            for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++) {
               if (item->suspision_request_other->state_request_size[i] & STATE_ATTACK)
               fprintf(file, "%d-%d\t", i*10,i*10+10);
            }
            fprintf(file, "\n");

            dom =item->suspision_request_other->other_suspision->domain_extension->list_of_most_used_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_request_other->other_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         else {
            fprintf(file, "\tMallformed packets found:\tCount of malformed responses: %d.\n", item->counter_request.request_without_string);
         }
      }
      //response tunnel
      if (item->state_response_tunnel == STATE_ATTACK) {
         if (item->suspision_response_tunnel->state_type & REQUEST_STRING_TUNNEL) {
            fprintf(file, "\tReponse tunnel found by request strings :\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->request_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->request_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->request_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->request_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->request_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //txt
         if (item->suspision_response_tunnel->state_type & TXT_TUNNEL) {
            fprintf(file, "\tReponse TXT tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->txt_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->txt_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->txt_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->txt_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->txt_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //cname
         if (item->suspision_response_tunnel->state_type & CNAME_TUNNEL) {
            fprintf(file, "\tReponse CNAME tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->cname_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->cname_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->cname_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->cname_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->cname_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //ns
         if (item->suspision_response_tunnel->state_type & NS_TUNNEL) {
            fprintf(file, "\tReponse NS tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->ns_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->ns_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->ns_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->ns_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->ns_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
         //mx
         if (item->suspision_response_tunnel->state_type & MX_TUNNEL) {
            fprintf(file, "\tReponse MX tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->mx_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->mx_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->mx_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->mx_suspision->domain_extension->list_of_most_unused_domains;
            for (int i=0; i<5;i++) {
               str[0]=0;
               if (dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_tunnel->mx_suspision, dom, str), dom->count_of_insert);
               dom= dom->domain_extension->most_used_domain_less;
            }
         }
      }
      //print founded anomaly other in responses
      if (item->state_response_other == STATE_ATTACK) {
         calulated_result_t result;
         calculate_statistic(item, &result);
         fprintf(file, "\tReseponse anomaly found:\tEX: %f.\tVAR: %f. \tPercent without request string %f. \tCount of responses %lu.\n", result.ex_response, result.var_response, (double)item->suspision_response_other->without_string / (double)item->suspision_response_other->packet_in_suspicion ,item->counter_response.dns_response_count);

         dom =item->suspision_response_other->other_suspision->domain_extension->list_of_most_used_domains;
         for (int i=0; i<5;i++) {
            str[0]=0;
            if (dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  prefix_tree_read_string(item->suspision_response_other->other_suspision, dom, str), dom->count_of_insert);
            dom= dom->domain_extension->most_used_domain_less;
         }
      }
   }
}

void print_suspision_ip(char *ip_address, ip_address_t *ip_item, FILE *file)
{
   if (ip_item->state_request_other == STATE_SUSPICION || ip_item->state_request_tunnel == STATE_SUSPICION || ip_item->state_response_other == STATE_SUSPICION || ip_item->state_request_tunnel == STATE_SUSPICION) {
      fprintf(file, "%s\n", ip_address);
   }
}


void write_summary_result(char * record_folder_name, unsigned long * histogram_dns_requests, unsigned long * histogram_dns_response)
{
   FILE *file;
   char file_path [255];
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_SUMMARY_REQUESTS);

//requests
   file = fopen(file_path, "w");
   //print title
   fprintf(file, TITLE_SUMMARY_REQUESTS "\n");
   //print range
   fprintf(file,  "ip\t");
   for (int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++) {
      fprintf(file, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);
   //print values
   fprintf(file, "all \t");
   for (int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++) {
      fprintf(file, "%lu\t",histogram_dns_requests[i]);
   }
   fprintf(file, "%lu\n", histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS -1]);
   fclose(file);

   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_SUMMARY_RESPONSES);

//responses
   file = fopen(file_path, "w");
   //print title
   fprintf(file, TITLE_SUMMARY_RESPONSES "\n");
   //print range
   fprintf(file,  "ip\t");
   for (int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++) {
      fprintf(file, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file, "%d-inf\n",(HISTOGRAM_SIZE_RESPONSE-1) * 10);
   //print values
   fprintf(file, "all \t");
   for (int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++) {
      fprintf(file, "%lu\t",histogram_dns_response[i]);
   }
   fprintf(file, "%lu\n", histogram_dns_response[HISTOGRAM_SIZE_RESPONSE -1]);
   fclose(file);

}


void print_histogram_values (char *ip_address, ip_address_t *ip_item, FILE *file_requests, FILE *file_responses, FILE *file_requests_count_letters)
{
   calulated_result_t result;
   //count statistic values
   calculate_statistic(ip_item, &result);
   //requests
   fprintf(file_requests, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_address, result.ex_request, result.var_request, result.skewness_request, result.kurtosis_request);
   for (int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++) {
      fprintf(file_requests, "%lu\t",ip_item->counter_request.histogram_dns_requests[i]);
   }
   fprintf(file_requests, "%lu\n", ip_item->counter_request.histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS - 1]);
   //requests count letter
   fprintf(file_requests_count_letters, "%s__EX=%f__VarX=%f\t", ip_address, result.ex_request_count_of_different_letters, result.var_request_count_letters);
   for (int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++) {
      fprintf(file_requests_count_letters, "%lu\t",result.histogram_dns_request_ex_cout_of_used_letter[i]);
   }
   fprintf(file_requests_count_letters, "%lu\n", result.histogram_dns_request_ex_cout_of_used_letter[HISTOGRAM_SIZE_REQUESTS - 1]);
   //response
   fprintf(file_responses, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_address, result.ex_response, result.var_response, result.skewness_response, result.kurtosis_response);
   for (int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++) {
      fprintf(file_responses, "%lu\t",ip_item->counter_response.histogram_dns_response[i]);
   }
   fprintf(file_responses, "%lu\n", ip_item->counter_response.histogram_dns_response[HISTOGRAM_SIZE_RESPONSE - 1]);
}

void write_detail_result(char * record_folder_name, void ** b_plus_tree, int count_of_btree)
{
   FILE *file_requests,
        *file_responses,
        *file_requests_count_letters,
        *file_suspision,
        *file_anomaly;
   char ip_buff[100] = {0};
   char file_path [255];
   int i;
   int is_there_next;
   b_plus_tree_item *b_item;
   ip_address_t *ip_item;
//requests
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUESTS);
   file_requests = fopen(file_path, "w");
   if (file_requests == NULL) {
      return;
   }
   //print titles
   fprintf(file_requests, TITLE_REQUESTS "\n");
   //print range to requests
   fprintf(file_requests,  "ip__EX__VarX__Skewness__Kurtosis\t");
   for (int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++) {

      fprintf(file_requests, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);

//responses
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_RESPONSES);
   file_responses = fopen(file_path, "w");
   if (file_responses == NULL) {
      return;
   }
   //print titles
   fprintf(file_responses, TITLE_RESPONSES "\n");
   //print range to respones
   fprintf(file_responses,  "ip__EX__VarX__Skewness__Kurtosis\t");
   for (int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++) {
      fprintf(file_responses, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_responses, "%d-inf\n",(HISTOGRAM_SIZE_RESPONSE-1) * 10);

//count letters
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUEST_COUNT_LETTERS);
   file_requests_count_letters = fopen(file_path, "w");
   if (file_requests_count_letters == NULL) {
      return;
   }
   //print titles
   fprintf(file_requests_count_letters, TITLE_REQUEST_COUNT_LETTERS "\n");
   //print range to requests count letter
   fprintf(file_requests_count_letters,  "ip__EX__VarX\t");
   for (int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++) {
      fprintf(file_requests_count_letters, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests_count_letters, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);

//found anomaly
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_FOUND_ANOMALY);
   file_anomaly = fopen(file_path, "w");
   if (file_anomaly == NULL) {
      return;
   }

//suspision list
   //open files
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_SUSPICION_LIST);
   file_suspision = fopen(file_path, "w");
   if (file_suspision == NULL) {
      return;
   }
   //print title
   fprintf(file_suspision, TITLE_SUSPICION_LIST "\n");

//print histogram of each IP
   //for each item in list
   for (i =0; i < count_of_btree; i++) {
      b_item = b_plus_tree_create_list_item(b_plus_tree[i]);
      is_there_next = b_plus_tree_get_list(b_plus_tree[i], b_item);
      while (is_there_next == 1) {
         //value from bplus item structure
         ip_item = (ip_address_t*)b_item->value;
         //translate ip int to str
         get_ip_str_from_ip_struct(ip_item, b_item->key, ip_buff);
         //print histogram values
         print_histogram_values(ip_buff, ip_item, file_requests, file_responses, file_requests_count_letters);
         //print fouded anomaly
         print_founded_anomaly(ip_buff, ip_item, file_anomaly);
         //print suspision
         print_suspision_ip(ip_buff, ip_item, file_suspision);
         //next item
         is_there_next = b_plus_tree_get_next_item_from_list(b_plus_tree[i], b_item);
      }
      b_plus_tree_destroy_list_item(b_item);
   }
   fclose(file_requests);
   fclose(file_requests_count_letters);
   fclose(file_responses);
   fclose(file_anomaly);
   fclose(file_suspision);
}

static inline int copy_string(char *dst, char *src, int size, int max_size_of_dst)
{
   if (size > max_size_of_dst-1) {
      size = max_size_of_dst-1;
   }
   memcpy(dst, src, size);
   dst[size] = 0;
   return size;
}

static inline void cut_max_domain(packet_t *packet)
{
   char * end_of_domain = END_OF_CUTTED_DOMAIN;
   while ((packet->request_length > 0 && packet->request_string[packet->request_length-1] != '.') || packet->request_length >= MAX_LENGTH_OF_REQUEST_DOMAIN - END_OF_CUTTED_DOMAIN_LENGTH -1) {
      packet->request_length--;
   }
   memcpy(packet->request_string + packet->request_length, end_of_domain, END_OF_CUTTED_DOMAIN_LENGTH);
   packet->request_length += END_OF_CUTTED_DOMAIN_LENGTH;
   packet->request_string[packet->request_length]=0;
}

int compare_ipv6(void * a, void * b)
{
   uint64_t *h1, *h2;
   h1 = (uint64_t*)a;
   h2 = (uint64_t*)b;
   if (h1[0] == h2[0]) {
      if (h1[1] == h2[1]) {
         return EQUAL;
      }
      else if (h1[1] < h2[1]) {
         return LESS;
      }
      else {
         return MORE;
      }
   }
   else if (h1[0] < h2[0]) {
      return LESS;
   }
   else {
      return MORE;
   }

}

int compare_ipv4(void * a, void * b)
{
   uint32_t *h1, *h2;
   h1 = (uint32_t*)a;
   h2 = (uint32_t*)b;
   if (*h1 == *h2) {
         return EQUAL;
   }
   else if (*h1 < *h2) {
      return LESS;
   }
   else {
      return MORE;
   }
}

unsigned int read_event_id_from_file(char * file_name)
{
   FILE *fp;
   fp = fopen(file_name,"r"); // read mode
   unsigned int id=0;

   if (fp == NULL)
   {
      if( access(file_name, F_OK) != -1 ) {
         // file exists
         fprintf(stderr, "Warning: File with last event ID (%s) exists, but it could not be opened. Last event_id = 0.\n", file_name);
         return 0;
      } else {
         fprintf(stderr, "Warning: File with last event ID (%s) does not exists. The file will be created, last event_id = 0.\n", file_name);
         return 0;
      }
   }
   if (fscanf(fp, "%u", &id) == EOF) {
      fprintf(stderr, "Warning: File with last event ID (%s) has incorect format. The file will be rewritten, last event_id = 0.\n", file_name);
      fclose(fp);
      return 0;
   }
   fclose(fp);
   return id;
}

int write_event_id_to_file(char * file_name, unsigned int event_id)
{
   FILE *fp;
   fp = fopen(file_name,"w"); // read mode

   if (fp == NULL)
   {
      fprintf(stderr, "Waring: File with last event ID (%s) could not be written. Last ID: %u, will not be saved. \n P",file_name, event_id);
      return 0;
   }
   fprintf(fp, "%u\n",event_id);
   fclose(fp);
   return 1;
}

void load_default_values()
{
   values.ex_request_max = EX_REQUEST_MAX;
   values.ex_request_min = EX_REQUEST_MIN;
   values.ex_response_max = EX_RESPONSE_MAX;
   values.ex_response_min = EX_RESPONSE_MIN;
   values.var_request_max = VAR_REQUEST_MAX;
   values.var_request_min = VAR_REQUEST_MIN;
   values.var_response_max = VAR_RESPONSE_MAX;
   values.var_response_min = VAR_RESPONSE_MIN;
   values.kurtosis_request_min = KURTOSIS_REQUEST_MIN;
   values.min_dns_request_count = MIN_DNS_REQUEST_COUNT;
   values.min_dns_request_count_tunnel = MIN_DNS_REQUEST_COUNT_TUNNEL;
   values.min_dns_request_count_other_anomaly = MIN_DNS_REQUEST_COUNT_OTHER_ANOMALY;
   values.min_dns_response_count_tunnel = MIN_DNS_RESPONSE_COUNT_TUNNEL;
   values.min_dns_response_count_other_anomaly = MIN_DNS_RESPONSE_COUNT_OTHER_ANOMALY;
   values.request_max_count_of_used_letters = REQUEST_MAX_COUNT_OF_USED_LETTERS;
   values.response_max_count_of_used_letters = RESPONSE_MAX_COUNT_OF_USED_LETTERS;
   values.max_percent_of_new_subdomains = MAX_PERCENT_OF_NEW_SUBDOMAINS;
   values.min_percent_of_new_subdomains = MIN_PERCENT_OF_NEW_SUBDOMAINS;
   values.min_percent_of_domain_searching_just_once = MIN_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE;
   values.max_percent_of_domain_searching_just_once = MAX_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE;
   values.min_percent_of_unique_domains = MIN_PERCENT_OF_UNIQUE_DOMAINS;
   values.max_percent_of_unique_domains = MAX_PERCENT_OF_UNIQUE_DOMAINS;
   values.max_percent_of_numbers_in_domain_prefix_tree_filter = MAX_PERCENT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER;
   values.max_percent_of_mallformed_packet_request = MAX_PERCENT_OF_MALLFORMED_PACKET_REQUEST;
   values.max_count_of_numbers_in_domain_prefix_tree_filter = MAX_COUNT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER;
   values.max_percent_of_subdomains_in_main_domain = MAX_PERCENT_OF_SUBDOMAINS_IN_MAIN_DOMAIN;
   values.max_count_of_round_in_suspiction = MAX_COUNT_OF_ROUND_IN_SUSPICTION;
   values.max_count_of_round_in_attack = MAX_COUNT_OF_ROUND_IN_ATTACK;
   values.min_length_of_tunnel_string = MIN_LENGTH_OF_TUNNEL_STRING;
   values.time_of_one_session = TIME_OF_ONE_SESSION;
   values.min_dns_request_count_tunnel_closer = MIN_DNS_REQUEST_COUNT_TUNNEL_CLOSER;
   values.request_max_count_of_used_letters_closer = REQUEST_MAX_COUNT_OF_USED_LETTERS_CLOSER;
   values.max_percent_of_domain_searching_just_once_closer = MAX_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE_CLOSER;
   values.max_percent_of_unique_domains_closer = MAX_PERCENT_OF_UNIQUE_DOMAINS_CLOSER;
   values.sdm_timeout = SDM_TIMEOUT;
   values.sdm_count_of_packets = SDM_COUNT_OF_PACKETS;
   values.file_name_event_id = NULL;
}

int main(int argc, char **argv)
{
   int ret, i, n_outputs;
   packet_t  packet;
   double start_time=0, packet_time=0;
   int count_of_cycle=0;
   char file_or_port=0;
   FILE * result_file = NULL,
        * exception_file_domain = NULL,
        * exception_file_ip = NULL;
   void * btree_ver4, *btree_ver6, *btree[2];
   prefix_tree_t * exception_domain_prefix_tree = NULL;
   void * exception_ip_v4_b_plus_tree = NULL;
   void * exception_ip_v6_b_plus_tree = NULL;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long histogram_dns_requests [HISTOGRAM_SIZE_REQUESTS];
   unsigned long histogram_dns_response [HISTOGRAM_SIZE_RESPONSE];
   unsigned char write_summary = 0;
   memset(histogram_dns_requests, 0, HISTOGRAM_SIZE_REQUESTS * sizeof(unsigned long));
   memset(histogram_dns_response, 0, HISTOGRAM_SIZE_RESPONSE * sizeof(unsigned long));
   //load default values from defined constants
   load_default_values();
   // ***** TRAP initialization *****
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   //signal(SIGTERM, signal_handler);
   //signal(SIGINT, signal_handler);
   signal(SIGUSR1, signal_handler);

   // ***** Create UniRec template *****
   char opt;
   char *record_folder_name = NULL;
   char *input_packet_file_name = NULL;
   ur_template_t *tmplt = NULL;
   unirec_tunnel_notification_t ur_notification;
   ur_notification.unirec_out = NULL;
   ur_notification.detection = NULL;
   ur_notification.unirec_out_sdm = NULL;
   ur_notification.detection_sdm = NULL;
   trap_ifc_spec_t ifc_spec;

   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'p':
            progress = atoi(optarg);
            break;
         case 's':
            record_folder_name = optarg;
            write_summary = 1;
            //if the folder does not exist it will create
            mkdir(optarg,  S_IRWXU|S_IRGRP|S_IXGRP);
            break;
         case 'S':
            if (sscanf(optarg, "%d,%d", &values.sdm_count_of_packets, &values.sdm_timeout) != 2) {
               fprintf(stderr, "Missing 'S' argument\n");
               goto failed_trap;
            }
            break;
         case 'd':
               result_file = fopen ( optarg, "a+" );
               if (result_file == NULL) {
                  fprintf(stderr, "Error: Output file couldn`t be opened.\n");
                  goto failed_trap;
               }
               else {
                  time_t mytime;
                  mytime = time(NULL);
                  fprintf(result_file, "\nSTART TIME: %s\n", ctime(&mytime));
               }
            break;
         case 'a':
            exception_file_domain = fopen ( optarg, "r" );
            if (exception_file_domain == NULL) {
               fprintf(stderr, "Error: Exception file with domains couldn`t be opened.\n");
               goto failed_trap;
            }
            break;
         case 'b':
            exception_file_ip = fopen ( optarg, "r" );
            if (exception_file_ip == NULL) {
               fprintf(stderr, "Error: Exception file with IPs couldn`t be opened.\n");
               goto failed_trap;
            }
            break;
         case 'f':
            input_packet_file_name = optarg;
            file_or_port |= READ_FROM_FILE;
            break;
         case 'g':
            if (sscanf(optarg, "%d,%d,%d,%d", &values.ex_request_min, &values.ex_request_max, &values.var_request_min, &values.var_request_max) != 4) {
               fprintf(stderr, "Missing 'g' argument\n");
               goto failed_trap;
            }
            break;

         case 'j':
            if (sscanf(optarg, "%d,%d", &values.request_max_count_of_used_letters, &values.response_max_count_of_used_letters) != 2) {
               fprintf(stderr, "Missing 'j' argument\n");
               goto failed_trap;
            }
            break;
         case 'k':
            if (sscanf(optarg, "%f,%f", &values.max_percent_of_new_subdomains, &values.min_percent_of_new_subdomains) != 2) {
               fprintf(stderr, "Missing 'k' argument\n");
               goto failed_trap;
            }
            break;
         case 'l':
            if (sscanf(optarg, "%d,%f", &values.max_count_of_numbers_in_domain_prefix_tree_filter, &values.max_percent_of_numbers_in_domain_prefix_tree_filter) != 2) {
               fprintf(stderr, "Missing 'l' argument\n");
               goto failed_trap;
            }
            break;
         case 'm':
            if (sscanf(optarg, "%f", &values.max_percent_of_mallformed_packet_request) != 1) {
               fprintf(stderr, "Missing 'm' argument\n");
               goto failed_trap;
            }
            break;
         case 'n':
            if (sscanf(optarg, "%d,%d", &values.min_dns_request_count_other_anomaly, &values.min_dns_request_count_tunnel) != 2) {
               fprintf(stderr, "Missing 'n' argument\n");
               goto failed_trap;
            }
            break;
         case 'o':
            if (sscanf(optarg, "%d,%d", &values.min_dns_response_count_other_anomaly, &values.min_dns_response_count_tunnel) != 2) {
               fprintf(stderr, "Missing 'o' argument\n");
               goto failed_trap;
            }
            break;
         case 'q':
            if (sscanf(optarg, "%f,%f", &values.max_percent_of_domain_searching_just_once, &values.min_percent_of_domain_searching_just_once) != 2) {
               fprintf(stderr, "Missing 'q' argument\n");
               goto failed_trap;
            }
            break;
         case 'r':
            if (sscanf(optarg, "%d,%d,%d,%d", &values.ex_response_min, &values.ex_response_max, &values.var_response_min, &values.var_response_max) != 4) {
               fprintf(stderr, "Missing 'r' argument\n");
               goto failed_trap;
            }
            break;
         case 't':
            if (sscanf(optarg, "%d,%d", &values.max_count_of_round_in_suspiction, &values.max_count_of_round_in_attack) != 2) {
               fprintf(stderr, "Missing 't' argument\n");
               goto failed_trap;
            }
            break;
         case 'w':
            if (sscanf(optarg, "%d", &values.min_length_of_tunnel_string) != 1) {
               fprintf(stderr, "Missing 'w' argument\n");
               goto failed_trap;
            }
            break;
         case 'z':
            if (sscanf(optarg, "%d", &values.time_of_one_session) != 1) {
               fprintf(stderr, "Missing 'z' argument\n");
               goto failed_trap;
            }
            break;
          case 'E':
            values.file_name_event_id = optarg;
            break;
         case 'i':
            file_or_port |= READ_FROM_UNIREC;
            break;
         case 'c':
            file_or_port |= MEASURE_PARAMETERS;
            input_packet_file_name = optarg;
      }
   }
   if (input_packet_file_name == NULL) {
     // TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
      ret = trap_parse_params(&argc, argv, &ifc_spec);
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_HELP) { // "-h" was found
            trap_print_help(module_info);
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 0;
         }
         fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      }
      // Count number of output interfaces
      n_outputs = strlen(ifc_spec.types) - 1;

      printf("Output interfaces: %d\n", n_outputs);

      // Number of output interfaces exceeds TRAP limit
      if (n_outputs > 2) {
         fprintf(stderr, "Error: More than 2 interfaces. In tunnel detection module can be maximal 2 otuput interfaces\n");
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      }

      // Initialize TRAP library (create and init all interfaces)
      ret = trap_init(module_info, ifc_spec);
      if (ret != TRAP_E_OK) {
         fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
         trap_free_ifc_spec(ifc_spec);
         TRAP_DEFAULT_FINALIZATION();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 1;
      }



      tmplt = ur_create_input_template(0, "BYTES,DNS_NAME,DST_PORT,SRC_IP,DST_IP,DNS_QTYPE,DNS_RDATA", NULL);
      if (tmplt == NULL) {
         fprintf(stderr, "Error: Invalid UniRec specifier.\n");
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
         return 4;
      }
      if (n_outputs > 0) {
         // prepare detection record
         trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
         ur_notification.unirec_out = ur_create_output_template(0, "EVENT_ID,SRC_IP,TUNNEL_PER_NEW_DOMAIN,TUNNEL_PER_SUBDOMAIN,TUNNEL_TYPE,TUNNEL_DOMAIN,TUNNEL_CNT_PACKET,TIME_FIRST,TIME_LAST", NULL);
         if (ur_notification.unirec_out == NULL) {
            fprintf(stderr, "Error: Invalid UniRec specifier.\n");
            trap_finalize();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 4;
         }
         ur_notification.detection = ur_create_record(ur_notification.unirec_out, MAX_LENGTH_OF_REQUEST_DOMAIN);
         if (ur_notification.detection == NULL) {
            fprintf(stderr,"ERROR: No memory available for detection record. Unable to continue.\n");
            ur_free_template(tmplt);
            ur_free_template(ur_notification.unirec_out);
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 4;
         }
      }
      if (n_outputs > 1) {
         // prepare output record for SDM
         trap_ifcctl(TRAPIFC_OUTPUT, 1, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
         ur_notification.unirec_out_sdm = ur_create_output_template(1, "SRC_IP,TIMEOUT,PACKETS,SDM_CAPTURE_FILE_ID", NULL);
         if (ur_notification.unirec_out_sdm == NULL) {
            fprintf(stderr, "Error: Invalid UniRec specifier.\n");
            trap_finalize();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 4;
         }
         ur_notification.detection_sdm = ur_create_record(ur_notification.unirec_out_sdm, MAX_LENGTH_SDM_CAPTURE_FILE_ID);
         if (ur_notification.detection_sdm == NULL) {
            fprintf(stderr,"ERROR: No memory available for detection record. Unable to continue.\n");
            ur_free_template(tmplt);
            ur_free_template(ur_notification.unirec_out);
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return 4;
         }
      }
   }
   else if (file_or_port != READ_FROM_FILE && file_or_port != MEASURE_PARAMETERS) {
      //fprintf(stderr, "Error: You have to specify input file or input socket (not both together).\n");
      //trap_finalize();
      //return 4;
   }
   values.event_id_counter = read_event_id_from_file(values.file_name_event_id == NULL ? FILE_NAME_EVENT_ID : values.file_name_event_id);
   //add domain exceptions to prefix tree, if the file is specified
   if (exception_file_domain != NULL) {
      int sign;
      int length;
      char domain[MAX_LENGTH_OF_REQUEST_DOMAIN];
      //read domains
      sign = fgetc(exception_file_domain);
      //initialize prefix tree
      exception_domain_prefix_tree = prefix_tree_initialize(SUFFIX ,0,'.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      if (exception_domain_prefix_tree == NULL) {
         fclose(exception_file_domain);
         fprintf(stderr, "Error: The exception tree could not be allocated.\n");
         trap_finalize();
         return 4;
      }
      while (sign != -1) {
         length = 0;
         while (sign != '\n' && sign != -1) {
            if (sign != '\t' && sign != ' ') {
               domain[length++] = sign;
            }
            //doamin is too long
            if (length > MAX_LENGTH_OF_REQUEST_DOMAIN) {
               fclose(exception_file_domain);
               fprintf(stderr, "Error: The exception domain is too long. Max length of domain exception is %d\n", MAX_LENGTH_OF_REQUEST_DOMAIN - 1);
               trap_finalize();
               return 4;
            }
            sign = fgetc(exception_file_domain);
         }
         domain[length] = 0;
         if (length != 0) {
            prefix_tree_add_string_exception(exception_domain_prefix_tree,domain ,length);
         }
         sign = fgetc(exception_file_domain);
      }
      fclose(exception_file_domain);
   }

   //add IPs exceptions to b+ tree, if the file is specified
   if (exception_file_ip != NULL) {
      int sign;
      int length;
      char ip_str[MAX_LENGTH_OF_IP];
      ip_addr_t addr;
      //read IPs
      sign = fgetc(exception_file_ip);
      while (sign != -1) {
         length = 0;
         while (sign != '\n' && sign != ';' && sign != -1) {
            if (sign != '\t' && sign != ' ') {
               ip_str[length++] = sign;
            }
            //IP is too long
            if (length > MAX_LENGTH_OF_IP) {
               fclose(exception_file_ip);
               fprintf(stderr, "Error: The exception ip is too long. Max length of ip is %d\n", MAX_LENGTH_OF_IP - 1);
               trap_finalize();
               return 4;
            }
            sign = fgetc(exception_file_ip);
         }
         ip_str[length] = 0;
         //translate to IP unirec format and insert to b plus tree.
         if (length != 0) {
            if (ip_from_str(ip_str, &addr) == 1) {
               if (ip_is4(&addr)) {
                  //is IPv4
                  if (exception_ip_v4_b_plus_tree == NULL) {
                     exception_ip_v4_b_plus_tree = b_plus_tree_initialize(COUNT_OF_ITEM_IN_LEAF, &compare_ipv4, 0, sizeof(uint32_t));
                  }
                  if (exception_ip_v4_b_plus_tree != NULL) {
                     uint32_t ip_to_tree = ip_get_v4_as_int(&addr);
                     b_plus_tree_insert_item(exception_ip_v4_b_plus_tree, &ip_to_tree);
                  }
               }
               else {
                  //is IPv6
                  if (exception_ip_v6_b_plus_tree == NULL) {
                     exception_ip_v6_b_plus_tree = b_plus_tree_initialize(COUNT_OF_ITEM_IN_LEAF, &compare_ipv6, 0, sizeof(uint64_t)*2);
                  }
                  if (exception_ip_v6_b_plus_tree != NULL) {
                     b_plus_tree_insert_item(exception_ip_v6_b_plus_tree, &addr);
                  }
               }
            }
            else {
               fprintf(stderr, "Error: The exception ip \"%s\" does not match IP format.", ip_str);
            }

         }
         sign = fgetc(exception_file_ip);
      }
      fclose(exception_file_ip);
   }
   //initialize b+ tree ipv4
   btree_ver4 = b_plus_tree_initialize(COUNT_OF_ITEM_IN_LEAF, &compare_ipv4, sizeof(ip_address_t), sizeof(uint32_t));
   //initialize b+ tree ipv6
   btree_ver6 = b_plus_tree_initialize(COUNT_OF_ITEM_IN_LEAF, &compare_ipv6, sizeof(ip_address_t), sizeof(uint64_t)*2);
   //add trees to array, you can work with it in cycle
   btree[0] = btree_ver4;
   btree[1] = btree_ver6;
   // ***** Main processing loop for Unirec records *****
   if (input_packet_file_name == NULL) {
      ip_addr_t * ip_in_packet;
      const void *data;
      uint16_t data_size;
      time_t start_t, end_t;
      time(&start_t);
      time(&end_t);
      #ifdef TEST
      char ip_buff [100];
      #endif /*TEST*/
      //read packets from interface
      while (!stop) {
         //cycle of colecting informations
         time(&start_t);
         time(&end_t);
         while (difftime(end_t, start_t) <= values.time_of_one_session && !stop) {
            // Receive data from any interface, wait until data are available
            ret = TRAP_RECEIVE(0, data, data_size, tmplt);
            TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

            // Check size of received data
            if (data_size < ur_rec_fixlen_size(tmplt)) {
               stop=1;
               if (data_size <= 1) {
                  break; // End of data (used for testing purposes)
               }
               else {
                  fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                          ur_rec_fixlen_size(tmplt), data_size);
                  break;
               }
            }
            cnt_packets++;
            //fill the packet structure
            //size
            packet.size = ur_get(tmplt, data, F_BYTES);
            //DNS NAME
            packet.request_length = copy_string(packet.request_string, ur_get_ptr(tmplt, data, F_DNS_NAME), ur_get_var_len(tmplt, data, F_DNS_NAME), MAX_LENGTH_OF_REQUEST_DOMAIN);
            if (packet.request_length >= MAX_SIZE_OF_REQUEST_EXPORTER) {
               cut_max_domain(&packet);
            }

            //type request
            if (ur_get(tmplt, data, F_DST_PORT)==53) {
               packet.is_response = 0;
               ip_in_packet = & ur_get(tmplt, data, F_SRC_IP);
               #ifdef TEST
                  ip_to_str(&ip_in_packet ,ip_buff);
                  printf("source ip address: %s\n", ip_buff);
               #endif /*TEST*/
               //ip
               if (ip_is4(ip_in_packet)) {
                  packet.ip_version = IP_VERSION_4;
                  packet.src_ip_v4 = ip_get_v4_as_int(ip_in_packet);
               }
               else {
                  packet.ip_version = IP_VERSION_6;
                  memcpy(packet.src_ip_v6, ip_in_packet, 16);
               }
            }
            //type response
            else {
               packet.is_response = 1;
               ip_in_packet = & ur_get(tmplt, data, F_DST_IP);
               #ifdef TEST
                  ip_to_str(&ip_in_packet ,ip_buff);
                  printf("destination ip address: %s\n", ip_buff);
               #endif /*TEST*/
               //ip
               if (ip_is4(ip_in_packet)) {
                  packet.ip_version = IP_VERSION_4;
                  packet.dst_ip_v4 = ip_get_v4_as_int(ip_in_packet);
               }
               else {
                  packet.ip_version = IP_VERSION_6;
                  memcpy(packet.dst_ip_v6, ip_in_packet, 16);
               }
               packet.ns_response[0]=0;
               packet.mx_response[0]=0;
               packet.txt_response[0]=0;
               packet.cname_response[0]=0;
               switch(ur_get(tmplt, data, F_DNS_QTYPE)) {
                  case 2:
                     copy_string(packet.ns_response, ur_get_ptr(tmplt, data, F_DNS_RDATA), ur_get_var_len(tmplt, data, F_DNS_RDATA), MAX_LENGTH_OF_RESPONSE_STRING);
                     break;
                  case 15:
                     copy_string(packet.mx_response, ur_get_ptr(tmplt, data, F_DNS_RDATA), ur_get_var_len(tmplt, data, F_DNS_RDATA), MAX_LENGTH_OF_RESPONSE_STRING);
                     break;
                  case 16:
                     copy_string(packet.txt_response, ur_get_ptr(tmplt, data, F_DNS_RDATA), ur_get_var_len(tmplt, data, F_DNS_RDATA), MAX_LENGTH_OF_RESPONSE_STRING);
                     break;
                  case 5:
                     copy_string(packet.cname_response, ur_get_ptr(tmplt, data, F_DNS_RDATA), ur_get_var_len(tmplt, data, F_DNS_RDATA), MAX_LENGTH_OF_RESPONSE_STRING);
                     break;
               }
            }
            #ifdef TEST
               printf("request: %s\n", packet.request_string);
               if (packet.ns_response[0] != 0)
                  printf("ns: %s\n", packet.ns_response);
               if (packet.mx_response[0] != 0)
                  printf("mx: %s\n", packet.mx_response);
               if (packet.txt_response[0] != 0)
                  printf("txt: %s\n", packet.txt_response);
               if (packet.cname_response[0] != 0)
                  printf("cname: %s\n", packet.cname_response);
               printf("\n");
            #endif /*TEST*/
            //test if it is not in exception
            if ( //domains
                  (exception_domain_prefix_tree == NULL ||
                   packet.request_length == 0 ||
                   prefix_tree_is_string_in_exception(exception_domain_prefix_tree, packet.request_string, packet.request_length) == 0
                  ) &&
                  (  //ip
                     (packet.ip_version == IP_VERSION_4 &&
                        (exception_ip_v4_b_plus_tree == NULL ||
                         (b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, &packet.src_ip_v4) == 0 &&
                          b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, &packet.dst_ip_v4) == 0
                         ))
                     )||
                     (packet.ip_version == IP_VERSION_6 &&
                        (exception_ip_v6_b_plus_tree == NULL ||
                        (b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, packet.src_ip_v6) == 0 &&
                         b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, packet.dst_ip_v6) == 0))
                     )
                  )
            ) {
                  //analyze the packet
                  //is it destination port of DNS (Port 53) request
                  if (packet.is_response==0) {
                     // Update counters
                     if (packet.ip_version == IP_VERSION_4) {
                           collection_of_information_and_basic_payload_detection(btree_ver4, (&packet.src_ip_v4), &packet);
                        }
                        else {
                           collection_of_information_and_basic_payload_detection(btree_ver6, packet.src_ip_v6,  &packet);
                        }
                     histogram_dns_requests[packet.size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
                  }
                  //is it source port of DNS (Port 53)
                  else {
                     // Update counters
                     if (packet.ip_version == IP_VERSION_4) {
                        collection_of_information_and_basic_payload_detection(btree_ver4, (&packet.dst_ip_v4), &packet);
                     }
                     else {
                        collection_of_information_and_basic_payload_detection(btree_ver6, packet.dst_ip_v6, &packet);
                     }

                     histogram_dns_response[packet.size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
                  }
            }
            if (stats == 1) {
               printf("Time: %lu\n", (long unsigned int) time(NULL));
               signal(SIGUSR1, signal_handler);
               stats = 0;
            }
            //save packet time
            time(&end_t);
         }
         //restart timer
         printf("cycle %d\n", ++count_of_cycle);
         printf("\tcount of ip's before_erase %lu\n", b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6));
         calculate_statistic_and_choose_anomaly(btree_ver4, result_file, &ur_notification);
         calculate_statistic_and_choose_anomaly(btree_ver6, result_file, &ur_notification);
         printf("\tcount of ip's after_erase %lu\n\n", b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6));
         //stop=1;
      }
   }
   else if (input_packet_file_name != NULL && file_or_port != MEASURE_PARAMETERS) {
   //***** Main processing loop for file *****
      //read packets from file
      //initialization of parser
      FILE *input;
      #ifdef TIME
            clock_t start_t, end_t;
            double delay = 0;
            double last_delay = 0;
            double ip_address_before_erase = 0;
            double ip_address_after_erase = 0;
      #endif /*TIME*/
      input = parser_initialize(input_packet_file_name);
      if (input == NULL) {
         fprintf(stderr, "Error: Input file couldn't be opened.\n");
         trap_finalize();
      return 1;
      }
      //loop till end of file
      while (!stop) {
         while (packet_time - start_time <= values.time_of_one_session && !stop) {
            // Check if packet was recieved
            if (read_packet(input, &packet) == -1) {
               printf("End of file\n" );
               stop=1;
               break; // End of data (used for testing purposes)
            }
            #ifdef TIME
                  start_t = clock();
            #endif /*TIME*/
            cnt_packets++;
            //read packet time
            if (start_time==0) {
               start_time = packet.time;
            }
            packet_time = packet.time;
            if (progress > 0 && cnt_flows % progress == 0) {
               printf(".");
               fflush(stdout);
            }
            //test if it is not in exception
            if ( //domains
                  (exception_domain_prefix_tree == NULL ||
                   packet.request_length == 0 ||
                   prefix_tree_is_string_in_exception(exception_domain_prefix_tree, packet.request_string, packet.request_length) == 0
                  ) &&
                  (  //ip
                     (packet.ip_version == IP_VERSION_4 &&
                        (exception_ip_v4_b_plus_tree == NULL ||
                         (b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, &packet.src_ip_v4) == 0 &&
                          b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, &packet.dst_ip_v4) == 0
                         ))
                     )||
                     (packet.ip_version == IP_VERSION_6 &&
                        (exception_ip_v6_b_plus_tree == NULL ||
                        (b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, packet.src_ip_v6) == 0 &&
                         b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, packet.dst_ip_v6) == 0))
                     )
                  )
            ) {
               //is it destination port of DNS (Port 53) request
               if (packet.is_response==0) {
                  // Update counters
                  if (packet.ip_version == IP_VERSION_4) {
                     collection_of_information_and_basic_payload_detection(btree_ver4, (&packet.src_ip_v4), &packet);
                  }
                  else {
                     collection_of_information_and_basic_payload_detection(btree_ver6, packet.src_ip_v6, &packet);
                  }
                  histogram_dns_requests[packet.size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
               }
               //is it source port of DNS (Port 53)
               else {
                  // Update counters
                  if (packet.ip_version == IP_VERSION_4) {
                     collection_of_information_and_basic_payload_detection(btree_ver4, (&packet.dst_ip_v4), &packet);
                  }
                  else {
                     collection_of_information_and_basic_payload_detection(btree_ver6, packet.dst_ip_v6, &packet);
                  }
                  histogram_dns_response[packet.size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
               }
            }

            if (stats == 1) {
               printf("Time: %lu\n", (long unsigned int) time(NULL));
               signal(SIGUSR1, signal_handler);
               stats = 0;
            }
            #ifdef TIME
                  end_t = clock();;

                  delay += (double)(end_t - start_t) / CLOCKS_PER_SEC;
            #endif /*TIME*/
         }
         //restart timer
         start_time=0;
         packet_time=0;
         printf("cycle %d\n", ++count_of_cycle);
         printf("\tcount of ip's before_erase %lu\n", b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6));
         #ifdef TIME
               ip_address_before_erase += b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6);
               start_t = clock();
         #endif /*TIME*/
         calculate_statistic_and_choose_anomaly(btree_ver4, result_file, &ur_notification);
         calculate_statistic_and_choose_anomaly(btree_ver6, result_file, &ur_notification);
          #ifdef TIME
              end_t = clock();;
          #endif /*TIME*/
          printf("\tcount of ip's after_erase %lu\n\n", b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6));
         #ifdef TIME
                  ip_address_after_erase += b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6);
                  delay += (double)(end_t - start_t) / CLOCKS_PER_SEC;
               printf("time all: %f\t delta time: %f\n", delay, delay - last_delay);
               printf("add to b plus: %d,\t search in b plus: %d,\t delete ip from blus: %d,\t add to prefix: %d \n", add_to_bplus, search_in_bplus, delete_from_blus, add_to_prefix );
               last_delay = delay;
         #endif /*TIME*/
      }
      //close reading from file
      parser_end(input);
       #ifdef TIME
      printf("..................................................................\n");
      printf("ex from delta time: %f,\t deleted ip for cycle %f, \t packets for cycle: %f, \t IP address before erase: %f, \t IP address after erase: %f \n", delay/(double)count_of_cycle, delete_from_blus/(double)count_of_cycle, (double)cnt_packets/(double)count_of_cycle, ip_address_before_erase/(double)count_of_cycle, ip_address_after_erase/(double)count_of_cycle );
       #endif /*TIME*/
   }
   else if (file_or_port == MEASURE_PARAMETERS) {
   //***** Main processing loop for measure parameters *****
      //read packets from file
      //inicialization of parser
      FILE *input;
      measure_parameters_t measure;
      character_statistic_t char_stat;
      prefix_tree_t * tree_measure;
      memset(&measure, 0, sizeof(measure_parameters_t));
      input = parser_initialize(input_packet_file_name);
      if (input == NULL) {
         fprintf(stderr, "Error: Input file couldn`t be opened.\n");
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
      }
      tree_measure = prefix_tree_initialize(PREFIX, 0, '.',DOMAIN_EXTENSION_YES, RELAXATION_AFTER_DELETE_YES);
      if (tree_measure == NULL) {
         fprintf(stderr, "Error: Prefix tree could not be created\n");
         trap_finalize();
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return 1;
      }
      //loop till end of file
      while (!stop) {
            // Check if packet was recieved
            if (read_packet(input, &packet) == -1) {
               printf("End of file\n" );
               stop=1;
               break; // End of data (used for testing purposes)
            }
            cnt_packets++;
            //read packet time
            packet_time = packet.time;
            if (progress > 0 && cnt_flows % progress == 0) {
               printf(".");
               fflush(stdout);
            }
            //test if it is not in exception
            if ( //domains
                  (exception_domain_prefix_tree == NULL ||
                   packet.request_length == 0 ||
                   prefix_tree_is_string_in_exception(exception_domain_prefix_tree, packet.request_string, packet.request_length) == 0
                  ) &&
                  (  //ip
                     (packet.ip_version == IP_VERSION_4 &&
                        (exception_ip_v4_b_plus_tree == NULL ||
                         (b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, &packet.src_ip_v4) == 0 &&
                          b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, &packet.dst_ip_v4) == 0
                         ))
                     )||
                     (packet.ip_version == IP_VERSION_6 &&
                        (exception_ip_v6_b_plus_tree == NULL ||
                        (b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, packet.src_ip_v6) == 0 &&
                         b_plus_tree_is_item_in_tree(exception_ip_v4_b_plus_tree, packet.dst_ip_v6) == 0))
                     )
                  )
            ) {
               //is it destination port of DNS (Port 53) request
               if (packet.is_response==0) {
                  if (packet.request_string[0] != 0) {
                     double percent_of_numbers_request;
                     measure.requests++;
                     calculate_character_statistic_conv_to_lowercase(packet.request_string, &char_stat);
                     measure.sum_size_request += packet.size;
                     measure.sum_2_size_request += packet.size * packet.size;
                     measure.sum_count_of_unique_letters_request += char_stat.count_of_different_letters;
                     measure.sum_2_count_of_unique_letters_request += char_stat.count_of_different_letters * char_stat.count_of_different_letters;
                     measure.sum_count_of_numbers += char_stat.count_of_numbers_in_string;
                     measure.sum_2_count_of_numbers += char_stat.count_of_numbers_in_string * char_stat.count_of_numbers_in_string;
                     percent_of_numbers_request = char_stat.length != 0 ? (double)char_stat.count_of_numbers_in_string / (double)char_stat.length : 0;
                     measure.sum_percent_of_numbers += percent_of_numbers_request;
                     measure.sum_2_percent_of_numbers += percent_of_numbers_request * percent_of_numbers_request;
                     prefix_tree_insert(tree_measure, packet.request_string, char_stat.length);
                  }
               }
               //is it source port of DNS (Port 53)
               else {
                  int max_count_of_unique_letters = 0;
                  if (packet.request_string[0] != 0) {
                     calculate_character_statistic_conv_to_lowercase(packet.request_string, &char_stat);
                     max_count_of_unique_letters = char_stat.count_of_different_letters;
                     prefix_tree_insert(tree_measure, packet.request_string, char_stat.length);
                  }
                  if (packet.mx_response[0] != 0) {
                     calculate_character_statistic_conv_to_lowercase(packet.mx_response, &char_stat);
                     if (char_stat.count_of_different_letters > max_count_of_unique_letters) {
                        max_count_of_unique_letters = char_stat.count_of_different_letters;
                     }
                  }
                  if (packet.ns_response[0] != 0) {
                     calculate_character_statistic_conv_to_lowercase(packet.ns_response, &char_stat);
                     if (char_stat.count_of_different_letters > max_count_of_unique_letters) {
                        max_count_of_unique_letters = char_stat.count_of_different_letters;
                     }
                  }
                  if (packet.cname_response[0] != 0) {
                     calculate_character_statistic_conv_to_lowercase(packet.cname_response, &char_stat);
                     if (char_stat.count_of_different_letters > max_count_of_unique_letters) {
                        max_count_of_unique_letters = char_stat.count_of_different_letters;
                     }
                  }
                  if (packet.txt_response[0] != 0) {
                     calculate_character_statistic_conv_to_lowercase(packet.txt_response, &char_stat);
                     if (char_stat.count_of_different_letters > max_count_of_unique_letters) {
                        max_count_of_unique_letters = char_stat.count_of_different_letters;
                     }
                  }
                  if (max_count_of_unique_letters != 0) {
                     measure.responses++;
                     measure.sum_size_response += packet.size;
                     measure.sum_2_size_response += packet.size * packet.size;
                     measure.sum_count_of_unique_letters_response += max_count_of_unique_letters;
                     measure.sum_2_count_of_unique_letters_response += max_count_of_unique_letters * max_count_of_unique_letters;
                  }
               }
            }
            if (stats == 1) {
               printf("Time: %lu\n", (long unsigned int) time(NULL));
               signal(SIGUSR1, signal_handler);
               stats = 0;
            }
      }
      calculate_limits_from_measuring(&measure);
      measure.max_percent_of_domain_searching_just_once = (double)(tree_measure->count_of_domain_searched_just_ones) / (double)(tree_measure->count_of_inserting);
      measure.max_percent_of_domain_searching_just_once -= measure.max_percent_of_domain_searching_just_once * (MEASURE_TOLERANCE);
      measure.var_request_max = values.var_request_max;
      measure.var_request_min = values.var_request_min;
      measure.var_response_max = values.var_response_max;
      measure.var_response_min = values.var_response_min;
      //close reading from file
      parser_end(input);
       #ifdef TIME
      printf("..................................................................\n");
      printf("ex from delta time: %f,\t deleted ip for cycle %f, \t packets for cycle: %f, \t IP address before erase: %f, \t IP address after erase: %f \n", delay/(double)count_of_cycle, delete_from_blus/(double)count_of_cycle, (double)cnt_packets/(double)count_of_cycle, ip_address_before_erase/(double)count_of_cycle, ip_address_after_erase/(double)count_of_cycle );
       #endif /*TIME*/
      printf("Calculated limits:\n");
      printf("ex_request_max: %f\n", measure.ex_request_max);
      printf("ex_request_min: %f\n", measure.ex_request_min);
      printf("ex_response_max: %f\n", measure.ex_response_max);
      printf("ex_response_min: %f\n", measure.ex_response_min);
      printf("var_request_max: %f\n", measure.var_request_max);
      printf("var_request_min: %f\n", measure.var_request_min);
      printf("var_response_max: %f\n", measure.var_response_max);
      printf("var_response_min: %f\n", measure.var_response_min);
      printf("request_max_count_of_used_letters: %f\n", measure.request_max_count_of_used_letters);
      printf("response_max_count_of_used_letters: %f\n", measure.response_max_count_of_used_letters);
      printf("max_percent_of_domain_searching_just_once: %f\n", measure.max_percent_of_domain_searching_just_once);
      printf("max_percent_of_unique_domains: %f\n", measure.max_percent_of_unique_domains);
      printf("max_percent_of_numbers_in_domain_prefix_tree_filter: %f\n", measure.max_percent_of_numbers_in_domain_prefix_tree_filter);
      printf("max_percent_of_subdomains_in_main_domain: %f\n", measure.max_percent_of_subdomains_in_main_domain);
      printf("max_count_of_numbers_in_domain_prefix_tree_filter: %f\n", measure.max_count_of_numbers_in_domain_prefix_tree_filter);
      printf("parameters:\n");
      printf("-g %d,%d,%d,%d ", (int)measure.ex_request_min, (int)measure.ex_request_max, (int)measure.var_request_min, (int)measure.var_request_max);
      printf("-r %d,%d,%d,%d ", (int)measure.ex_response_min, (int)measure.ex_response_max, (int)measure.var_response_min, (int)measure.var_response_max);
      printf("-j %d,%d ", (int)measure.request_max_count_of_used_letters, (int)measure.response_max_count_of_used_letters);
      printf("-q %f,%f ", measure.max_percent_of_domain_searching_just_once, values.min_percent_of_domain_searching_just_once);
      printf("-l %d,%f \n", (int)measure.max_count_of_numbers_in_domain_prefix_tree_filter, measure.max_percent_of_numbers_in_domain_prefix_tree_filter);
   }
   // ***** Print results *****
   if (progress > 0) {
      printf("\n");
   }
   printf("Packets: %20lu\n", cnt_packets);
   // *****  Write into file ******
   if (write_summary) {
      write_summary_result(record_folder_name, histogram_dns_requests, histogram_dns_response);
      write_detail_result(record_folder_name, btree, 2);
   }
   write_event_id_to_file(values.file_name_event_id == NULL ? FILE_NAME_EVENT_ID : values.file_name_event_id, values.event_id_counter);
   // ***** Cleanup *****
   //clean values in b plus tree
   if (result_file != NULL) {
      fclose(result_file);
   }

   //clean btree ver4 and ver6
   b_plus_tree_item *b_item;
   for (i = 0; i<2; i++) {
      b_item = b_plus_tree_create_list_item(btree[i]);
      int is_there_next = b_plus_tree_get_list(btree[i], b_item);
      while (is_there_next == 1) {
         check_and_delete_suspision((ip_address_t*)b_item->value, REQUEST_AND_RESPONSE_PART);
         is_there_next = b_plus_tree_get_next_item_from_list(btree[i], b_item);
      }
      b_plus_tree_destroy_list_item(b_item);
      b_plus_tree_destroy(btree[i]);
   }
   //clean exception prefix tree
   if (exception_domain_prefix_tree != NULL) {
      prefix_tree_destroy(exception_domain_prefix_tree);
   }
   //clean exception b plus tree for IPv4
   if (exception_ip_v4_b_plus_tree != NULL) {
      b_plus_tree_destroy(exception_ip_v4_b_plus_tree);
   }
   //clean exception b plus tree for IPv6
   if (exception_ip_v6_b_plus_tree != NULL) {
      b_plus_tree_destroy(exception_ip_v6_b_plus_tree);
   }
   // Do all necessary cleanup before exiting
failed_trap:
   if (file_or_port & READ_FROM_UNIREC) {
      // send terminate message
      char dummy[1] = {0};
      trap_send(0, dummy, 1);
      // clean up before termination
      if (tmplt != NULL) {
         ur_free_template(tmplt);
      }
      if (ur_notification.unirec_out != NULL) {
         ur_free_template(ur_notification.unirec_out);
      }
      if (ur_notification.detection != NULL) {
         ur_free_record(ur_notification.detection);
      }
      if (ur_notification.unirec_out_sdm != NULL) {
         ur_free_template(ur_notification.unirec_out_sdm);
      }
      if (ur_notification.detection_sdm != NULL) {
         ur_free_record(ur_notification.detection_sdm);
      }

      trap_finalize();
   }
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return 0;
}
