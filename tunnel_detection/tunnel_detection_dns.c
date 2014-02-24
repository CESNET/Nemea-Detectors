/*!
 * \file tunnel_detection_dns.c
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

#include <math.h>  
#include <stdio.h>
#include "tunnel_detection_dns.h"
#include "parser_pcap_dns.h"
#include "b_plus_tree.h"
 #include "prefix_tree.h"

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "DNS-tunnel-detection module", // Module name
   // Module description
   "Modul that detects DNS tunnels on the network.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "   -p N        Show progess - print a dot every N flows.\n"
   "   -s          Write results into file. Specify folder for data saving.\n"
   "   -d          File with list of ip exception which will not be analysed\n"   
   "   -e          File with list of domain exception which will not be analysed\n"
   "   -f          Read packets from file\n"   
   "   -g          Set Max and Min EX and VAR for suspision in requests, [MIN EX, MAX EX, MIN VAR, MAX VAR]\n" 
   "   -h          Set Max and Min EX and VAR for suspision in responses, [MIN EX, MAX EX, MIN VAR, MAX VAR]\n" 
   "   -j          Set Max count of used letters not to be in suspision mode [MAX number for Request, MAX number for response]\n"
   "   -k          Max and Min percent of subdomain [MAX, MIN]\n" 
   "   -l          Max count of numbers in domain not to be in suspiction mode [MAX, MIN]\n"  
   "   -l          Max count and percent of numbers in domain not to be in suspiction mode [MAX count, MAX percent]\n"  
   "   -m          Max percent of mallformed packet to be in traffic anoly [MAX]\n"  
   "   -n          MIN count of suspected requests to be traffic anomaly or tunnel [MIN for traffic anomaly, MIN for tunnel]\n" 
   "   -o          MIN count of suspected responses to be traffic anomaly or tunnel [MIN for traffic anomaly, MIN for tunnel]\n" 
   "   -q          Max and Min percent of searching just ones [MAX, MIN]\n"  
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;
static int stats = 0;
static int progress = 0;
static values_t values;
void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   } else if (signal == SIGUSR1) {
      stats = 1;
   }
}


ip_address_t * crete_new_ip_address_struc( uint64_t * ip, ip_address_t * next){
   ip_address_t * create;
   create = (ip_address_t *) calloc(sizeof(ip_address_t),1); 
   //write next list item
   create->next = next;
   return create; 
}

ip_address_t * find_ip(uint64_t * search_ip, ip_address_t * struc){
   //if it is on the end of the list or it found item
   //if(struc == NULL || (struc->ip[0] ==  search_ip[0] && struc->ip[1] ==  search_ip[1]))
     // return struc;
   //recursive call function on next item in list
   //return find_ip(search_ip, struc->next);
}

 void get_ip_str_from_ip_struct(ip_address_t * item, void * key,  char * ip_buff){
   ip_addr_t ip_to_translate;
   //*ip_buff=0;
   uint64_t * ip = (uint64_t *)key;
   if(item->ip_version == IP_VERSION_4){
      ip_to_translate = ip_from_int(ip[1]);
   }else{
      ip_to_translate = ip_from_16_bytes_be((char*)&ip[0]);
   }
   ip_to_str(&ip_to_translate ,ip_buff);
   
}

ip_address_t * add_to_list( ip_address_t * list_of_ip, uint64_t * ip_in_packet, int size, char request){
   ip_address_t * found;
   float size2;
   size2=size*size;
   found = find_ip(ip_in_packet, list_of_ip);
   //if item was not found or list is free, create new item
   if (found == NULL){
      found = crete_new_ip_address_struc(ip_in_packet, list_of_ip);
      list_of_ip=found;
   }
   //add to request or response
   if(request == 1){
      found->histogram_dns_requests[size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
      found->dns_request_count++;
      //calculate sums for statistic
      found->sum_Xi_request += size;
      found->sum_Xi2_request += size2;
      found->sum_Xi3_request += size2*size;
      found->sum_Xi4_request += size2*size2;

   }
   else{
      found->histogram_dns_response[size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
      found->dns_response_count++;
      //calculate sums for statistic
      found->sum_Xi_response += size;
      found->sum_Xi2_response += size2;
      found->sum_Xi3_response += size2*size;
      found->sum_Xi4_response += size2*size2;

   }
   return list_of_ip;
}

int filter_trafic_to_save_in_prefix_tree_tunnel_suspiction( character_statistic_t * char_stat){
   if(char_stat->count_of_different_letters > values.request_max_count_of_used_letters ||     //just domains which have a lot of letters
      ((double)char_stat->count_of_numbers_in_string / (double)char_stat->length > values.max_percent_of_numbers_in_domain_prefix_tree_filter && //just domains which have a lot of numbers
      char_stat->count_of_numbers_in_string > values.max_count_of_numbers_in_domain_prefix_tree_filter))
   {
      return 1;
   }
   return 0;
}


void add_to_bplus_tree( void * tree, uint64_t * ip_in_packet, int size, char request, packet_t * packet){
   ip_address_t * found;
   b_plus_tree_item  item;
   float size2;
   int index_to_histogram;
   character_statistic_t char_stat;
   size2=size*size;
   //found or create in b plus tree
   found = (ip_address_t*)create_or_find_struct_b_plus_tree(tree, (void*)ip_in_packet, &item);
   found->ip_version = packet->ip_version;

   //add to request or response
   if(request == 1){
      //calculate index in histogram
      index_to_histogram = size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_REQUESTS - 1;

      found->histogram_dns_requests[index_to_histogram]++;
      found->dns_request_count++;
      //calculate sums for statistic
      found->sum_Xi_request += size;
      found->sum_Xi2_request += size2;
      found->sum_Xi3_request += size2*size;
      found->sum_Xi4_request += size2*size2;

         //packet has request string
         if(packet->request_length > 0){
            found->dns_request_string_count++;
            found->histogram_dns_request_sum_for_cout_of_used_letter[index_to_histogram]++;
            calculate_character_statistic(packet->request_string, &char_stat);
            found->histogram_dns_request_ex_sum_of_used_letter[index_to_histogram] += char_stat.count_of_different_letters;
            //filter to immediatly save into prefix tree, if there is proofed tunnel, than dont capture more
            if( !(found->state_request & STATE_TUNNEL) &&  filter_trafic_to_save_in_prefix_tree_tunnel_suspiction(&char_stat)){
               if(found->suspision_request == NULL){
                  found->suspision_request = (ip_address_suspision_request_t*)calloc(sizeof(ip_address_suspision_request_t),1);
               }
               if(found->suspision_request->tunnel_suspision == NULL){   
                  found->suspision_request->tunnel_suspision = inicialize_prefix_tree();
               }
               add_to_prefix_tree(found->suspision_request->tunnel_suspision, packet->request_string, char_stat.length, &char_stat);
               found->state_request |= STATE_SUSPISION;
            }
            //add to prefix tree, if ip is in suspision state
            if((found->state_request & STATE_SUSPISION) && found->suspision_request && found->suspision_request->state_request_size[index_to_histogram] & STATE_OTHER_ANOMALY){
               //printf(" add request %s %d\n", packet->request_string, char_stat.length);
               add_to_prefix_tree(found->suspision_request->other_suspision, packet->request_string, char_stat.length, &char_stat);          
            }
         }
         else{
            found->request_without_string++;
         }

      }  
   else{
      //calculate index in histogram
      index_to_histogram = size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1;

      found->histogram_dns_response[size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
      found->dns_response_count++;
      //calculate sums for statistic
      found->sum_Xi_response += size;
      found->sum_Xi2_response += size2;
      found->sum_Xi3_response += size2*size;
      found->sum_Xi4_response += size2*size2;

      //tunnel detection
      if(!(found->state_response & STATE_TUNNEL)){
         if(packet->txt_response[0]!=0){
            calculate_character_statistic(packet->txt_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response == NULL){
                  found->suspision_response = (ip_address_suspision_response_t*)calloc(sizeof(ip_address_suspision_response_t),1);
               }
               if(found->suspision_response->txt_suspision == NULL){
                  found->suspision_response->txt_suspision = inicialize_prefix_tree();
               }
               //printf(" add txt %s %d\n", packet->txt_response, char_stat.length);
               add_to_prefix_tree(found->suspision_response->txt_suspision, packet->txt_response, char_stat.length, &char_stat);
               found->state_response |= STATE_SUSPISION;
            }
         }
         if(packet->cname_response[0]!=0){
            calculate_character_statistic(packet->cname_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response == NULL){
                  found->suspision_response = (ip_address_suspision_response_t*)calloc(sizeof(ip_address_suspision_response_t),1);
               }
               if(found->suspision_response->cname_suspision == NULL){
                  found->suspision_response->cname_suspision = inicialize_prefix_tree();
               }
               //printf(" add cname %s %d\n", packet->cname_response, char_stat.length);
               add_to_prefix_tree(found->suspision_response->cname_suspision, packet->cname_response, char_stat.length, &char_stat);
               found->state_response |= STATE_SUSPISION;
            }
         }
         if(packet->mx_response[0]!=0){
            calculate_character_statistic(packet->mx_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response == NULL){
                  found->suspision_response = (ip_address_suspision_response_t*)calloc(sizeof(ip_address_suspision_response_t),1);
               }        
               if(found->suspision_response->mx_suspision == NULL){
                  found->suspision_response->mx_suspision = inicialize_prefix_tree();
               }
              // printf(" add mx %s %d\n", packet->mx_response, char_stat.length);
               add_to_prefix_tree(found->suspision_response->mx_suspision, packet->mx_response, char_stat.length, &char_stat); 
               found->state_response |= STATE_SUSPISION;   
            }
         }
         if(packet->ns_response[0]!=0){
            calculate_character_statistic(packet->ns_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response == NULL){
                  found->suspision_response = (ip_address_suspision_response_t*)calloc(sizeof(ip_address_suspision_response_t),1);
               } 
               if(found->suspision_response->ns_suspision == NULL){
                  found->suspision_response->ns_suspision = inicialize_prefix_tree();
               }
               //printf(" add ns %s %d\n", packet->ns_response, char_stat.length);
               add_to_prefix_tree(found->suspision_response->ns_suspision, packet->ns_response, char_stat.length, &char_stat);
               found->state_response |= STATE_SUSPISION;
            }
         }
      }

   }
}

void free_ip_list(ip_address_t * list){
      ip_address_t * next_item;
   while(list != NULL){
      next_item = list->next;
      free(list);
      list=next_item;
   }
}

void calculate_character_statistic(char * string, character_statistic_t * stat){
   char letter;
   char used[255];
   int i;
   memset(used, 0, 255);
   stat->count_of_different_letters = 0;
   stat->count_of_numbers_in_string = 0;
   stat->length = 0;
   while(*string != 0){
      used[*string]++;
      if(*string>='0' && *string<='9'){
         stat->count_of_numbers_in_string++;
      }
      string++;
      stat->length++;
   }

   //count used letters
   for(i=0; i<255; i++){
      if(used[i]!=0){
         stat->count_of_different_letters++;
      }
   }

}


void calculate_statistic(ip_address_t * ip_rec, calulated_result_t * result){
   float xn2_request;
   float xn2_response;


   //calculate ex
   //ex = Sum(Xi) / n
   result->ex_request = (float)ip_rec->sum_Xi_request / (float)ip_rec->dns_request_count;
   result->ex_response = (float)ip_rec->sum_Xi_response / (float)ip_rec->dns_response_count;

   xn2_request = result->ex_request * result->ex_request;
   xn2_response = result->ex_response * result->ex_response;

   //calculate var
   // var x = (Sum(Xi^2) - Xn^2 * n) / (n-1)
   result->var_request = (float)(ip_rec->sum_Xi2_request - xn2_request * ip_rec->dns_request_count ) / (float)(ip_rec->dns_request_count - 1);
   result->var_response = (float)(ip_rec->sum_Xi2_response - xn2_response * ip_rec->dns_response_count ) / (float)(ip_rec->dns_response_count - 1);

   //calculace skewness
   //skewness = n * (Sum(Xi^4) - 4 * Xn * Sum(Xi^3)  +  6 * Xn^2 * Sum(Xi^2) - 4 * Xn^3 * Sum(Xi) + Xn^4 * n ) / (var x)^2
   result->skewness_request = (float)((ip_rec->sum_Xi4_request - 
                              4 * result->ex_request * ip_rec->sum_Xi3_request  +  
                              6 * xn2_request * ip_rec->sum_Xi2_request - 
                              4 * result->ex_request * xn2_request  * ip_rec->sum_Xi_request + 
                              xn2_request * xn2_request * ip_rec->dns_request_count) *
                              ip_rec->dns_request_count) /
                              (float)(result->var_request * result->var_request);
   result->skewness_response = (float)((ip_rec->sum_Xi4_response - 
                              4 * result->ex_response * ip_rec->sum_Xi3_response  +  
                              6 * xn2_response * ip_rec->sum_Xi2_response - 
                              4 * result->ex_response * xn2_response  * ip_rec->sum_Xi_response + 
                              xn2_response * xn2_response * ip_rec->dns_response_count) *
                              ip_rec->dns_response_count) /
                              (float)(result->var_response * result->var_response);

   //calculace kurtosis
   //kurtosis = n^(1/2) * (Sum(Xi^3) - 3 * Sum(Xi^2) * Xn  +  3 * Xn^2 * Sum(Xi) - Xn^3 * n ) / (var x)^(3/2)
   result->kurtosis_request = (float)((ip_rec->sum_Xi3_request -
                              3 * ip_rec->sum_Xi2_request * result->ex_request + 
                              3 * xn2_request * ip_rec->sum_Xi_request -
                              xn2_request * result->ex_request * ip_rec->dns_request_count) * 
                              sqrtf((float)ip_rec->dns_request_count)) /
                              sqrtf((float)(result->var_request * result->var_request * result->var_request));
   result->kurtosis_response = (float)((ip_rec->sum_Xi3_response -
                              3 * ip_rec->sum_Xi2_response * result->ex_response + 
                              3 * xn2_response * ip_rec->sum_Xi_response -
                              xn2_response * result->ex_response * ip_rec->dns_response_count) * 
                              sqrtf((float)ip_rec->dns_response_count)) /
                              sqrtf((float)(result->var_response * result->var_response * result->var_response));

   //calculate ex of used letters
   result->ex_request_count_of_different_letters = 0;
   result->var_request_count_letters = 0;
   for (int i=0; i < HISTOGRAM_SIZE_REQUESTS; i++){
      if(ip_rec->histogram_dns_request_sum_for_cout_of_used_letter[i] > 0){
         result->histogram_dns_request_ex_cout_of_used_letter[i] = (float)ip_rec->histogram_dns_request_ex_sum_of_used_letter[i] / (float)ip_rec->histogram_dns_request_sum_for_cout_of_used_letter [i];
         result->ex_request_count_of_different_letters += result->histogram_dns_request_ex_cout_of_used_letter[i];
         result->var_request_count_letters += result->histogram_dns_request_ex_cout_of_used_letter[i] * result->histogram_dns_request_ex_cout_of_used_letter[i];
      }
      else{
         result->histogram_dns_request_ex_cout_of_used_letter[i] =0;
      }
   }

   result->ex_request_count_of_different_letters /= (float)ip_rec->dns_request_string_count;
   result->var_request_count_letters /= (float)ip_rec->dns_request_string_count;
   result->var_request_count_letters -=  result->ex_request_count_of_different_letters * result->ex_request_count_of_different_letters;
}

void check_and_delete_suspision(ip_address_t * item_to_delete, unsigned char part){
   if(part & REQUEST_PART){
      if(item_to_delete->suspision_request != NULL){
         if(item_to_delete->suspision_request->tunnel_suspision != NULL){
            destroy_prefix_tree(item_to_delete->suspision_request->tunnel_suspision);
         }
         if(item_to_delete->suspision_request->other_suspision != NULL){
            destroy_prefix_tree(item_to_delete->suspision_request->other_suspision);
         }
         free(item_to_delete->suspision_request);
         item_to_delete->suspision_request = NULL;
      }
   }
   if(part & RESPONSE_PART){
      if(item_to_delete->suspision_response != NULL){
         if(item_to_delete->suspision_response->cname_suspision != NULL){
            destroy_prefix_tree(item_to_delete->suspision_response->cname_suspision);
         }
         if(item_to_delete->suspision_response->txt_suspision != NULL){
            destroy_prefix_tree(item_to_delete->suspision_response->txt_suspision);
         }
         if(item_to_delete->suspision_response->ns_suspision != NULL){
            destroy_prefix_tree(item_to_delete->suspision_response->ns_suspision);
         }
         if(item_to_delete->suspision_response->mx_suspision != NULL){
            destroy_prefix_tree(item_to_delete->suspision_response->mx_suspision);
         }
         free(item_to_delete->suspision_response);
         item_to_delete->suspision_response = NULL;
      }
   }

}


int is_traffic_on_ip_ok_request(ip_address_t * item, calulated_result_t * result){
   int i;
   //if there is more traffic than minimum
   if(!(item->state_request & STATE_OTHER_ANOMALY) && item->dns_request_count > values.min_dns_request_count){
      //other anomaly can be caused, then select the peaks, which have most of communication
      //printf("ex %f var %f\n",result->ex_request, result->var_request);
      if( result->ex_request < values.ex_request_min || result->var_request < values.var_request_min || result->var_request > values.var_request_max || result->ex_request > values.ex_request_max /*|| result->kurtosis_request < values.kurtosis_request_min*/){
         int max;
         item->state_request |= STATE_SUSPISION;
         //if it is first suspision
         if(item->suspision_request == NULL){
            item->suspision_request = (ip_address_suspision_request_t*)calloc(sizeof(ip_address_suspision_request_t),1);
         }
         //if it is first other suspision
         if(item->suspision_request->other_suspision == NULL){
            item->suspision_request->other_suspision = inicialize_prefix_tree();
         }      
         max = 0;
         for(i = max; i < HISTOGRAM_SIZE_REQUESTS ; i++){
            //select the biggest peak
            if (item->histogram_dns_requests[i] > item->histogram_dns_requests[max]){
               max = i;
            }
            //selecet everything what have more than certain amount of traffic and is not in tunnel detection tree
            if((float)item->histogram_dns_requests[i] / (float)item->dns_request_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPISION && 
               result->histogram_dns_request_ex_cout_of_used_letter[i] < values.request_max_count_of_used_letters ){
                  item->suspision_request->state_request_size[i] |= STATE_OTHER_ANOMALY;
            }
         }
         //the biggest peak
         item->suspision_request->state_request_size[max] |= STATE_OTHER_ANOMALY;
      }
      if((double)item->request_without_string / (double)item->dns_request_count > values.max_percent_of_mallformed_packet_request){
         item->state_request = STATE_OTHER_ANOMALY;
      }
   }
   if(item->state_request == STATE_NEW){
      return STATE_OK;
   }
   return STATE_SUSPISION;

}

int is_traffic_on_ip_ok_response(ip_address_t * item, calulated_result_t * result){
   int i;
   //responses
   if( !(item->state_response & STATE_OTHER_ANOMALY) && item->dns_response_count > values.min_dns_response_count_other_anomaly){
      if( result->ex_response < values.ex_response_min || result->var_response < values.var_response_min || result->var_response > values.var_response_max || result->ex_response > values.ex_response_max /*|| result->kurtosis_request < values.kurtosis_request_min*/){
         item->state_response |= STATE_OTHER_ANOMALY;
      }
   }
   if(item->state_response == STATE_NEW){
      return STATE_OK;
   }
   return STATE_SUSPISION;
}


int is_payload_on_ip_ok_request(ip_address_t * item){
   int i;
   prefix_tree_t *tree;
   if((item->state_request & STATE_SUSPISION) && item->suspision_request != NULL){
      //tunnel detection request
      if(!(item->state_request & STATE_TUNNEL) && item->suspision_request->tunnel_suspision != NULL){
         tree = item->suspision_request->tunnel_suspision;  
         //percent of count of subdomains, is bigger than x percent
         if(tree->count_of_searching > values.min_dns_request_count_tunnel &&
            (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
            (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) > values.max_percent_of_unique_domains   //percent of unique domains
            ){  //percent of unique search
            item->state_request |= STATE_TUNNEL;
         }
      }
      //other anomaly detection request  
     if(!(item->state_request & STATE_OTHER_ANOMALY) && item->suspision_request->other_suspision != NULL){
         tree = item->suspision_request->other_suspision;
         if (tree->count_of_searching > values.min_dns_request_count_other_anomaly &&
            (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
            (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) < values.min_percent_of_unique_domains   //percent of unique domains
         ){
            //printf("print just ones %f\n", (float)tree->count_of_domain_searched_just_ones / (float)item->dns_request_count );
               item->state_request |= STATE_OTHER_ANOMALY;

         }
      }
      //if there wasnt any payload problem
      if(!(item->state_request & STATE_TUNNEL) && !(item->state_request & STATE_OTHER_ANOMALY)){
         item->round_in_suspiction_request++;
         //maximum round in suspiction
         if(item->round_in_suspiction_request > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
            item->round_in_suspiction_request = 0;
            check_and_delete_suspision(item, REQUEST_PART);
            item->state_request = STATE_NEW;
            if(item->suspision_request!= NULL){
            }
         }
      }
      else if ((item->state_request & STATE_TUNNEL) && (item->state_request & STATE_OTHER_ANOMALY)){
         item->state_request &= ~STATE_SUSPISION;
         if(item->state_request ==STATE_NEW &&  item->suspision_request!= NULL){;
         }
      }
   }   
   if(item->state_request == STATE_NEW){
      return STATE_OK;
   }
   return STATE_SUSPISION;
}



int is_payload_on_ip_ok_response(ip_address_t * item){
   int i;
   prefix_tree_t *tree;
   //tunnel detection response
   if(!(item->state_response & STATE_TUNNEL) && item->state_response & STATE_SUSPISION){
      tree = item->suspision_response->txt_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL &&
         tree->count_of_searching > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response |= STATE_TUNNEL;
         item->suspision_response->state_type |= TXT_TUNNEL;

      }
      tree = item->suspision_response->mx_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL && 
         tree->count_of_searching > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response |= STATE_TUNNEL;
         item->suspision_response->state_type |= MX_TUNNEL;
      }
      tree = item->suspision_response->cname_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL && 
         tree->count_of_searching > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response |= STATE_TUNNEL;
         item->suspision_response->state_type |= CNAME_TUNNEL;
      }
      tree = item->suspision_response->ns_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL && 
         tree->count_of_searching > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response |= STATE_TUNNEL;
         item->suspision_response->state_type |= NS_TUNNEL;
      }
      //if there wasnt any payload problem
      if(!(item->state_response & STATE_TUNNEL)){
         item->round_in_suspiction_response++;
         //maximum round in suspiction
         if(item->round_in_suspiction_response > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
            item->round_in_suspiction_response = 0;
            check_and_delete_suspision(item, RESPONSE_PART);
            item->state_response = STATE_NEW;
         }
      }
   }

   if(item->state_response == STATE_NEW){
      return STATE_OK;
   }
   return STATE_SUSPISION;
}



void calculate_statistic_and_choose_anomaly(void * b_plus_tree){
   ip_address_t * item;
   ip_address_t * previous = NULL;
   ip_address_t * start;
   b_plus_tree_item b_item;
   int is_there_next=0;
   unsigned char payload_state_request = STATE_OK, 
                 traffic_state_request = STATE_OK,
                 payload_state_response = STATE_OK, 
                 traffic_state_response = STATE_OK;
   calulated_result_t result;
   is_there_next = get_list(b_plus_tree, &b_item);

   while(is_there_next == 1){
      item = (ip_address_t*)b_item.value;

      calculate_statistic(item, &result);
      //without anomaly

      if(item->state_request & STATE_SUSPISION ){
         payload_state_request = is_payload_on_ip_ok_request(item);
      }
      if(item->state_response & STATE_SUSPISION){
         payload_state_response = is_payload_on_ip_ok_response(item);
      }
      if(item->state_request == STATE_NEW || item->state_request & STATE_SUSPISION){
         traffic_state_request = is_traffic_on_ip_ok_request(item, &result);
      }
      if(item->state_response == STATE_NEW || item->state_response & STATE_SUSPISION){
         traffic_state_response = is_traffic_on_ip_ok_response(item, &result);
      }


      if(item->state_request == STATE_NEW && item->state_response == STATE_NEW){
         ip_address_t * item_to_delete;
         /*
         if(previous == NULL){
            start = item->next;
            //free(item);
            item_to_delete = item;
            item = item->next;
         }
         else{
            previous->next=item->next;
            //free(item);
            item_to_delete = item;
            item=previous->next;
         }*/
         is_there_next = delete_item_b_plus_tree(b_plus_tree, &b_item);

      }
      //with anomaly
      else{
         /*previous=item;
         item=item->next;*/
         is_there_next = get_next_item_from_list(b_plus_tree, &b_item);
      }
   }
   //return anomaly items
   //return start;
}

void print_results(char * record_folder_name, void * b_plus_tree){
   prefix_tree_domain_t *dom;
   FILE *file;
   char file_path [255];
   char ip_buff[100] = {0};
   ip_address_t *item;
   b_plus_tree_item b_item;
   int is_there_next;
   //open files
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_FOUND_ANOMALY);
   file = fopen(file_path, "w");
   if(file == NULL){
      return;
   }   
   char str[1024];
   //printing result
   is_there_next = get_list(b_plus_tree, &b_item);
   while(is_there_next == 1){
      item = (ip_address_t*)b_item.value;

      if(item->state_request & STATE_TUNNEL || item->state_request & STATE_OTHER_ANOMALY || item->state_response & STATE_OTHER_ANOMALY || item->state_request & STATE_TUNNEL){
         get_ip_str_from_ip_struct(item,b_item.key, ip_buff);
         fprintf(file, "\n%s\n", ip_buff);
      }
      //print founded anomaly tunnel
      if(item->state_request & STATE_TUNNEL){
         fprintf(file, "\tRequest tunnel found:\tDomain searched just once: %f.\tcount of different domains: %f.\tAll recorded requests: %d\n\t\tFound in sizes: ", (double)(item->suspision_request->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request->tunnel_suspision->count_of_searching_for_just_ones), (double)item->suspision_request->tunnel_suspision->count_of_different_domains/(double)(item->suspision_request->tunnel_suspision->count_of_searching_for_just_ones),(item->suspision_request->tunnel_suspision->count_of_searching) );
         for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
            if(item->suspision_request->state_request_size[i] & STATE_TUNNEL)
            fprintf(file, "%d-%d\t", i*10,i*10+10);
         } 
         fprintf(file, "\n");

         dom =item->suspision_request->tunnel_suspision->list_of_most_unused_domains;
         for(int i=0; i<5;i++){
            str[0]=0;
            if(dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
            dom= dom->most_used_domain_less;
         }               
      }
      //print founded anomaly other in request
      if(item->state_request & STATE_OTHER_ANOMALY){  
         if(item->suspision_request != NULL){
            fprintf(file, "\tRequest traffic anomaly found:\tDomain searched just once: %f.\tCount of different domains: %f.\tAll recorded requests: %d.\tCount of malformed requests: %d.\n\t\tFound in sizes: ", (double)(item->suspision_request->other_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request->other_suspision->count_of_searching_for_just_ones), (double)item->suspision_request->other_suspision->count_of_different_domains/(double)(item->suspision_request->other_suspision->count_of_searching_for_just_ones),(item->suspision_request->other_suspision->count_of_searching), item->request_without_string  );
            for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
               if(item->suspision_request->state_request_size[i] & STATE_OTHER_ANOMALY)
               fprintf(file, "%d-%d\t", i*10,i*10+10);
            } 
            fprintf(file, "\n");
      
            dom =item->suspision_request->other_suspision->list_of_most_used_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
               dom= dom->most_used_domain_less;
            }
         }
         else{
            fprintf(file, "\tMallformed packets found:\tCount of malformed responses: %d.\n", item->request_without_string);

         }
      }

      //response tunnel
      if(item->state_response & STATE_TUNNEL){
         //txt
         if(item->suspision_response->state_type & TXT_TUNNEL){
            fprintf(file, "\tReponse TXT tunnel found:\tdomain searched just once: %f.\tcount of different domains: %f.\tall requests: %d.\n", (double)(item->suspision_response->txt_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response->txt_suspision->count_of_searching_for_just_ones), (double)item->suspision_response->txt_suspision->count_of_different_domains/(double)(item->suspision_response->txt_suspision->count_of_searching_for_just_ones),(item->suspision_response->txt_suspision->count_of_searching) );
            dom =item->suspision_response->txt_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
               dom= dom->most_used_domain_less;
            }        
         }
         //cname
         if(item->suspision_response->state_type & CNAME_TUNNEL){
            fprintf(file, "\tReponse CNAME tunnel found:\tdomain searched just once: %f.\tcount of different domains: %f.\tall requests: %d.\n", (double)(item->suspision_response->cname_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response->cname_suspision->count_of_searching_for_just_ones), (double)item->suspision_response->cname_suspision->count_of_different_domains/(double)(item->suspision_response->cname_suspision->count_of_searching_for_just_ones),(item->suspision_response->cname_suspision->count_of_searching) );
            dom =item->suspision_response->cname_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
               dom= dom->most_used_domain_less;
            }        
         }
         //ns
         if(item->suspision_response->state_type & NS_TUNNEL){
            fprintf(file, "\tReponse NS tunnel found:\tdomain searched just once: %f.\tcount of different domains: %f.\tall requests: %d.\n", (double)(item->suspision_response->ns_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response->ns_suspision->count_of_searching_for_just_ones), (double)item->suspision_response->ns_suspision->count_of_different_domains/(double)(item->suspision_response->ns_suspision->count_of_searching_for_just_ones),(item->suspision_response->ns_suspision->count_of_searching) );
            dom =item->suspision_response->ns_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
               dom= dom->most_used_domain_less;
            }        
         }  
         //mx
         if(item->suspision_response->state_type & MX_TUNNEL){
            fprintf(file, "\tReponse MX tunnel found:\tdomain searched just once: %f.\tcount of different domains: %f.\tall requests: %d.\n", (double)(item->suspision_response->mx_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response->mx_suspision->count_of_searching_for_just_ones), (double)item->suspision_response->mx_suspision->count_of_different_domains/(double)(item->suspision_response->mx_suspision->count_of_searching_for_just_ones),(item->suspision_response->mx_suspision->count_of_searching) );
            dom =item->suspision_response->mx_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
               dom= dom->most_used_domain_less;
            }        
         }
      }
      //print founded anomaly other in responses
      if(item->state_response & STATE_OTHER_ANOMALY){  
         calulated_result_t result;
         calculate_statistic(item, &result);
         fprintf(file, "\tReseponse anomaly found:\tEX: %f.\tVAR: %f.\tCount of responses %lu.\n", result.ex_response, result.var_response, item->dns_response_count);
         }
      

      
      is_there_next = get_next_item_from_list(b_plus_tree, &b_item);
   }
   print_suspision_ip(file, b_plus_tree);   
   fclose(file);
}

void print_suspision_ip(FILE * file, void * b_plus_tree){
   char ip_buff[100] = {0};
   b_plus_tree_item b_item;
   int is_there_next;
   ip_address_t * ip_item;
   is_there_next = get_list(b_plus_tree, &b_item);
   fprintf(file, "\nIP in SUSPISION STATE\n");
   while(is_there_next == 1){
      ip_item = (ip_address_t*)b_item.value;
      if(ip_item->state_request & STATE_SUSPISION){
         get_ip_str_from_ip_struct(ip_item ,b_item.key, ip_buff);
         fprintf(file, "%s\n", ip_buff);
      }
      is_there_next = get_next_item_from_list(b_plus_tree, &b_item);
   }

}


void write_summary_result(char * record_folder_name, unsigned long * histogram_dns_requests, unsigned long * histogram_dns_response){
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
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
      fprintf(file, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);
   //print values
   fprintf(file, "all \t");
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
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
   for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
      fprintf(file, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file, "%d-inf\n",(HISTOGRAM_SIZE_RESPONSE-1) * 10);
   //print values
   fprintf(file, "all \t");
   for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
      fprintf(file, "%lu\t",histogram_dns_response[i]);
   }    
   fprintf(file, "%lu\n", histogram_dns_response[HISTOGRAM_SIZE_RESPONSE -1]);
   fclose(file);
   
}
void write_detail_result(char * record_folder_name, void * b_plus_tree){
   FILE *file_requests, 
        *file_responses,
        *file_requests_count_letters;
   char ip_buff[100] = {0};
   char file_path [255];
   calulated_result_t result;
   int is_there_next;
   b_plus_tree_item b_item;
   ip_address_t * ip_item;

   //open files
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUESTS);
   file_requests = fopen(file_path, "w");
   if(file_requests == NULL){
      return;
   }
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_RESPONSES);
   file_responses = fopen(file_path, "w");  
   if(file_responses == NULL){
      return;
   } 
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUEST_COUNT_LETTERS);
   file_requests_count_letters = fopen(file_path, "w"); 
   if(file_requests_count_letters == NULL){
      return;
   }
   //print titles 
   fprintf(file_requests, TITLE_REQUESTS "\n");
   fprintf(file_requests_count_letters, TITLE_REQUEST_COUNT_LETTERS "\n");
   fprintf(file_responses, TITLE_RESPONSES "\n");
   //print range to requests
   fprintf(file_requests,  "ip__EX__VarX__Skewness__Kurtosis\t");
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){

      fprintf(file_requests, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);
   //print range to requests count letter 
   fprintf(file_requests_count_letters,  "ip__EX__VarX\t");
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
      fprintf(file_requests_count_letters, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests_count_letters, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);
   //print range to respones
   fprintf(file_responses,  "ip__EX__VarX__Skewness__Kurtosis\t");
   for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
      fprintf(file_responses, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_responses, "%d-inf\n",(HISTOGRAM_SIZE_RESPONSE-1) * 10);
   //print histogram of each IP
   //for each item in list
   is_there_next = get_list(b_plus_tree, &b_item);
   while(is_there_next == 1){
      ip_item = (ip_address_t*)b_item.value;
      //translate ip int to str 
      get_ip_str_from_ip_struct(ip_item, b_item.key, ip_buff);
      //count ex value
      calculate_statistic(ip_item, &result);
      //requests
      fprintf(file_requests, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_buff, result.ex_request, result.var_request, result.skewness_request, result.kurtosis_request);
      for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
         fprintf(file_requests, "%lu\t",ip_item->histogram_dns_requests[i]);
      }    
      fprintf(file_requests, "%lu\n", ip_item->histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS - 1]);  
      //requests count letter
      fprintf(file_requests_count_letters, "%s__EX=%f__VarX=%f\t", ip_buff, result.ex_request_count_of_different_letters, result.var_request_count_letters);
      for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
         fprintf(file_requests_count_letters, "%lu\t",result.histogram_dns_request_ex_cout_of_used_letter[i]);
      }
      fprintf(file_requests_count_letters, "%lu\n", result.histogram_dns_request_ex_cout_of_used_letter[HISTOGRAM_SIZE_REQUESTS - 1]); 
      //response
      fprintf(file_responses, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_buff, result.ex_response, result.var_response, result.skewness_response, result.kurtosis_response);
      for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
         fprintf(file_responses, "%lu\t",ip_item->histogram_dns_response[i]);
      }
      fprintf(file_responses, "%lu\n", ip_item->histogram_dns_response[HISTOGRAM_SIZE_RESPONSE - 1]); 
      //next item
      is_there_next = get_next_item_from_list(b_plus_tree, &b_item);
   }
   fclose(file_requests);
   fclose(file_requests_count_letters);
   fclose(file_responses);

}

int compare_ipv6(void * a, void * b){
   uint64_t *h1, *h2;

   h1 = (uint64_t*)a;
   h2 = (uint64_t*)b;
   if (h1[0] == h2[0]){
      if(h1[1] == h2[1]){
         return EQUAL;
      }
      else if(h1[1] < h2[1]){
         return LESS;
      }      
      else{
         return MORE;
      }
   } 
   else if(h1[0] < h2[0]){
      return LESS;
   }
   else if(h1[0] > h2[0]){
      return MORE;
   }

}

void load_default_values(){
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
}

int main(int argc, char **argv)
{
   int ret;
   void * btree;
   prefix_tree_t * preftree;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   unsigned long histogram_dns_requests [HISTOGRAM_SIZE_REQUESTS];
   unsigned long histogram_dns_response [HISTOGRAM_SIZE_RESPONSE];
   ip_address_t * list_of_ip = NULL;
   char write_summary = 0;
   memset(histogram_dns_requests, 0, HISTOGRAM_SIZE_REQUESTS * sizeof(unsigned long));
   memset(histogram_dns_response, 0, HISTOGRAM_SIZE_RESPONSE * sizeof(unsigned long));

   //load default values from defined constants
   load_default_values();
   // ***** TRAP initialization *****
   
   //TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGUSR1, signal_handler);
   
   // ***** Create UniRec template *****
   
   char *unirec_specifier = "<COLLECTOR_FLOW>";
   char opt;
   char *record_folder_name = NULL;
   char *input_packet_file_name = NULL;
   char *domains_exception_file_name = NULL;
   char *ip_exception_file_name = NULL;
   while ((opt = getopt(argc, argv, "u:p:s:f:e:g:h:j:k:l:m:n:o:q:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'p':
            progress = atoi(optarg);
            break;
         case 's':
            record_folder_name = optarg;
            write_summary = 1;
            //if the folder does not exist it will create
            mkdir(optarg,  S_IRWXU|S_IRGRP|S_IXGRP);
            break;
         case 'd':
            ip_exception_file_name = optarg;
            break;
         case 'e':
            domains_exception_file_name = optarg;
            break;
         case 'f':
            input_packet_file_name = optarg;
            break;
         case 'g':
            if (sscanf(optarg, "%d,%d,%d,%d", &values.ex_request_min, &values.ex_request_max, &values.var_request_min, &values.var_request_max) != 4) {
               fprintf(stderr, "Missing 'g' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'h':
            if (sscanf(optarg, "%d,%d,%d,%d", &values.ex_response_min, &values.ex_response_max, &values.var_response_min, &values.var_response_max) != 4) {
               fprintf(stderr, "Missing 'h' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'j':
            if (sscanf(optarg, "%d,%d", &values.request_max_count_of_used_letters, &values.response_max_count_of_used_letters) != 2) {
               fprintf(stderr, "Missing 'j' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'k':
            if (sscanf(optarg, "%f,%f", &values.max_percent_of_new_subdomains, &values.min_percent_of_new_subdomains) != 2) {
               fprintf(stderr, "Missing 'k' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'l':
            if (sscanf(optarg, "%d,%f", &values.max_count_of_numbers_in_domain_prefix_tree_filter, &values.max_percent_of_numbers_in_domain_prefix_tree_filter) != 2) {
               fprintf(stderr, "Missing 'l' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'm':
            if (sscanf(optarg, "%f", &values.max_percent_of_mallformed_packet_request) != 1) {
               fprintf(stderr, "Missing 'm' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'n':
            if (sscanf(optarg, "%d,%d", &values.min_dns_request_count_other_anomaly, &values.min_dns_request_count_tunnel) != 2) {
               fprintf(stderr, "Missing 'n' argument with number of links\n");
               goto failed_trap;
            }
            break;
         case 'o':
            if (sscanf(optarg, "%d,%d", &values.min_dns_response_count_other_anomaly, &values.min_dns_response_count_tunnel) != 2) {
               fprintf(stderr, "Missing 'o' argument with number of links\n");
               goto failed_trap;
            }
            break;   
         case 'q':
            if (sscanf(optarg, "%f,%f", &values.max_percent_of_domain_searching_just_once, &values.min_percent_of_domain_searching_just_once) != 2) {
               fprintf(stderr, "Missing 'q' argument with number of links\n");
               goto failed_trap;
            }
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 3;
      }
   }
   
   ur_template_t *tmplt = ur_create_template(unirec_specifier);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return 4;
   }

   
   //inicialize b+ tree ipv6
   btree = inicialize_b_plus_tree(5, &compare_ipv6, sizeof(ip_address_t), sizeof(uint64_t)*2);

   //inicialize prefix tree
   preftree = inicialize_prefix_tree();

   //add exceptions to prefix tree, if the file is specified
   if(domains_exception_file_name != NULL){
      FILE *file;
      int sign;
      int length;
      char domain[MAX_SIZE_OF_REQUEST_DOMAIN];
      file = fopen ( domains_exception_file_name, "r" );
      if(file == NULL){
         fprintf(stderr, "Error: Input file couldn`t be opened.\n");
         trap_finalize();
         return 1;
      }       
      //read domains
      sign = fgetc(file);
      while(sign != -1){
         length = 0;
         while(sign != '\n' && sign != -1){
            if(sign != '\t' && sign != ' '){
               domain[length++] = sign;
            }
            sign = fgetc(file);
         }
         domain[length] = 0;
         if(length != 0){
            add_exception_to_prefix_tree(preftree,domain ,length);
         }
         sign = fgetc(file);
      }
      fclose(file);
   }

  
   // ***** Main processing loop *****
   if(input_packet_file_name==NULL){
      //read packets from interface
      while (!stop) {
         // Receive data from any interface, wait until data are available
         const void *data;
         char debug_ip_src[INET6_ADDRSTRLEN];
         uint16_t data_size;
         ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
         TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
         
         // Check size of received data
         if (data_size < ur_rec_static_size(tmplt)) {
            if (data_size <= 1) {
               break; // End of data (used for testing purposes)
            }
            else {
               fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                       ur_rec_static_size(tmplt), data_size);
               break;
            }
         }
         
         if (progress > 0 && cnt_flows % progress == 0) {
            printf(".");
            fflush(stdout);
         }
         
         //is it destination port of DNS (Port 53)
         if(ur_get(tmplt, data, UR_DST_PORT) == 53){
            int size;
            ip_addr_t * ip_in_packet;
            uint64_t ip_in_packet_int [2];
            // Update counters
            size = ur_get(tmplt, data, UR_BYTES);
            ip_in_packet = & ur_get(tmplt, data, UR_SRC_IP);
            ip_in_packet_int[0] = 0;
            ip_in_packet_int[1] = ip_get_v4_as_int(ip_in_packet);
            if(ip_is4(ip_in_packet))
               list_of_ip = add_to_list(list_of_ip, ip_in_packet_int, size, 1);
            histogram_dns_requests[size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
         }
         //is it source port of DNS (Port 53)
         else if(ur_get(tmplt, data, UR_SRC_PORT) == 53){
            int size;
            ip_addr_t * ip_in_packet;
            uint64_t ip_in_packet_int[2];
            // Update counters
            size = ur_get(tmplt, data, UR_BYTES);
            ip_in_packet = & ur_get(tmplt, data, UR_DST_IP);
            ip_in_packet_int[0] = 0;
            ip_in_packet_int[1] = ip_get_v4_as_int(ip_in_packet);
            if(ip_is4(ip_in_packet))
               list_of_ip = add_to_list(list_of_ip, ip_in_packet_int , size, 0);
            histogram_dns_response[size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
         }
         if (stats == 1) {
            printf("Time: %lu\n", (long unsigned int) time(NULL));
            signal(SIGUSR1, signal_handler);
            stats = 0;
         }
      }
   }
   else{
      //read packets from file
      //inicialization of parser
      FILE *input;
      packet_t  packet;
      double start_time=0, packet_time=0;
      input = parser_inicialize(input_packet_file_name);
      if(input == NULL){
         fprintf(stderr, "Error: Input file couldn`t be opened.\n");
         trap_finalize();
      return 1;
      }
      //loop till end of file
      while (!stop) {

         while(packet_time - start_time <= TIME_OF_ONE_SESSION && !stop){
            

            // Check if packet was recieved
            if (read_packet(input, &packet) == -1) {
               printf("Game over\n" );
               stop=1;
               break; // End of data (used for testing purposes)
            }

            //read packet time
            if(start_time==0){
               start_time = packet.time;
            }
            packet_time = packet.time;



            
            if (progress > 0 && cnt_flows % progress == 0) {
               printf(".");
               fflush(stdout);
            }
            
            //is it destination port of DNS (Port 53) request
            if(packet.is_response==0){
               // Update counters
                  //add domain to prexit tree, when it is exception, this record will not be added to btree. Analysis will not see this packet
                  if(packet.request_length == 0 || add_to_prefix_tree(preftree, packet.request_string, packet.request_length, NULL) != NULL){
                     add_to_bplus_tree(btree, packet.src_ip, packet.size, 1, &packet);
                  }
               histogram_dns_requests[packet.size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
            }
            //is it source port of DNS (Port 53)
            else{
               // Update counters
               add_to_bplus_tree(btree, packet.dst_ip, packet.size, 0, &packet);
               histogram_dns_response[packet.size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
            }
            if (stats == 1) {
               printf("Time: %lu\n", (long unsigned int) time(NULL));
               signal(SIGUSR1, signal_handler);
               stats = 0;
            }
            //destroy recieved packet
            //destroy_packet(packet);

            
         }
         //restart timer
         start_time=0;
         packet_time=0;
         printf("end \n");
         //list_of_ip = get_list(btree);
         calculate_statistic_and_choose_anomaly(btree);
         //stop=1;         

      }
      //close reading from file
      parser_end(input);
   }
   
   // ***** Print results *****
 

/*
   if (progress > 0) {
      printf("\n");
   }
   printf("Flows:   %20lu\n", cnt_flows);
   printf("Packets: %20lu\n", cnt_packets);
   printf("Bytes:   %20lu\n", cnt_bytes);
   printf("********** HISTOGRAM *********\n");
   printf("***** REQUESTS *****\n");

   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
      printf("%d-%d    %lu\n",i * 10, (i + 1) * 10, histogram_dns_requests[i]);
   }
      printf("%d-inf   %lu\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10, histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS -1]);

      printf("\n***** RESPONSES *****\n");
   for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
      printf("%d-%d    %lu\n",i * 10, (i + 1) * 10, histogram_dns_response[i]);
   }
      printf("%d-inf   %lu\n",(HISTOGRAM_SIZE_RESPONSE-1) * 10, histogram_dns_response[HISTOGRAM_SIZE_RESPONSE -1]);

   //read the most used domain
      
   printf("\n");
   char str[256];

   prefix_tree_domain_t *dom =preftree->list_of_most_used_domains;
   //dom->count_of_different_subdomains=15;

   for(int i=0; i<10;i++){
      str[0]=0;
      printf("%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
      dom= dom->most_used_domain_less;

   }
   */
   

   // *****  Write into file ******
   if (write_summary){
      //list_of_ip = get_list(btree);
      if(list_of_ip != NULL){
         //list_of_ip=calculate_statistic_and_choose_anomaly(list_of_ip, btree);
         write_summary_result(record_folder_name, histogram_dns_requests, histogram_dns_response);
         write_detail_result(record_folder_name, btree);
         print_results(record_folder_name, btree); 
      }

   }
   
   


   // ***** Cleanup *****
   while(list_of_ip!=NULL){
      check_and_delete_suspision(list_of_ip, REQUEST_AND_RESPONSE_PART);
      list_of_ip = list_of_ip->next;
   }
   destroy_b_plus_tree(btree);
   destroy_prefix_tree(preftree);

   //free_ip_list(list_of_ip);
   // Do all necessary cleanup before exiting
failed_trap:
   //TRAP_DEFAULT_FINALIZATION();
   trap_finalize();
   ur_free_template(tmplt);
   
   return 0;
   

}

