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
   "   -u TMPLT    UniRec template for the input interface.\n"
   "   -p N        Show progess - print a dot every N flows.\n"
   "   -s          Write results into file. Specify folder for data saving.\n"
   "   -d          File with the list of ip whitelist (will not be analysed)\n"
   "   -e          File with the list of domain whitelist (will not be analysed)\n"
   "   -f          Read packets from file\n"
   "   -g          Set Max and Min EX and VAR for suspision in requests, [MIN EX, MAX EX, MIN VAR, MAX VAR]\n"
   "   -h          Set Max and Min EX and VAR for suspision in responses, [MIN EX, MAX EX, MIN VAR, MAX VAR]\n"
   "   -j          Set Max count of used letters not to be in suspision state [MAX number for Request, MAX number for response]\n"
   "   -k          Max and Min percent of subdomain [MAX, MIN]\n"
   "   -l          Max count of digits in domain not to be in suspiction state [MAX, MIN]\n"
   "   -l          Max count and percentage of digits in domain not to be in suspision state [MAX count, MAX percent]\n"
   "   -m          Max percent of malformed packets to mark as anomaly [MAX]\n"
   "   -n          MIN count of suspected requests to mark as anomaly or tunnel [MIN for traffic anomaly, MIN for tunnel]\n"
   "   -o          MIN count of suspected responses to mark as anomaly or tunnel [MIN for traffic anomaly, MIN for tunnel]\n"
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
   //create->next = next;
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
   
   if(item->ip_version == IP_VERSION_4){
      uint32_t * ip = (uint32_t *)key;
      ip_to_translate = ip_from_int(*ip);
   }else{
      uint64_t * ip = (uint64_t *)key;
      ip_to_translate = ip_from_16_bytes_be((char*)&ip[0]);
   }
   ip_to_str(&ip_to_translate ,ip_buff);
   
}

ip_address_t * add_to_list( ip_address_t * list_of_ip, uint64_t * ip_in_packet, int size, char request){
  /* ip_address_t * found;
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
   return list_of_ip;*/
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


void collection_of_information_and_basic_payload_detection( void * tree, void * ip_in_packet, int size, char request, packet_t * packet){
   ip_address_t * found;
   float size2;
   int index_to_histogram;
   character_statistic_t char_stat;
   size2=size*size;
   //found or create in b plus tree
   found = (ip_address_t*)b_plus_tree_insert_or_find_item(tree,ip_in_packet);
   found->ip_version = packet->ip_version;

   //add to request or response
   if(request == 1){
      //calculate index in histogram
      index_to_histogram = size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_REQUESTS - 1;

      found->counter_request.histogram_dns_requests[index_to_histogram]++;
      found->counter_request.dns_request_count++;
      //calculate sums for statistic
      found->counter_request.sum_Xi_request += size;
      found->counter_request.sum_Xi2_request += size2;
      found->counter_request.sum_Xi3_request += size2*size;
      found->counter_request.sum_Xi4_request += size2*size2;

         //packet has request string
         if(packet->request_length > 0){
            found->counter_request.dns_request_string_count++;
            found->counter_request.histogram_dns_request_sum_for_cout_of_used_letter[index_to_histogram]++;
            calculate_character_statistic(packet->request_string, &char_stat);
            found->counter_request.histogram_dns_request_ex_sum_of_used_letter[index_to_histogram] += char_stat.count_of_different_letters;
            //filter to immediatly save into prefix tree, if there is proofed tunnel, than dont capture more
            if( found->state_request_tunnel != STATE_ATTACK &&  filter_trafic_to_save_in_prefix_tree_tunnel_suspiction(&char_stat)){
               if(found->suspision_request_tunnel == NULL){
                  found->suspision_request_tunnel = (ip_address_suspision_request_tunnel_t*)calloc(sizeof(ip_address_suspision_request_tunnel_t),1);
               }
               if(found->suspision_request_tunnel->tunnel_suspision == NULL){   
                  found->suspision_request_tunnel->tunnel_suspision = prefix_tree_inicialize();
               }
               prefix_tree_add_domain(found->suspision_request_tunnel->tunnel_suspision, packet->request_string, char_stat.length, &char_stat);
               found->state_request_tunnel = STATE_SUSPISION;
            }
            //add to prefix tree, if ip is in suspision state, other anomaly
            if(found->state_request_other == STATE_SUSPISION && found->suspision_request_other && found->suspision_request_other->state_request_size[index_to_histogram] == STATE_ATTACK){
               //printf(" add request %s %d\n", packet->request_string, char_stat.length);
               prefix_tree_add_domain(found->suspision_request_other->other_suspision, packet->request_string, char_stat.length, &char_stat);          
            }
            //add to prefix tree, if ip is in suspision state, tunnel anomaly
            if(found->state_request_tunnel == STATE_SUSPISION && found->suspision_request_tunnel && found->suspision_request_tunnel->state_request_size[index_to_histogram] == STATE_ATTACK){
               //printf(" add request %s %d\n", packet->request_string, char_stat.length);
               prefix_tree_add_domain(found->suspision_request_tunnel->tunnel_suspision, packet->request_string, char_stat.length, &char_stat);          
            }            
         }
         else{
            found->counter_request.request_without_string++;
         }

      }  
   else{
      //calculate index in histogram
      index_to_histogram = size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1;

      found->counter_response.histogram_dns_response[size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
      found->counter_response.dns_response_count++;
      //calculate sums for statistic
      found->counter_response.sum_Xi_response += size;
      found->counter_response.sum_Xi2_response += size2;
      found->counter_response.sum_Xi3_response += size2*size;
      found->counter_response.sum_Xi4_response += size2*size2;


      if(found->state_response_other == STATE_SUSPISION && found->suspision_response_other && found->suspision_response_other->state_response_size[index_to_histogram] == STATE_ATTACK){
         //printf(" add response %s %d\n", packet->response_string, char_stat.length);
         if(packet->request_length > 0){
            calculate_character_statistic(packet->request_string, &char_stat);
            prefix_tree_add_domain(found->suspision_response_other->other_suspision, packet->request_string, char_stat.length, &char_stat);    
         }
         else{
            found->suspision_response_other->without_string++;
         }
         found->suspision_response_other->packet_in_suspiction++;
      }


      //tunnel detection
      if(found->state_response_tunnel != STATE_ATTACK){
         if(packet->request_length > 0){
            calculate_character_statistic(packet->request_string, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response_tunnel == NULL){
                  found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
               }
               if(found->suspision_response_tunnel->request_suspision == NULL){
                  found->suspision_response_tunnel->request_suspision = prefix_tree_inicialize();
               }
               //printf(" add txt %s %d\n", packet->txt_response, char_stat.length);
               prefix_tree_add_domain(found->suspision_response_tunnel->request_suspision, packet->request_string, char_stat.length, &char_stat);
               found->state_response_tunnel = STATE_SUSPISION;
            }
         }

         if(packet->txt_response[0]!=0){
            calculate_character_statistic(packet->txt_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response_tunnel == NULL){
                  found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
               }
               if(found->suspision_response_tunnel->txt_suspision == NULL){
                  found->suspision_response_tunnel->txt_suspision = prefix_tree_inicialize();
               }
               //printf(" add txt %s %d\n", packet->txt_response, char_stat.length);
               prefix_tree_add_domain(found->suspision_response_tunnel->txt_suspision, packet->txt_response, char_stat.length, &char_stat);
               found->state_response_tunnel = STATE_SUSPISION;
            }
         }
         if(packet->cname_response[0]!=0){
            calculate_character_statistic(packet->cname_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response_tunnel == NULL){
                  found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
               }
               if(found->suspision_response_tunnel->cname_suspision == NULL){
                  found->suspision_response_tunnel->cname_suspision = prefix_tree_inicialize();
               }
               //printf(" add cname %s %d\n", packet->cname_response, char_stat.length);
               prefix_tree_add_domain(found->suspision_response_tunnel->cname_suspision, packet->cname_response, char_stat.length, &char_stat);
               found->state_response_tunnel = STATE_SUSPISION;
            }
         }
         if(packet->mx_response[0]!=0){
            calculate_character_statistic(packet->mx_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response_tunnel == NULL){
                  found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
               }        
               if(found->suspision_response_tunnel->mx_suspision == NULL){
                  found->suspision_response_tunnel->mx_suspision = prefix_tree_inicialize();
               }
              // printf(" add mx %s %d\n", packet->mx_response, char_stat.length);
               prefix_tree_add_domain(found->suspision_response_tunnel->mx_suspision, packet->mx_response, char_stat.length, &char_stat); 
               found->state_response_tunnel = STATE_SUSPISION;   
            }
         }
         if(packet->ns_response[0]!=0){
            calculate_character_statistic(packet->ns_response, &char_stat);
            if(char_stat.count_of_different_letters > values.response_max_count_of_used_letters){
               if(found->suspision_response_tunnel == NULL){
                  found->suspision_response_tunnel = (ip_address_suspision_response_tunnel_t*)calloc(sizeof(ip_address_suspision_response_tunnel_t),1);
               } 
               if(found->suspision_response_tunnel->ns_suspision == NULL){
                  found->suspision_response_tunnel->ns_suspision = prefix_tree_inicialize();
               }
               //printf(" add ns %s %d\n", packet->ns_response, char_stat.length);
               prefix_tree_add_domain(found->suspision_response_tunnel->ns_suspision, packet->ns_response, char_stat.length, &char_stat);
               found->state_response_tunnel = STATE_SUSPISION;
            }
         }
      }

   }
}

void free_ip_list(ip_address_t * list){
      ip_address_t * next_item;
   while(list != NULL){
      //next_item = list->next;
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
   result->ex_request = (float)ip_rec->counter_request.sum_Xi_request / (float)ip_rec->counter_request.dns_request_count;
   result->ex_response = (float)ip_rec->counter_response.sum_Xi_response / (float)ip_rec->counter_response.dns_response_count;

   xn2_request = result->ex_request * result->ex_request;
   xn2_response = result->ex_response * result->ex_response;

   //calculate var
   // var x = (Sum(Xi^2) - Xn^2 * n) / (n-1)
   result->var_request = (float)(ip_rec->counter_request.sum_Xi2_request - xn2_request * ip_rec->counter_request.dns_request_count ) / (float)(ip_rec->counter_request.dns_request_count - 1);
   result->var_response = (float)(ip_rec->counter_response.sum_Xi2_response - xn2_response * ip_rec->counter_response.dns_response_count ) / (float)(ip_rec->counter_response.dns_response_count - 1);

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

   //calculate ex of used letters
   result->ex_request_count_of_different_letters = 0;
   result->var_request_count_letters = 0;
   for (int i=0; i < HISTOGRAM_SIZE_REQUESTS; i++){
      if(ip_rec->counter_request.histogram_dns_request_sum_for_cout_of_used_letter[i] > 0){
         result->histogram_dns_request_ex_cout_of_used_letter[i] = (float)ip_rec->counter_request.histogram_dns_request_ex_sum_of_used_letter[i] / (float)ip_rec->counter_request.histogram_dns_request_sum_for_cout_of_used_letter [i];
         result->ex_request_count_of_different_letters += result->histogram_dns_request_ex_cout_of_used_letter[i];
         result->var_request_count_letters += result->histogram_dns_request_ex_cout_of_used_letter[i] * result->histogram_dns_request_ex_cout_of_used_letter[i];
      }
      else{
         result->histogram_dns_request_ex_cout_of_used_letter[i] =0;
      }
   }

   result->ex_request_count_of_different_letters /= (float)ip_rec->counter_request.dns_request_string_count;
   result->var_request_count_letters /= (float)ip_rec->counter_request.dns_request_string_count;
   result->var_request_count_letters -=  result->ex_request_count_of_different_letters * result->ex_request_count_of_different_letters;
}

void check_and_delete_suspision(ip_address_t * item_to_delete, unsigned char part){
   if(part & REQUEST_PART_TUNNEL){
      if(item_to_delete->suspision_request_tunnel != NULL){
         if(item_to_delete->suspision_request_tunnel->tunnel_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_request_tunnel->tunnel_suspision);
         }
         free(item_to_delete->suspision_request_tunnel);
         item_to_delete->suspision_request_tunnel = NULL;
      }
   }
   if(part & REQUEST_PART_OTHER){
      if(item_to_delete->suspision_request_other != NULL){
         if(item_to_delete->suspision_request_other->other_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_request_other->other_suspision);
         }
         free(item_to_delete->suspision_request_other);
         item_to_delete->suspision_request_other = NULL;
      }
      memset(&item_to_delete->counter_request, 0, sizeof(counter_request_t));
   }   
   if(part & RESPONSE_PART_OTHER){
      if(item_to_delete->suspision_response_other != NULL){
         if(item_to_delete->suspision_response_other->other_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_response_other->other_suspision);
         }
         free(item_to_delete->suspision_response_other);
         item_to_delete->suspision_response_other = NULL;
      }
      memset(&item_to_delete->counter_response, 0, sizeof(counter_response_t));
   }   
   if(part & RESPONSE_PART_TUNNEL){
      if(item_to_delete->suspision_response_tunnel != NULL){
         if(item_to_delete->suspision_response_tunnel->request_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->request_suspision);
         }         
         if(item_to_delete->suspision_response_tunnel->cname_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->cname_suspision);
         }
         if(item_to_delete->suspision_response_tunnel->txt_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->txt_suspision);
         }
         if(item_to_delete->suspision_response_tunnel->ns_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->ns_suspision);
         }
         if(item_to_delete->suspision_response_tunnel->mx_suspision != NULL){
            prefix_tree_destroy(item_to_delete->suspision_response_tunnel->mx_suspision);
         }
         free(item_to_delete->suspision_response_tunnel);
         item_to_delete->suspision_response_tunnel = NULL;
      }
   }
   if(part & RESPONSE_PART_OTHER){
      memset(&item_to_delete->counter_response, 0, sizeof(counter_response_t));
   }

}


int is_traffic_on_ip_ok_request_other(ip_address_t * item, calulated_result_t * result){
   int i;
   //if there is more traffic than minimum
   if(item->state_request_other != STATE_ATTACK && item->counter_request.dns_request_count > values.min_dns_request_count_other_anomaly){
      //other anomaly can be caused, then select the peaks, which have most of communication
      //printf("ex %f var %f\n",result->ex_request, result->var_request);
      if( result->ex_request < values.ex_request_min || result->var_request < values.var_request_min || result->var_request > values.var_request_max || result->ex_request > values.ex_request_max /*|| result->kurtosis_request < values.kurtosis_request_min*/){
         int max;
         item->state_request_other = STATE_SUSPISION;
         //if it is first suspision
         if(item->suspision_request_other == NULL){
            item->suspision_request_other = (ip_address_suspision_request_other_t*)calloc(sizeof(ip_address_suspision_request_other_t),1);
         }
         //if it is first other suspision
         if(item->suspision_request_other->other_suspision == NULL){
            item->suspision_request_other->other_suspision = prefix_tree_inicialize();
         }      
         max = 0;
         for(i = max; i < HISTOGRAM_SIZE_REQUESTS ; i++){
            //select the biggest peak
            if (item->counter_request.histogram_dns_requests[i] > item->counter_request.histogram_dns_requests[max]){
               max = i;
            }
            //selecet everything what have more than certain amount of traffic and is not in tunnel detection tree
            if((float)item->counter_request.histogram_dns_requests[i] / (float)item->counter_request.dns_request_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPISION && 
               result->histogram_dns_request_ex_cout_of_used_letter[i] < values.request_max_count_of_used_letters ){
                  item->suspision_request_other->state_request_size[i] = STATE_ATTACK;
            }
         }
         //the biggest peak
         item->suspision_request_other->state_request_size[max] = STATE_ATTACK;
      }
      if((double)item->counter_request.request_without_string / (double)item->counter_request.dns_request_count > values.max_percent_of_mallformed_packet_request){
         item->state_request_other = STATE_ATTACK;
      }
   }
   if(item->state_request_other == STATE_NEW){
      return STATE_NEW;
   }
   return STATE_SUSPISION;

}

int is_traffic_on_ip_ok_request_tunnel(ip_address_t * item, calulated_result_t * result){
   int i;
   //if there is more traffic than minimum
   if(item->state_request_tunnel != STATE_ATTACK && item->counter_request.dns_request_count > values.min_dns_request_count_other_anomaly){
      //other anomaly can be caused, then select the peaks, which have most of communication
      //printf("ex %f var %f\n",result->ex_request, result->var_request);
      if( result->var_request < values.var_request_min || result->var_request > values.var_request_max || result->ex_request > values.ex_request_max /*|| result->kurtosis_request < values.kurtosis_request_min*/){
         int max;
         item->state_request_tunnel = STATE_SUSPISION;
         //if it is first suspision
         if(item->suspision_request_tunnel == NULL){
            item->suspision_request_tunnel = (ip_address_suspision_request_tunnel_t*)calloc(sizeof(ip_address_suspision_request_tunnel_t),1);
         }
         //if it is first other suspision
         if(item->suspision_request_tunnel->tunnel_suspision == NULL){
            item->suspision_request_tunnel->tunnel_suspision = prefix_tree_inicialize();
         }      
         max = 0;
         for(i = max; i < HISTOGRAM_SIZE_REQUESTS ; i++){
            //selecet everything what have more than certain amount of traffic and is not in tunnel detection tree
            if((float)item->counter_request.histogram_dns_requests[i] / (float)item->counter_request.dns_request_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPISION && 
               result->histogram_dns_request_ex_cout_of_used_letter[i] < values.request_max_count_of_used_letters ){
                  item->suspision_request_tunnel->state_request_size[i] = STATE_ATTACK;
            }
         }
      }

   }
   if(item->state_request_tunnel == STATE_NEW){
      return STATE_NEW;
   }
   return STATE_SUSPISION;

}



int is_traffic_on_ip_ok_response_other(ip_address_t * item, calulated_result_t * result){
   int i;
   //responses
   if( item->state_response_other != STATE_ATTACK && item->counter_response.dns_response_count > values.min_dns_response_count_other_anomaly){
      if( result->ex_response < values.ex_response_min || result->var_response < values.var_response_min || result->var_response > values.var_response_max || result->ex_response > values.ex_response_max /*|| result->kurtosis_request < values.kurtosis_request_min*/){
        int max;
         item->state_response_other = STATE_SUSPISION;
         //if it is first suspision
         if(item->suspision_response_other == NULL){
            item->suspision_response_other = (ip_address_suspision_response_other_t*)calloc(sizeof(ip_address_suspision_response_other_t),1);
         }
         //if it is first other suspision
         if(item->suspision_response_other->other_suspision == NULL){
            item->suspision_response_other->other_suspision = prefix_tree_inicialize();
         }      
         max = 0;
         for(i = max; i < HISTOGRAM_SIZE_RESPONSE ; i++){
            //select the biggest peak
            if (item->counter_response.histogram_dns_response[i] > item->counter_response.histogram_dns_response[max]){
               max = i;
            }
            //selecet everything what have more than certain amount of traffic and is not in tunnel detection tree
            if((float)item->counter_response.histogram_dns_response[i] / (float)item->counter_response.dns_response_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPISION){
                  item->suspision_response_other->state_response_size[i] = STATE_ATTACK;
            }
         }
         //the biggest peak
         item->suspision_response_other->state_response_size[max] = STATE_ATTACK;
      }

   }
   if(item->state_response_other == STATE_NEW){
  	  check_and_delete_suspision(item, RESPONSE_PART_OTHER);
      return STATE_NEW;
   }
   return STATE_SUSPISION;
}


int is_payload_on_ip_ok_request_other(ip_address_t * item){
   int i;
   prefix_tree_t *tree;

      //other anomaly detection request  
     if(!(item->state_request_other == STATE_ATTACK) && item->suspision_request_other->other_suspision != NULL){
         tree = item->suspision_request_other->other_suspision;
         if (tree->count_of_inserting > values.min_dns_request_count_other_anomaly &&
            (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
            (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_unique_domains   //percent of unique domains
         ){
            item->state_request_other = STATE_ATTACK;

         }
         else{
         	//if there wasnt any payload problem
 	        item->suspision_request_other->round_in_suspiction++;
	        //maximum round in suspiction
	        if(item->suspision_request_other->round_in_suspiction > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
	           //item->suspision_request_tunnel->round_in_suspiction = 0;
	           check_and_delete_suspision(item, REQUEST_PART_OTHER);
	           item->state_request_other = STATE_NEW;
	        }        	
         }
      }  
   if(item->state_request_other == STATE_NEW){
      return STATE_NEW;
   }
     
   return STATE_SUSPISION;

}

int is_payload_on_ip_ok_response_other(ip_address_t * item){
   int i;
   prefix_tree_t *tree;

      //other anomaly detection response  
     if(!(item->state_response_other == STATE_ATTACK) && item->suspision_response_other->other_suspision != NULL){
         tree = item->suspision_response_other->other_suspision;
         if (tree->count_of_inserting > values.min_dns_response_count_other_anomaly &&
            (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_domain_searching_just_once &&      //percent of searching unique domains
            (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) < values.min_percent_of_unique_domains   //percent of unique domains
         ){
            item->state_response_other = STATE_ATTACK;
         }
         else if((double)item->suspision_response_other->without_string / (double)item->suspision_response_other->packet_in_suspiction > values.max_percent_of_mallformed_packet_request){
         item->state_response_other = STATE_ATTACK;
         }
         
         else{
            //if there wasnt any payload problem
           item->suspision_response_other->round_in_suspiction++;
           //maximum round in suspiction
           if(item->suspision_response_other->round_in_suspiction > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
              //item->suspision_response_tunnel->round_in_suspiction = 0;
              check_and_delete_suspision(item, RESPONSE_PART_OTHER);
              item->state_response_other = STATE_NEW;
           }         
         }
      }  
   if(item->state_response_other == STATE_NEW){
      return STATE_NEW;
   }
     
   return STATE_SUSPISION;

}

int is_payload_on_ip_ok_request_tunnel(ip_address_t * item){
	prefix_tree_t *tree;
  //tunnel detection request
 	if((item->state_request_tunnel != STATE_ATTACK) && item->suspision_request_tunnel->tunnel_suspision != NULL){
		tree = item->suspision_request_tunnel->tunnel_suspision;  
		//percent of count of subdomains, is bigger than x percent
		if(tree->count_of_inserting > values.min_dns_request_count_tunnel &&
		    ((
		    (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
		    (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting_for_just_ones) > values.max_percent_of_unique_domains   //percent of unique domains
		    )&&
		    (most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION) > values.max_percent_of_subdomains_in_main_domain)
		    )){  //percent of unique search
//*********************
 /*        printf("tunel ma hodntu %f ,%f ,%f ,%d, %d, %d\n", most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION),  (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting)  , (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting)  , most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION) > values.max_percent_of_subdomains_in_main_domain ,(double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains , (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once , most_used_domain_percent_of_subdomains(tree, DEPTH_TUNNEL_SUSPICTION) > values.max_percent_of_subdomains_in_main_domain );
		   
   prefix_tree_domain_t *dom;
   char str[1024];
         printf("\tRequest tunnel found:\tDomains searched just once: %f.\tcount of different domains: %f.\tPercent of subdomain in most used domain %f.\tAll recorded requests: %d\n", (double)(item->suspision_request_tunnel->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_tunnel->tunnel_suspision->count_of_different_domains/(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), most_used_domain_percent_of_subdomains(item->suspision_request_tunnel->tunnel_suspision, DEPTH_TUNNEL_SUSPICTION) ,(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting) );

         dom =item->suspision_request_tunnel->tunnel_suspision->list_of_most_unused_domains;
         for(int i=0; i<5;i++){
            str[0]=0;
            if(dom==NULL) break;
            printf("\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
            dom= dom->most_used_domain_less;
         }  
*/
//**********************
          item->state_request_tunnel = STATE_ATTACK;
		}
		//if there wasnt any problem
	  	else{
	        item->suspision_request_tunnel->round_in_suspiction++;
	        //maximum round in suspiction
	        if(item->suspision_request_tunnel->round_in_suspiction > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
	           //item->suspision_request_tunnel->round_in_suspiction = 0;
	           check_and_delete_suspision(item, REQUEST_PART_TUNNEL);
	           item->state_request_tunnel = STATE_NEW;
	        }
	    }
  	}
  	if(item->state_request_tunnel == STATE_NEW){
      return STATE_NEW;
   }
   return STATE_SUSPISION;
}

int is_payload_on_ip_ok_response_tunnel(ip_address_t * item){
   int i;
   prefix_tree_t *tree;
   //tunnel detection response
   if(item->state_response_tunnel != STATE_ATTACK){
      tree = item->suspision_response_tunnel->request_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response_tunnel = STATE_ATTACK;
         item->suspision_response_tunnel->state_type |= REQUEST_STRING_TUNNEL;
      }
      tree = item->suspision_response_tunnel->txt_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL &&
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response_tunnel = STATE_ATTACK;
         item->suspision_response_tunnel->state_type |= TXT_TUNNEL;

      }
      tree = item->suspision_response_tunnel->mx_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL && 
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response_tunnel = STATE_ATTACK;
         item->suspision_response_tunnel->state_type |= MX_TUNNEL;
      }
      tree = item->suspision_response_tunnel->cname_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL && 
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response_tunnel = STATE_ATTACK;
         item->suspision_response_tunnel->state_type |= CNAME_TUNNEL;
      }
      tree = item->suspision_response_tunnel->ns_suspision;
      //percent of count of subdomains, is bigger than x percent
      if(tree != NULL && 
         tree->count_of_inserting > values.min_dns_response_count_tunnel &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_inserting) > values.max_percent_of_domain_searching_just_once &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_inserting) > values.max_percent_of_unique_domains   //percent of unique domains
         ){  //percent of unique search
         item->state_response_tunnel = STATE_ATTACK;
         item->suspision_response_tunnel->state_type |= NS_TUNNEL;
      }
      //if there wasnt any payload problem
      if(item->state_response_tunnel == STATE_SUSPISION){
         item->suspision_response_tunnel->round_in_suspiction++;
         //maximum round in suspiction
         if(item->suspision_response_tunnel->round_in_suspiction > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
            item->suspision_response_tunnel->round_in_suspiction = 0;
            check_and_delete_suspision(item, RESPONSE_PART_TUNNEL);
            item->state_response_tunnel = STATE_NEW;
         }
      }
   }

   if(item->state_response_tunnel == STATE_NEW){
      return STATE_OK;
   }
   return STATE_SUSPISION;
}



void calculate_statistic_and_choose_anomaly(void * b_plus_tree){
   ip_address_t * item;
   ip_address_t * previous = NULL;
   ip_address_t * start;
   b_plus_tree_item * b_item;
   int is_there_next=0;
   calulated_result_t result;
   b_item = b_plus_tree_create_list_item(b_plus_tree);
   is_there_next = b_plus_tree_get_list(b_plus_tree, b_item);

   while(is_there_next == 1){
      item = (ip_address_t*)b_item->value;

      calculate_statistic(item, &result);
      //without anomaly

      //request other anomaly
      if(item->state_request_other == STATE_SUSPISION){
         is_payload_on_ip_ok_request_other(item);
      }
      else if(item->state_request_other == STATE_NEW){
      	is_traffic_on_ip_ok_request_other(item, &result);
      }
      //request tunnel anomaly
      if(item->state_request_tunnel == STATE_SUSPISION){
         is_payload_on_ip_ok_request_tunnel(item);
      }
      else if(item->state_request_tunnel == STATE_NEW){
      	is_traffic_on_ip_ok_request_tunnel(item, &result);
      }

      //response payload, tunnel anomaly 
      if(item->state_response_tunnel == STATE_SUSPISION){
        is_payload_on_ip_ok_response_tunnel(item);
      }
      //response traffic, other anomaly 
      if(item->state_response_other == STATE_SUSPISION){
         is_payload_on_ip_ok_response_other(item);
      }
      else if(item->state_response_other == STATE_NEW){
        is_traffic_on_ip_ok_response_other(item, &result);
      }

      //check if it can be deleted
      if(item->state_request_other == STATE_NEW && item->state_request_tunnel == STATE_NEW && item->state_response_other == STATE_NEW && item->state_response_tunnel == STATE_NEW){
         is_there_next = b_plus_tree_delete_item_from_list(b_plus_tree, b_item);
      }
      else{
      	//with anomaly, in can not be deleted
         is_there_next = b_plus_tree_get_next_item_from_list(b_plus_tree, b_item);
      }
   }
   b_plus_tree_destroy_list_item(b_item);
}

void print_founded_anomaly(char * ip_address, ip_address_t *item, FILE *file){
   prefix_tree_domain_t *dom;
   char str[1024];
   

    if(item->state_request_other == STATE_ATTACK || item->state_request_tunnel == STATE_ATTACK || item->state_response_other == STATE_ATTACK || item->state_request_tunnel == STATE_ATTACK){
         fprintf(file, "\n%s\n", ip_address);
      
      //print found anomaly tunnel
      if(item->state_request_tunnel == STATE_ATTACK){
         fprintf(file, "\tRequest tunnel found:\tDomains searched just once: %f.\tcount of different domains: %f.\tPercent of subdomain in most used domain %f.\tAll recorded requests: %d\n", (double)(item->suspision_request_tunnel->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_tunnel->tunnel_suspision->count_of_different_domains/(double)(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting_for_just_ones), most_used_domain_percent_of_subdomains(item->suspision_request_tunnel->tunnel_suspision, DEPTH_TUNNEL_SUSPICTION) ,(item->suspision_request_tunnel->tunnel_suspision->count_of_inserting) );

         dom =item->suspision_request_tunnel->tunnel_suspision->list_of_most_unused_domains;
         for(int i=0; i<5;i++){
            str[0]=0;
            if(dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
            dom= dom->most_used_domain_less;
         }               
      }
      //print founded anomaly other in request
      if(item->state_request_other == STATE_ATTACK){  
         if(item->suspision_request_other != NULL){
            fprintf(file, "\tRequest traffic anomaly found:\tDomains searched just once: %f.\tCount of different domains: %f.\tAll recorded requests: %d.\tCount of malformed requests: %d.\n\t\tFound in sizes: ", (double)(item->suspision_request_other->other_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones), (double)item->suspision_request_other->other_suspision->count_of_different_domains/(double)(item->suspision_request_other->other_suspision->count_of_inserting_for_just_ones),(item->suspision_request_other->other_suspision->count_of_inserting), item->counter_request.request_without_string  );
            for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
               if(item->suspision_request_other->state_request_size[i] & STATE_ATTACK)
               fprintf(file, "%d-%d\t", i*10,i*10+10);
            } 
            fprintf(file, "\n");
      
            dom =item->suspision_request_other->other_suspision->list_of_most_used_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
               dom= dom->most_used_domain_less;
            }
         }
         else{
            fprintf(file, "\tMallformed packets found:\tCount of malformed responses: %d.\n", item->counter_request.request_without_string);

         }
      }

      //response tunnel
      if(item->state_response_tunnel == STATE_ATTACK){
         if(item->suspision_response_tunnel->state_type & REQUEST_STRING_TUNNEL){
            fprintf(file, "\tReponse tunnel found by request strings :\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->request_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->request_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->request_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->request_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->request_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
               dom= dom->most_used_domain_less;
            }        
         }         
         //txt
         if(item->suspision_response_tunnel->state_type & TXT_TUNNEL){
            fprintf(file, "\tReponse TXT tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->txt_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->txt_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->txt_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->txt_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->txt_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
               dom= dom->most_used_domain_less;
            }        
         }
         //cname
         if(item->suspision_response_tunnel->state_type & CNAME_TUNNEL){
            fprintf(file, "\tReponse CNAME tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->cname_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->cname_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->cname_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->cname_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->cname_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
               dom= dom->most_used_domain_less;
            }        
         }
         //ns
         if(item->suspision_response_tunnel->state_type & NS_TUNNEL){
            fprintf(file, "\tReponse NS tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->ns_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->ns_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->ns_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->ns_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->ns_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
               dom= dom->most_used_domain_less;
            }        
         }  
         //mx
         if(item->suspision_response_tunnel->state_type & MX_TUNNEL){
            fprintf(file, "\tReponse MX tunnel found:\tstrings searched just once: %f.\tcount of different strings: %f.\tall requests: %d.\n", (double)(item->suspision_response_tunnel->mx_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones), (double)item->suspision_response_tunnel->mx_suspision->count_of_different_domains/(double)(item->suspision_response_tunnel->mx_suspision->count_of_inserting_for_just_ones),(item->suspision_response_tunnel->mx_suspision->count_of_inserting) );
            dom =item->suspision_response_tunnel->mx_suspision->list_of_most_unused_domains;
            for(int i=0; i<5;i++){
               str[0]=0;
               if(dom==NULL) break;
               fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
               dom= dom->most_used_domain_less;
            }        
         }
      }
      //print founded anomaly other in responses
      if(item->state_response_other == STATE_ATTACK){  
         calulated_result_t result;
         calculate_statistic(item, &result);
         fprintf(file, "\tReseponse anomaly found:\tEX: %f.\tVAR: %f. \tPercent without request string %f. \tCount of responses %lu.\n", result.ex_response, result.var_response, (double)item->suspision_response_other->without_string / (double)item->suspision_response_other->packet_in_suspiction ,item->counter_response.dns_response_count);

         dom =item->suspision_response_other->other_suspision->list_of_most_used_domains;
         for(int i=0; i<5;i++){
            str[0]=0;
            if(dom==NULL) break;
            fprintf(file, "\t\t%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
            dom= dom->most_used_domain_less;
         }
      }
    }
}

void print_suspision_ip(char *ip_address, ip_address_t *ip_item, FILE *file){
   if(ip_item->state_request_other == STATE_SUSPISION || ip_item->state_request_tunnel == STATE_SUSPISION || ip_item->state_response_other == STATE_SUSPISION || ip_item->state_request_tunnel == STATE_SUSPISION){
      fprintf(file, "%s\n", ip_address);
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


void print_histogram_values (char *ip_address, ip_address_t *ip_item, FILE *file_requests, FILE *file_responses, FILE *file_requests_count_letters){
   calulated_result_t result;

   //count statistic values
   calculate_statistic(ip_item, &result);
   //requests
   fprintf(file_requests, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_address, result.ex_request, result.var_request, result.skewness_request, result.kurtosis_request);
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
      fprintf(file_requests, "%lu\t",ip_item->counter_request.histogram_dns_requests[i]);
   }    
   fprintf(file_requests, "%lu\n", ip_item->counter_request.histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS - 1]);  
   //requests count letter
   fprintf(file_requests_count_letters, "%s__EX=%f__VarX=%f\t", ip_address, result.ex_request_count_of_different_letters, result.var_request_count_letters);
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
      fprintf(file_requests_count_letters, "%lu\t",result.histogram_dns_request_ex_cout_of_used_letter[i]);
   }
   fprintf(file_requests_count_letters, "%lu\n", result.histogram_dns_request_ex_cout_of_used_letter[HISTOGRAM_SIZE_REQUESTS - 1]); 
   //response
   fprintf(file_responses, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_address, result.ex_response, result.var_response, result.skewness_response, result.kurtosis_response);
   for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
      fprintf(file_responses, "%lu\t",ip_item->counter_response.histogram_dns_response[i]);
   }
   fprintf(file_responses, "%lu\n", ip_item->counter_response.histogram_dns_response[HISTOGRAM_SIZE_RESPONSE - 1]);    
}

void write_detail_result(char * record_folder_name, void ** b_plus_tree, int count_of_btree){
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
   if(file_requests == NULL){
      return;
   }
   //print titles 
   fprintf(file_requests, TITLE_REQUESTS "\n");
   //print range to requests
   fprintf(file_requests,  "ip__EX__VarX__Skewness__Kurtosis\t");
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){

      fprintf(file_requests, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);   

//responses
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_RESPONSES);
   file_responses = fopen(file_path, "w");  
   if(file_responses == NULL){
      return;
   } 
   //print titles
   fprintf(file_responses, TITLE_RESPONSES "\n");
   //print range to respones
   fprintf(file_responses,  "ip__EX__VarX__Skewness__Kurtosis\t");
   for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
      fprintf(file_responses, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_responses, "%d-inf\n",(HISTOGRAM_SIZE_RESPONSE-1) * 10);

//count letters
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUEST_COUNT_LETTERS);
   file_requests_count_letters = fopen(file_path, "w"); 
   if(file_requests_count_letters == NULL){
      return;
   }
   //print titles
   fprintf(file_requests_count_letters, TITLE_REQUEST_COUNT_LETTERS "\n");
   //print range to requests count letter 
   fprintf(file_requests_count_letters,  "ip__EX__VarX\t");
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
      fprintf(file_requests_count_letters, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests_count_letters, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);

//found anomaly
   //open file
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_FOUND_ANOMALY);
   file_anomaly = fopen(file_path, "w");
   if(file_anomaly == NULL){
      return;
   }   

//suspision list
   //open files
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_SUSPISION_LIST);
   file_suspision = fopen(file_path, "w");
   if(file_suspision == NULL){
      return;
   }   
   //print title
   fprintf(file_suspision, TITLE_SUSPISION_LIST "\n");
   




   //print histogram of each IP
   //for each item in list
   for(i =0; i < count_of_btree; i++){
      b_item = b_plus_tree_create_list_item(b_plus_tree[i]);
      is_there_next = b_plus_tree_get_list(b_plus_tree[i], b_item);
      while(is_there_next == 1){
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

int compare_ipv4(void * a, void * b){
   uint32_t *h1, *h2;

   h1 = (uint32_t*)a;
   h2 = (uint32_t*)b;
   if (*h1 == *h2){
         return EQUAL;
   } 
   else if(*h1 < *h2){
      return LESS;
   }
   else if(*h1 > *h2){
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
   values.max_percent_of_subdomains_in_main_domain = MAX_PERCENT_OF_SUBDOMAINS_IN_MAIN_DOMAIN;
}

int main(int argc, char **argv)
{
   int ret, i;
   void * btree_ver4, *btree_ver6, *btree[2];
   prefix_tree_t * preftree;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   unsigned long histogram_dns_requests [HISTOGRAM_SIZE_REQUESTS];
   unsigned long histogram_dns_response [HISTOGRAM_SIZE_RESPONSE];
   ip_address_t * list_of_ip = NULL;
   unsigned char write_summary = 0, has_exception = 0;
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



   //inicialize prefix tree
   preftree = prefix_tree_inicialize();

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
      has_exception = 1;
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
            prefix_tree_add_domain_exception(preftree,domain ,length);
         }
         sign = fgetc(file);
      }
      fclose(file);
   }


   //inicialize b+ tree ipv4
   btree_ver4 = b_plus_tree_inicialize(5, &compare_ipv4, sizeof(ip_address_t), sizeof(uint32_t));   
   //inicialize b+ tree ipv6
   btree_ver6 = b_plus_tree_inicialize(5, &compare_ipv6, sizeof(ip_address_t), sizeof(uint64_t)*2);
   //add trees to array, you can work with it in cycle
   btree[0] = btree_ver4;
   btree[1] = btree_ver6;




  
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
      int count_of_cycle=0;
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
               printf("End of file\n" );
               stop=1;
               break; // End of data (used for testing purposes)
            }
            cnt_packets++;
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
                  if(packet.request_length == 0 || has_exception == 0 || prefix_tree_is_domain_in_exception(preftree, packet.request_string, packet.request_length, NULL) == 0){
                     if(packet.ip_version == IP_VERSION_4){
                        collection_of_information_and_basic_payload_detection(btree_ver4, (&packet.src_ip_v4), packet.size, 1, &packet);
                     }
                     else{
                        collection_of_information_and_basic_payload_detection(btree_ver6, packet.src_ip_v6, packet.size, 1, &packet);
                     }
                  }
               histogram_dns_requests[packet.size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
            }
            //is it source port of DNS (Port 53)
            else{
               // Update counters
               if(packet.ip_version == IP_VERSION_4){
                  collection_of_information_and_basic_payload_detection(btree_ver4, (&packet.dst_ip_v4), packet.size, 0, &packet);
               }
               else{
                  collection_of_information_and_basic_payload_detection(btree_ver6, packet.dst_ip_v6, packet.size, 0, &packet);
               }
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
         printf("cycle %d\n", ++count_of_cycle);
         printf("\tcount of ip's before_erase %lu\n", b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6));
         calculate_statistic_and_choose_anomaly(btree_ver4);
         calculate_statistic_and_choose_anomaly(btree_ver6);
          printf("\tcount of ip's after_erase %lu\n\n", b_plus_tree_get_count_of_values(btree_ver4) + b_plus_tree_get_count_of_values(btree_ver6));
         //stop=1;         

      }
      //close reading from file
      parser_end(input);
   }
   
   // ***** Print results *****
 


   if (progress > 0) {
      printf("\n");
   }
   //printf("Flows:   %20lu\n", cnt_flows);
   printf("Packets: %20lu\n", cnt_packets);
   //printf("Bytes:   %20lu\n", cnt_bytes);
/*
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
      printf("%s. %d\n",  read_doamin(dom, str), dom->count_of_insert);
      dom= dom->most_used_domain_less;

   }
   */
   

   // *****  Write into file ******
   if (write_summary){

         write_summary_result(record_folder_name, histogram_dns_requests, histogram_dns_response);
         write_detail_result(record_folder_name, btree, 2);

   }
   
   


   // ***** Cleanup *****
   //clean values in b plus tree
   b_plus_tree_item *b_item;

   //clean btree ver4 and ver6
   for(i = 0; i<2; i++){
      b_item = b_plus_tree_create_list_item(btree[i]);
      int is_there_next = b_plus_tree_get_list(btree[i], b_item);
      while(is_there_next == 1){
         check_and_delete_suspision((ip_address_t*)b_item->value, REQUEST_AND_RESPONSE_PART);
         is_there_next = b_plus_tree_get_next_item_from_list(btree[i], b_item);
      }
      b_plus_tree_destroy_list_item(b_item);
      b_plus_tree_destroy(btree[i]);
   }

   //clean prefix tred
   prefix_tree_destroy(preftree);


   // Do all necessary cleanup before exiting
failed_trap:
   //TRAP_DEFAULT_FINALIZATION();
   trap_finalize();
   ur_free_template(tmplt);
   
   return 0;
   

}

