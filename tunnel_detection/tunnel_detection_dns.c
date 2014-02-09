/*!
 * \file tunnel_detection_dns.c
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
   "   -f          Read packets from file"
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

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   } else if (signal == SIGUSR1) {
      stats = 1;
   }
}


ip_address_t * crete_new_ip_address_struc( uint32_t * ip, ip_address_t * next){
   ip_address_t * create;
   create = (ip_address_t *) calloc(sizeof(ip_address_t),1); 
   //write next list item
   create->next = next;
   create->ip = *ip;
   //clear allocated memory
   //memset(create->histogram_dns_requests, 0, HISTOGRAM_SIZE_REQUESTS * sizeof(unsigned long));
   //memset(create->histogram_dns_response, 0, HISTOGRAM_SIZE_RESPONSE * sizeof(unsigned long));
   return create; 
}

ip_address_t * find_ip(uint32_t * search_ip, ip_address_t * struc){
   //if it is on the end of the list or it found item
   if(struc == NULL || struc->ip == * search_ip)
      return struc;
   //recursive call function on next item in list
   return find_ip(search_ip, struc->next);
}

ip_address_t * add_to_list( ip_address_t * list_of_ip, uint32_t * ip_in_packet, int size, char request){
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
   if(char_stat->count_of_different_letters > REQUEST_MAX_COUNT_OF_USED_LETTERS ||     //just domains which have a lot of letters
      (double)char_stat->count_of_numbers_in_string / (double)char_stat->length > MAX_PERCENT_OF_NUMBERS_IN_DOMAIN_PREFIX_TREE_FILTER) //just domains which have a lot of numbers
   {
      return 1;
   }
   return 0;
}


void add_to_bplus_tree( void * tree, uint32_t * ip_in_packet, int size, char request, char * request_string, int request_length){
   ip_address_t * found;
   float size2;
   int index_to_histogram;
   size2=size*size;
   //found or create in b plus tree
   found = create_or_find_struct_b_plus_tree(tree, *ip_in_packet);

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
      //get count of unique name of request string
      if(request_string != NULL){
         character_statistic_t char_stat;

         found->dns_request_string_count++;
         found->histogram_dns_request_sum_for_cout_of_used_letter[index_to_histogram]++;
         calculate_character_statistic(request_string, &char_stat);
         found->histogram_dns_request_ex_sum_of_used_letter[index_to_histogram] += char_stat.count_of_different_letters;
         //add to prefix tree, if ip is in suspision state
         if(found->state != STATE_NEW && found->suspision != NULL){
            if((found->suspision->state_request_size[index_to_histogram] == STATE_TUNNEL || 
               found->suspision->state_request_size[index_to_histogram] == STATE_TUNNEL_AND_OTHER_ANOMALY) &&
               filter_trafic_to_save_in_prefix_tree_tunnel_suspiction(&char_stat)){            
               add_to_prefix_tree(found->suspision->tunnel_suspision, request_string, char_stat.length, &char_stat);
            }
            else if(found->suspision->state_request_size[index_to_histogram] == STATE_OTHER_ANOMALY || found->suspision->state_request_size[index_to_histogram] == STATE_TUNNEL_AND_OTHER_ANOMALY){
               add_to_prefix_tree(found->suspision->other_suspision, request_string, char_stat.length, &char_stat);
            }
         }

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
                              (float)(ip_rec->var_request * ip_rec->var_request);
   result->skewness_response = (float)((ip_rec->sum_Xi4_response - 
                              4 * result->ex_response * ip_rec->sum_Xi3_response  +  
                              6 * xn2_response * ip_rec->sum_Xi2_response - 
                              4 * result->ex_response * xn2_response  * ip_rec->sum_Xi_response + 
                              xn2_response * xn2_response * ip_rec->dns_response_count) *
                              ip_rec->dns_response_count) /
                              (float)(ip_rec->var_response * ip_rec->var_response);

   //calculace kurtosis
   //kurtosis = n^(1/2) * (Sum(Xi^3) - 3 * Sum(Xi^2) * Xn  +  3 * Xn^2 * Sum(Xi) - Xn^3 * n ) / (var x)^(3/2)
   result->kurtosis_request = (float)((ip_rec->sum_Xi3_request -
                              3 * ip_rec->sum_Xi2_request * result->ex_request + 
                              3 * xn2_request * ip_rec->sum_Xi_request -
                              xn2_request * result->ex_request * ip_rec->dns_request_count) * 
                              sqrtf((float)ip_rec->dns_request_count)) /
                              sqrtf((float)(ip_rec->var_request * ip_rec->var_request * ip_rec->var_request));
   result->kurtosis_response = (float)((ip_rec->sum_Xi3_response -
                              3 * ip_rec->sum_Xi2_response * result->ex_response + 
                              3 * xn2_response * ip_rec->sum_Xi_response -
                              xn2_response * result->ex_response * ip_rec->dns_response_count) * 
                              sqrtf((float)ip_rec->dns_response_count)) /
                              sqrtf((float)(ip_rec->var_response * ip_rec->var_response * ip_rec->var_response));

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

void check_and_delete_suspision(ip_address_t * item_to_delete){
   if(item_to_delete->suspision != NULL){
      if(item_to_delete->suspision->tunnel_suspision != NULL){
         destroy_prefix_tree(item_to_delete->suspision->tunnel_suspision);
      }
      if(item_to_delete->suspision->other_suspision != NULL){
         destroy_prefix_tree(item_to_delete->suspision->other_suspision);
      }
      free(item_to_delete->suspision);
   }
}

int is_traffic_on_ip_ok(ip_address_t * item, calulated_result_t * result){
   int i;
   //if there is more traffic than minimum
   if(item->dns_request_count > MIN_DNS_REQUEST_COUNT){
      //count of used leeters, it can be tunnel
      for(i=0;i<HISTOGRAM_SIZE_REQUESTS;i++){
         //if it is first suspision
         if(result->histogram_dns_request_ex_cout_of_used_letter[i] > REQUEST_MAX_COUNT_OF_USED_LETTERS){
            if(item->suspision == NULL){
               item->suspision = (ip_address_suspision_t*)calloc(sizeof(ip_address_suspision_t),1);
            }
            if(item->suspision->tunnel_suspision == NULL){
               item->suspision->tunnel_suspision = inicialize_prefix_tree();
            }
             item->suspision->state_request_size[i] = STATE_TUNNEL;
         }
      }
      //var is bigger than normal, it can be tunnel, add everything from EX_REQUEST_MAX till the end
      if(result->var_request > VAR_REQUEST_MAX || result->ex_request >EX_REQUEST_MAX){
          //if it is first suspision
         if(item->suspision == NULL){
            item->suspision = (ip_address_suspision_t*)calloc(sizeof(ip_address_suspision_t),HISTOGRAM_SIZE_REQUESTS);
         }
         if(item->suspision->tunnel_suspision == NULL){
            item->suspision->tunnel_suspision = inicialize_prefix_tree();
         }     
         for(i = (EX_REQUEST_MAX <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? EX_REQUEST_MAX / 10 : HISTOGRAM_SIZE_REQUESTS - 1); i < HISTOGRAM_SIZE_REQUESTS; i++){
            item->suspision->state_request_size[i] = STATE_TUNNEL;
         }

      }

      //other anomaly can be caused, then select the peaks, which have most of communication
      //printf("ex %f var %f\n",result->ex_request, result->var_request);
      if( result->ex_request < EX_REQUEST_MIN || result->var_request < VAR_REQUEST_MIN /*|| result->kurtosis_request < KURTOSIS_REQUEST_MIN*/){
         int max;
         //if it is first suspision
         if(item->suspision == NULL){
            item->suspision = (ip_address_suspision_t*)calloc(sizeof(ip_address_suspision_t),HISTOGRAM_SIZE_REQUESTS);
         }
         //if it is first other suspision
         if(item->suspision->other_suspision == NULL){
            item->suspision->other_suspision = inicialize_prefix_tree();
         }      
         max = 0;
         for(i = max; i <HISTOGRAM_SIZE_REQUESTS ; i++){
            //select the biggest peak
            if (item->histogram_dns_requests[i] > item->histogram_dns_requests[max]){
               max = i;
            }
            //selecet everything what have more than certain amount of traffic
            if((float)item->histogram_dns_requests[i] / (float)item->dns_request_count > PERCENT_OF_COMMUNICATION_TO_BE_SUSPISION){
               if(item->suspision->state_request_size[i] == STATE_TUNNEL){
                  item->suspision->state_request_size[i] = STATE_TUNNEL_AND_OTHER_ANOMALY;
               }
               else{
                  item->suspision->state_request_size[i] = STATE_OTHER_ANOMALY;
               }
            }
         }
         //the biggest peak
         if(item->suspision->state_request_size[max] == STATE_TUNNEL){
            item->suspision->state_request_size[max] = STATE_TUNNEL_AND_OTHER_ANOMALY;
         }
         else{
            item->suspision->state_request_size[max] = STATE_OTHER_ANOMALY;
         }
      }

      if(item->suspision != NULL){
         item->state = STATE_SUSPISION;
         //****************************
          /*     char ip_buff[100] = {0};
               ip_addr_t ip_to_translate = ip_from_int(item->ip);
               ip_to_str(&ip_to_translate ,ip_buff);

            printf("ip= %s  ex %f var %f\n",ip_buff, result->ex_request, result->var_request);
            printf("tunel ");
               for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
                  if(item->suspision->state_request_size[i] == STATE_TUNNEL || item->suspision->state_request_size[i] == STATE_TUNNEL_AND_OTHER_ANOMALY )
                  printf("%d-%d\t", i*10,i*10+10);
               }
               printf("\nother ");
               for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
                  if(item->suspision->state_request_size[i] == STATE_TUNNEL_AND_OTHER_ANOMALY || item->suspision->state_request_size[i] == STATE_OTHER_ANOMALY)
                  printf("%d-%d\t", i*10,i*10+10);
               }               
               printf("\n");*/
         //********************************

         return STATE_SUSPISION;
      }
   }
   item->state = STATE_OK;
   return STATE_OK;

}

int is_payload_on_ip_ok(ip_address_t * item){
   int i;
   prefix_tree_t *tree;
   item->state = STATE_OK;
   //tunnel detection
   if(item->suspision->tunnel_suspision != NULL){
      tree = item->suspision->tunnel_suspision;  
      //percent of count of subdomains, is bigger than x percent
      if(tree->count_of_searching > MIN_DNS_REQUEST_COUNT_TUNNEL &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) > MAX_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) > MAX_PERCENT_OF_UNIQUE_DOMAINS   //percent of unique domains
         ){  //percent of unique search
         item->state = STATE_TUNNEL;
      }


   }
   //other anomaly detection   
  if(item->suspision->other_suspision != NULL){
      tree = item->suspision->other_suspision;
      if (tree->count_of_searching > MIN_DNS_REQUEST_COUNT_OTHER_ANOMALY &&
         (double)(tree->count_of_domain_searched_just_ones) / (double)(tree->count_of_searching) < MIN_PERCENT_OF_DOMAIN_SEARCHING_JUST_ONCE &&      //percent of searching unique domains
         (double)(tree->count_of_different_domains) / (double)(tree->count_of_searching) < MIN_PERCENT_OF_UNIQUE_DOMAINS   //percent of unique domains
         ){
         //printf("print just ones %f\n", (float)tree->count_of_domain_searched_just_ones / (float)item->dns_request_count );
         if(item->state != STATE_TUNNEL){
            item->state = STATE_OTHER_ANOMALY;
         }
         else{
            item->state = STATE_TUNNEL_AND_OTHER_ANOMALY;
         }
      }
         
   }
   //if there wasnt any payload problem
   if(item->state == STATE_OK){
      item->round_in_suspiction++;
      //maximum round in suspiction
      if(item->round_in_suspiction > MAX_COUNT_OF_ROUND_IN_SUSPICTION){
         item->round_in_suspiction = 0;
         check_and_delete_suspision(item);
      }
      else{
         item->state == STATE_SUSPISION;
      } 
   }
   return item->state;
}



ip_address_t * calculate_statistic_and_choose_anomaly(ip_address_t * ip_rec, void * tree){
   ip_address_t * item;
   ip_address_t * previous = NULL;
   ip_address_t * start;

   calulated_result_t result;
   start = ip_rec;
   item = ip_rec;

   while(item != NULL){
      calculate_statistic(item, &result);
      //without anomaly
      if((item->state == STATE_SUSPISION && is_payload_on_ip_ok(item) == STATE_OK) || //second round of automat, it payload of traffic is ok or there is probably something
         (item->state == STATE_NEW && is_traffic_on_ip_ok(item, &result) == STATE_OK)   //first round of automat, if traffic is Ok or it looks like there is anomally
         ) 
      {
         ip_address_t * item_to_delete;
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
         }
         delete_item_b_plus_tree(tree, item_to_delete);

      }
      //with anomaly
      else{
         previous=item;
         item=item->next;
      }
   }
   //return anomaly items
   return start;
}

void print_results(ip_address_t *item){
   prefix_tree_domain_t *dom;
   char str[256];
         //printing result
         if(item == NULL)
            return;

            if(/*item->state == STATE_TUNNEL || item->state == STATE_OTHER_ANOMALY || item->state == STATE_TUNNEL_AND_OTHER_ANOMALY*/1){
               char ip_buff[100] = {0};
               ip_addr_t ip_to_translate = ip_from_int(item->ip);
               ip_to_str(&ip_to_translate ,ip_buff);
               printf("%s\n", ip_buff);
            }
            //print founded anomaly tunnel
            if(/*item->suspision &&  item->suspision->tunnel_suspision */item->state == STATE_TUNNEL || item->state == STATE_TUNNEL_AND_OTHER_ANOMALY){
               printf(" tunnel found:  domain searched just once %f \t count of different domains %f  all requests %d\n", (double)(item->suspision->tunnel_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision->tunnel_suspision->count_of_searching_for_just_ones), (double)item->suspision->tunnel_suspision->count_of_different_domains/(double)(item->suspision->tunnel_suspision->count_of_searching_for_just_ones),(item->suspision->tunnel_suspision->count_of_searching) );
               for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
                  if(item->suspision->state_request_size[i] == STATE_TUNNEL || item->suspision->state_request_size[i] == STATE_TUNNEL_AND_OTHER_ANOMALY )
                  printf("%d-%d\t", i*10,i*10+10);
               } 
               printf("\n");

               dom =item->suspision->tunnel_suspision->list_of_most_unused_domains;
               for(int i=0; i<5;i++){
                  str[0]=0;
                  if(dom==NULL) break;
                  printf("%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
                  dom= dom->most_used_domain_less;
               }               
            }
            //print founded anomaly other
            if(/*item->suspision &&  item->suspision->other_suspision  */item->state == STATE_OTHER_ANOMALY || item->state == STATE_TUNNEL_AND_OTHER_ANOMALY){
               
               
               
               
               printf(" other found:  domain searched just once %f \t count of different domains %f  all requests %d\n", (double)(item->suspision->other_suspision->count_of_domain_searched_just_ones) /(double)(item->suspision->other_suspision->count_of_searching_for_just_ones), (double)item->suspision->other_suspision->count_of_different_domains/(double)(item->suspision->other_suspision->count_of_searching_for_just_ones),(item->suspision->other_suspision->count_of_searching) );
             for (int i=0; i<HISTOGRAM_SIZE_REQUESTS; i++){
                  if(item->suspision->state_request_size[i] == STATE_OTHER_ANOMALY || item->suspision->state_request_size[i] == STATE_TUNNEL_AND_OTHER_ANOMALY )
                  printf("%d-%d\t", i*10,i*10+10);
               } 
                 
         
               dom =item->suspision->other_suspision->list_of_most_used_domains;
               for(int i=0; i<5;i++){
                  str[0]=0;
                  if(dom==NULL) break;
                  printf("%s. %d\n",  read_doamin(dom, str), dom->count_of_search);
                  dom= dom->most_used_domain_less;
               }
               printf("\n");
               printf("\n");
            }
            return print_results(item->next);

}

void print_suspision(ip_address_t *item){
   char ip_buff[100] = {0};
   ip_addr_t ip_to_translate;
   printf("\nSUSPISION\n");
   while(item!=NULL){
      if(item->state == STATE_SUSPISION){
         ip_to_translate = ip_from_int(item->ip);
         ip_to_str(&ip_to_translate ,ip_buff);
         printf("%s\n", ip_buff);
      }
      item = item->next;
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
void write_detail_result(char * record_folder_name, ip_address_t * list_of_ip){
   FILE *file_requests, 
        *file_responses,
        *file_requests_count_letters;
   char ip_buff[100] = {0};
   ip_addr_t ip_to_translate;
   char file_path [255];

   //open files
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUESTS);
   file_requests = fopen(file_path, "w");
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_RESPONSES);
   file_responses = fopen(file_path, "w");   
   strcpy(file_path, record_folder_name);
   strcat(file_path, "/" FILE_NAME_REQUEST_COUNT_LETTERS);
   file_requests_count_letters = fopen(file_path, "w"); 
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
   while(list_of_ip){
      //translate ip int to str 
      ip_to_translate = ip_from_int(list_of_ip->ip);
      ip_to_str(&ip_to_translate,ip_buff);
      //count ex value
      
      //requests
      fprintf(file_requests, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_buff, list_of_ip->ex_request, list_of_ip->var_request, list_of_ip->skewness_request, list_of_ip->kurtosis_request);
      for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
         fprintf(file_requests, "%lu\t",list_of_ip->histogram_dns_requests[i]);
      }    
      fprintf(file_requests, "%lu\n", list_of_ip->histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS - 1]);  
      //requests count letter
      fprintf(file_requests_count_letters, "%s__EX=%f__VarX=%f\t", ip_buff, list_of_ip->ex_request_count_of_different_letters, list_of_ip->var_request_count_letters);
      for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
         //fprintf(file_requests_count_letters, "%lu\t",list_of_ip->histogram_dns_request_ex_cout_of_used_letter[i]);
      }
      //fprintf(file_requests_count_letters, "%lu\n", list_of_ip->histogram_dns_request_ex_cout_of_used_letter[HISTOGRAM_SIZE_REQUESTS - 1]); 
      //response
      fprintf(file_responses, "%s__EX=%f__VarX=%f__skewness=%f__kurtosis=%f\t", ip_buff, list_of_ip->ex_response, list_of_ip->var_response, list_of_ip->skewness_response, list_of_ip->kurtosis_response);
      for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
         fprintf(file_responses, "%lu\t",list_of_ip->histogram_dns_response[i]);
      }
      fprintf(file_responses, "%lu\n", list_of_ip->histogram_dns_response[HISTOGRAM_SIZE_RESPONSE - 1]); 
      //next item
      list_of_ip = list_of_ip->next;
   }
   fclose(file_requests);
   fclose(file_requests_count_letters);
   fclose(file_responses);

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
   while ((opt = getopt(argc, argv, "u:p:s:f:")) != -1) {
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
         case 'f':
            input_packet_file_name = optarg;
            //if the folder does not exist it will create
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

   
   //inicialize b+ tree
   btree = inicialize_b_plus_tree(5);

   //inicialize prefix tree
   preftree = inicialize_prefix_tree();

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
            uint32_t ip_in_packet_int;
            // Update counters
            size = ur_get(tmplt, data, UR_BYTES);
            ip_in_packet = & ur_get(tmplt, data, UR_SRC_IP);
            ip_in_packet_int = ip_get_v4_as_int(ip_in_packet);
            if(ip_is4(ip_in_packet))
               list_of_ip = add_to_list(list_of_ip, &ip_in_packet_int, size, 1);
            histogram_dns_requests[size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
         }
         //is it source port of DNS (Port 53)
         else if(ur_get(tmplt, data, UR_SRC_PORT) == 53){
            int size;
            ip_addr_t * ip_in_packet;
            uint32_t ip_in_packet_int;
            // Update counters
            size = ur_get(tmplt, data, UR_BYTES);
            ip_in_packet = & ur_get(tmplt, data, UR_DST_IP);
            ip_in_packet_int = ip_get_v4_as_int(ip_in_packet);
            if(ip_is4(ip_in_packet))
               list_of_ip = add_to_list(list_of_ip, &ip_in_packet_int , size, 0);
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
               if(packet.src_ip !=0){
                  //list_of_ip = add_to_list(list_of_ip, &(packet.src_ip), packet.size, 1);
                  if(packet.request_string != NULL){
                     //printf("%s  %d\n", packet.request_string, packet.request_length );
                     add_to_prefix_tree(preftree, packet.request_string, packet.request_length, NULL);
                  }
                  add_to_bplus_tree(btree, &(packet.src_ip), packet.size, 1, packet.request_string, packet.request_length);
               }
               histogram_dns_requests[packet.size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? packet.size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
            }
            //is it source port of DNS (Port 53)
            else{
               // Update counters
               if(packet.dst_ip !=0){
                  //list_of_ip = add_to_list(list_of_ip, &(packet.dst_ip), packet.size, 0);
                  add_to_bplus_tree(btree, &(packet.src_ip), packet.size, 0, packet.request_string, packet.request_length);
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
         printf("end \n");
         list_of_ip = get_list(btree);
         list_of_ip = calculate_statistic_and_choose_anomaly(list_of_ip, btree);
         //stop=1;         

      }
      //close reading from file
      parser_end(input);
   }
   
   // ***** Print results *****
 print_results(list_of_ip);  
 print_suspision(list_of_ip);
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
         write_detail_result(record_folder_name, list_of_ip);
      }

   }
   
   


   // ***** Cleanup *****
   while(list_of_ip!=NULL){
      check_and_delete_suspision(list_of_ip);
      list_of_ip = list_of_ip->next;
   }
   destroy_b_plus_tree(btree);
   destroy_prefix_tree(preftree);

   //free_ip_list(list_of_ip);
   // Do all necessary cleanup before exiting
   //TRAP_DEFAULT_FINALIZATION();
   
   ur_free_template(tmplt);
   
   return 0;
   
}

