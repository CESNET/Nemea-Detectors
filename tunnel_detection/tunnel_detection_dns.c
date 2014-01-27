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

#include "tunnel_detection_dns.h"

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
   create = (ip_address_t *) malloc(sizeof(ip_address_t)); 
   //write next list item
   create->next = next;
   create->ip = *ip;
   //clear allocated memory
   memset(create->histogram_dns_requests, 0, HISTOGRAM_SIZE_REQUESTS * sizeof(unsigned long));
   memset(create->histogram_dns_response, 0, HISTOGRAM_SIZE_RESPONSE * sizeof(unsigned long));
   return create; 
}

ip_address_t * find_ip(uint32_t * search_ip, ip_address_t * struc){
   //if it is on the end of the list or it found item
   if(struc == NULL || struc->ip == * search_ip)
      return struc;
   //recursive call function on next item in list
   return find_ip(search_ip, struc->next);
}

ip_address_t * add_to_list( ip_address_t * listOfIp, uint32_t * ip_in_packet, int size, char request){
   ip_address_t * found;
   found = find_ip(ip_in_packet, listOfIp);
   //if item was not found or list is free, create new item
   if (found == NULL){
      found = crete_new_ip_address_struc(ip_in_packet, listOfIp);
      listOfIp=found;
   }
   //add to request or response
   if(request == 1){
      found->histogram_dns_requests[size <= (HISTOGRAM_SIZE_REQUESTS - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_REQUESTS - 1]++;
   }
   else{
      found->histogram_dns_response[size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
   }
   return listOfIp;
}

void free_ip_list(ip_address_t * list){
      ip_address_t * next_item;
   while(list != NULL){
      next_item = list->next;
      free(list);
      list=next_item;
   }
}

void write_summary_result(char * record_folder, unsigned long * histogram_dns_requests, unsigned long * histogram_dns_response){
   FILE *file;
   char file_path [255];
   strcpy(file_path, record_folder);
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

   strcpy(file_path, record_folder);
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
void write_detail_result(char * record_folder, ip_address_t * list_of_ip){
   FILE *file_requests, 
        *file_responses;
   char ip_buff[100] = {0};
   ip_addr_t ip_to_translate;
   char file_path [255];

   //open files
   strcpy(file_path, record_folder);
   strcat(file_path, "/" FILE_NAME_REQUESTS);
   file_requests = fopen(file_path, "w");
   strcpy(file_path, record_folder);
   strcat(file_path, "/" FILE_NAME_RESPONSES);
   file_responses = fopen(file_path, "w");   
   //print titles 
   fprintf(file_requests, TITLE_REQUESTS "\n");
   fprintf(file_responses, TITLE_RESPONSES "\n");
   //print range to requests
   fprintf(file_requests,  "ip\t");
   for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){

      fprintf(file_requests, "%d-%d\t",i * 10, (i + 1) * 10);
   }
   fprintf(file_requests, "%d-inf\n",(HISTOGRAM_SIZE_REQUESTS-1) * 10);
   //print range to respones
   fprintf(file_responses,  "ip\t");
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
      //requests
      fprintf(file_requests, "%s\t", ip_buff);
      for(int i=0;i<HISTOGRAM_SIZE_REQUESTS - 1; i++){
         fprintf(file_requests, "%lu\t",list_of_ip->histogram_dns_requests[i]);
      }    
      fprintf(file_requests, "%lu\n", list_of_ip->histogram_dns_requests[HISTOGRAM_SIZE_REQUESTS -1]);  
      //respones  
      fprintf(file_responses, "%s\t", ip_buff);  
      for(int i=0;i<HISTOGRAM_SIZE_RESPONSE - 1; i++){
         fprintf(file_responses, "%lu\t",list_of_ip->histogram_dns_response[i]);
      }    
      fprintf(file_responses, "%lu\n", list_of_ip->histogram_dns_response[HISTOGRAM_SIZE_REQUESTS -1]);  
      //next item
      list_of_ip = list_of_ip->next;
   }
   fclose(file_requests);
   fclose(file_responses);

}

int main(int argc, char **argv)
{
   int ret;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   unsigned long histogram_dns_requests [HISTOGRAM_SIZE_REQUESTS];
   unsigned long histogram_dns_response [HISTOGRAM_SIZE_RESPONSE];
   ip_address_t * listOfIp = NULL;
   char write_summary = 0;
   memset(histogram_dns_requests, 0, HISTOGRAM_SIZE_REQUESTS * sizeof(unsigned long));
   memset(histogram_dns_response, 0, HISTOGRAM_SIZE_RESPONSE * sizeof(unsigned long));

   // ***** TRAP initialization *****
   
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGUSR1, signal_handler);
   
   // ***** Create UniRec template *****
   
   char *unirec_specifier = "<COLLECTOR_FLOW>";
   char opt;
   char *record_folder = NULL;
   while ((opt = getopt(argc, argv, "u:p:s:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'p':
            progress = atoi(optarg);
            break;
         case 's':
            record_folder = optarg;
            write_summary = 1;
            //if the folder does not exist it will create
            mkdir(optarg,  S_IRWXU|S_IRGRP|S_IXGRP);
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

   
   
   // ***** Main processing loop *****
   
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
            listOfIp = add_to_list(listOfIp, &ip_in_packet_int, size, 1);
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
            listOfIp = add_to_list(listOfIp, &ip_in_packet_int , size, 0);
         histogram_dns_response[size <= (HISTOGRAM_SIZE_RESPONSE - 1) * 10 ? size / 10 : HISTOGRAM_SIZE_RESPONSE - 1]++;
      }
      if (stats == 1) {
         printf("Time: %lu\n", (long unsigned int) time(NULL));
         signal(SIGUSR1, signal_handler);
         stats = 0;
      }
   }
   
   // ***** Print results *****

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

   // *****  Write into file ******
   if (write_summary){
      write_summary_result(record_folder, histogram_dns_requests, histogram_dns_response);
      write_detail_result(record_folder, listOfIp);
   }
   
      
   // ***** Cleanup *****
   free_ip_list(listOfIp);
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   
   ur_free_template(tmplt);
   
   return 0;
   
}

