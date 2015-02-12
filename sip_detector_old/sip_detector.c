/**
 * \file sip_detector.c
 * \brief Saves SIP statistics to memory and periodically saves them to stats.txt.
 * \author Nikolas Jisa <jisaniko@fit.cvut.cz>
 * \author Katerina Pilatova <xpilat05@stud.fit.vutbr.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2013,2014 CESNET
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

#include "sip_detector.h"

static int stop = 0;
static cc_hash_table_v2_t ht_ips;
static char start_time_string[SIP_STATISTICS_TIME_MAX_LEN];

void signal_handler(int sig) {
   if (sig == SIGALRM) {
      sip_detector_save_statistics(&ht_ips);
      signal(SIGALRM, signal_handler);
      alarm(SIP_ALARM_PERIOD);
   }
   if (sig == SIGTERM || sig == SIGINT) {
      stop = 1;
      trap_terminate();
   }
   if (sig == SIGSEGV) {
      fprintf(stderr, "Segmentation fault\n");
#ifdef DEBUG
      fprintf(stderr, "Stack trace:\n");
      void* trace_ptrs[100];
      size_t count = backtrace(trace_ptrs, 100);
      char** function_names = backtrace_symbols(trace_ptrs, count);
      for (int i = 0; i < count; i++) {
         fprintf(stderr, "%s\n", function_names[i]);
      }
      free(function_names);
#endif
      trap_terminate();
      exit(1);
   }
}

void sip_detector_save_statistics(cc_hash_table_v2_t* ht_ips) {
   static char file_name[SIP_STATISTICS_FILE_NAME_MAX_LEN];
   time_t t = time(NULL);
   struct tm tm = *localtime(&t);
   static char end_time_string[SIP_STATISTICS_TIME_MAX_LEN];
   strftime(end_time_string, SIP_STATISTICS_TIME_MAX_LEN, SIP_STATISTICS_TIME_FORMAT, &tm);
   
   strcpy(file_name, SIP_STATISTICS_FILE_NAME_PREFIX); 
   strcat(file_name, start_time_string);
   strcat(file_name, SIP_STATISTICS_TIME_SEPARATOR);
   strcat(file_name, end_time_string);
   strcat(file_name, SIP_STATISTICS_FILE_NAME_SUFFIX);
   
   // Create directory if it does not exist
   mkdir(SIP_STATISTICS_DIRECTORY, 0755);
#ifdef DEBUG
   printf("***** Saving statistics to file %s *****\n", file_name);
#endif
   FILE* file = fopen(file_name, "w");
   if (file == NULL) {
      fprintf(stderr, "ERROR: Cannot open file %s.\n", file_name);
      return;
   }
   sip_ip_entry_print_header(file);
   for (int i = 0; i < ht_ips->table_size; i++) {
      if (ht_ips->ind[i].valid == 0) {
         continue;
      }
      sip_ip_entry_print(file, ht_ips->data[ht_ips->ind[i].index]);
   }
   if (ferror(file)) {
      fprintf(stderr, "ERROR: Cannot write to file.\n");
   }
   fclose(file);
#ifdef DEBUG
   printf("***** Saved statistics to file %s *****\n", file_name);
#endif
}

static sip_ip_entry_t new_ip_entry;
static int ht_full = 0;

sip_ip_entry_t* get_or_insert_ip_entry(cc_hash_table_v2_t* ht_ips, ip_addr_t* ip_ptr, sip_ip_entry_t new_ip_entry) {
   // Get or create sip_ip_entry
   sip_ip_entry_t* ip_entry_ptr = (sip_ip_entry_t*)ht_get_v2(ht_ips, (char*)ip_ptr);
   // Create new sip_ip_entry if it doesn't exist.
   if (ip_entry_ptr == NULL && ht_full == 0) {
      if (ht_insert_v2(ht_ips, (char*)ip_ptr, (void*)&new_ip_entry) != NULL) {
#ifdef DEBUG
         printf("Hash table with ip entries is FULL\n");
#endif
         ht_full = 1;
      }
      ip_entry_ptr = (sip_ip_entry_t*)ht_get_v2(ht_ips, (char*)ip_ptr);
      ip_entry_ptr->ip = *ip_ptr;
   }
   return ip_entry_ptr;
}

static regex_t sip_via_regex;

static void sip_detector_process_via_compile_regex() {
   regcomp(&sip_via_regex, SIP_VIA_PATTERN, REG_EXTENDED);
}

void sip_detector_process_via(cc_hash_table_v2_t* ht_ips, ur_template_t* tmplt, const void* data) {
   static char via[SIP_VIA_MAX_LEN + 1];
   static const char* match_ptr;
   static regmatch_t matches[3];
   static ip_addr_t ip;
   
   const char* via_ptr = ur_get_dyn(tmplt, data, UR_INVEA_SIP_VIA);
   int len = ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_VIA);
   sip_ip_entry_t* ip_entry_ptr;

   if (len > SIP_VIA_MAX_LEN) {
      len = SIP_VIA_MAX_LEN;
   }
   memcpy(via, via_ptr, len);
   via[len] = '\0';
   match_ptr = via;
   while (1) {
      int nomatch = regexec(&sip_via_regex, match_ptr, 3, matches, 0);
      if (nomatch == 1) {
         return;
      }
      if (ip_from_str(match_ptr + matches[2].rm_so, &ip) != 0) {
         ip_entry_ptr = get_or_insert_ip_entry(ht_ips, &ip, new_ip_entry);
         if (ip_entry_ptr != NULL) {
            ip_entry_ptr->as_proxy++;
         }
      }
      match_ptr += matches[0].rm_eo;
   }
}

void sip_detector_print_accepted_msg(FILE* file, ur_template_t* tmplt, const void* data, uint16_t data_size) {
   static char ip_src_str[SIP_IP_STR_MAX_LEN];
   static char ip_dst_str[SIP_IP_STR_MAX_LEN];
   
   ip_to_str(ur_get_ptr(tmplt, data, UR_SRC_IP), ip_src_str);
   ip_to_str(ur_get_ptr(tmplt, data, UR_DST_IP), ip_dst_str);

   fprintf(file,
      "Accepted SIP msg: "
      "data_size = %d, "
      "src_ip = %s, "
      "dst_ip = %s, "
      "call_id = %.*s, "
      "from = %.*s, "
      "to = %.*s, "
      "via = %.*s, ",
      data_size,
      ip_src_str,
      ip_dst_str,
      ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALL_ID), ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALL_ID),
      ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALLING_PARTY), ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALLING_PARTY),
      ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALLED_PARTY), ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALLED_PARTY),
      ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_VIA), ur_get_dyn(tmplt, data, UR_INVEA_SIP_VIA)
   );
   uint8_t packet_type = ur_get(tmplt, data, UR_INVEA_VOIP_PACKET_TYPE);
   uint64_t sip_stats = ur_get(tmplt, data, UR_INVEA_SIP_STATS);
   switch(packet_type) {
   case NON_VOIP:
      fprintf(file,
         "packet_type = NON VOIP"
      );
      break;
   case SERVICE_SIP_REQUEST:
      fprintf(file,
         "packet_type = SERVICE SIP REQUEST, "
         "INFO = %lu, "
         "PUBLISH = %lu, "
         "NOTIFY = %lu, "
         "SUBSCRIBE = %lu, "
         "OPTIONS = %lu, "
         "REGISTER = %lu",
         SIP_STATS_0,
         SIP_STATS_8,
         SIP_STATS_16(packet_type),
         SIP_STATS_24,
         SIP_STATS_32(packet_type),
         SIP_STATS_48(packet_type)
      );
      break;
   case SERVICE_SIP_RESPONSE:
      fprintf(file,
         "packet_type = SERVICE SIP RESPONSE, "
         "OK = %lu, "
         "BAD REQUEST = %lu, "
         "FORBIDDEN = %lu, "
         "INTERNAL ERROR = %lu, "
         "NOT FOUND = %lu, "
         "PROXY AUTH. REQ. = %lu, "
         "UNAUTHORIZED = %lu, "
         "TRYING = %lu",
         SIP_STATS_0,
         SIP_STATS_8,
         SIP_STATS_16(packet_type),
         SIP_STATS_24,
         SIP_STATS_32(packet_type),
         SIP_STATS_40,
         SIP_STATS_48(packet_type),
         SIP_STATS_56
      );
      break;
   case CALL_SIP_REQUEST:
      fprintf(file,
         "packet_type = CALL SIP REQUEST, "
         "CANCEL = %lu, "
         "ACK = %lu, "
         "BYE = %lu, "
         "INVITE = %lu",   
         SIP_STATS_0,
         SIP_STATS_8,
         SIP_STATS_16(packet_type),
         SIP_STATS_32(packet_type)
      );
      break;
   case CALL_SIP_RESPONSE:
      fprintf(file,
         "packet_type = CALL SIP RESPONSE, "
         "OK = %lu, "
         "BUSY HERE = %lu, "
         "RINGING = %lu, "
         "DECLINE = %lu, "
         "DIALOG ESTABILISH = %lu, "
         "SESSION PROGRESS = %lu, "
         "PROXY AUTH. = %lu, "
         "TRYING = %lu",
         SIP_STATS_0,
         SIP_STATS_8,
         SIP_STATS_16(packet_type),
         SIP_STATS_24,
         SIP_STATS_32(packet_type),
         SIP_STATS_40,
         SIP_STATS_48(packet_type),
         SIP_STATS_56
      );
      break;
   case RTP_VOICE_DATA:
      fprintf(file,
         "packet_type = RTP VOICE DATA"
      );
      break;
   case RTCP_STATISTIC_DATA:
      fprintf(file,
         "packet_type = RTCP STATISTIC DATA"
      );
      break;
   }
   fprintf(file, "\n");
   if (ferror(file)) {
      fprintf(stderr, "ERROR: Cannot write to file.\n");
   }
}

void sip_detector_update_counters(ur_template_t* tmplt, const void* data) {
   static uint64_t request_count;
   static uint64_t response_count;

   uint8_t packet_type = (uint8_t)ur_get(tmplt, data, UR_INVEA_VOIP_PACKET_TYPE);
   uint64_t sip_stats = (uint64_t)ur_get(tmplt, data, UR_INVEA_SIP_STATS);
   switch(packet_type) {
   case NON_VOIP:
      break;
   case SERVICE_SIP_REQUEST:
      request_count += SIP_STATS_0 + SIP_STATS_8 + SIP_STATS_16(packet_type) + SIP_STATS_24 + SIP_STATS_32(packet_type) + SIP_STATS_48(packet_type);
      break;
   case SERVICE_SIP_RESPONSE:
      response_count += SIP_STATS_0 + SIP_STATS_8 + SIP_STATS_16(packet_type) + SIP_STATS_24 + SIP_STATS_32(packet_type) + SIP_STATS_48(packet_type);
      break;
   case CALL_SIP_REQUEST:
      request_count += SIP_STATS_0 + SIP_STATS_8 + SIP_STATS_16(packet_type) + SIP_STATS_24 + SIP_STATS_32(packet_type) + SIP_STATS_48(packet_type);
      break;
   case CALL_SIP_RESPONSE:
      response_count += SIP_STATS_0 + SIP_STATS_8 + SIP_STATS_16(packet_type) + SIP_STATS_24 + SIP_STATS_32(packet_type) + SIP_STATS_48(packet_type);
      break;
   case RTP_VOICE_DATA:
      break;
   case RTCP_STATISTIC_DATA:
      break;
   }
}

int main(int argc, char** argv)
{
#ifdef DEBUG
   printf("*###* DEBUG is defined *###*\n");
#endif

   // ***** TRAP initialization *****
#ifdef DEBUG
   printf("***** TRAP initialization *****\n");
#endif

   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGALRM, signal_handler);
   signal(SIGSEGV, signal_handler);

   // ***** Getting verbosity level *****
   int verbosity = trap_get_verbose_level();

   // ***** Create UniRec template *****
#ifdef DEBUG
   printf("***** Creating UniRec template *****\n");
#endif

   char *unirec_specifier = "<COLLECTOR_FLOW>,<VOIP>";
   ur_template_t *tmplt = ur_create_template(unirec_specifier);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return 4;
   }
   
#ifdef DEBUG
   ur_print_template(tmplt);
#endif
   
   // ***** Initialize structures *****
#ifdef DEBUG
   printf("***** Initializing structures *****\n");
#endif
   sip_detector_process_via_compile_regex();
   memset(&new_ip_entry, 0, sizeof(new_ip_entry));
   
   // Set program start time
   time_t t = time(NULL);
   struct tm tm = *localtime(&t);
   strftime(start_time_string, SIP_STATISTICS_TIME_MAX_LEN, SIP_STATISTICS_TIME_FORMAT, &tm);
   // ***** Initialize hash table *****
#ifdef DEBUG
   printf("***** Hash table initialization *****\n");
#endif
   ht_init_v2(&ht_ips, SIP_IP_ENTRIES_NUM, sizeof(sip_ip_entry_t), sizeof(ip_addr_t));
  
  // ***** Receive data *****
#ifdef DEBUG
   printf("***** Receiving data *****\n");
#endif
   alarm(SIP_ALARM_PERIOD);

   const void *data;
   uint16_t data_size;
   int ret;
   
   sip_ip_entry_t* src_ip_entry_ptr;
   sip_ip_entry_t* dst_ip_entry_ptr;
   ip_addr_t* src_ip_ptr;
   ip_addr_t* dst_ip_ptr;

   while (!stop) {
      // Receive data from any interface (blocking).
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);
      
      // Check size of received data.
      if (data_size < ur_rec_static_size(tmplt)) {
         fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, "
                         "received size: %hu)\n", ur_rec_static_size(tmplt), data_size);
         break;
      }
      
      if (verbosity > 1) {
         sip_detector_print_accepted_msg(stdout, tmplt, data, data_size);
      }

      // Get source ip.
      src_ip_ptr = ur_get_ptr(tmplt, data, UR_SRC_IP);
      dst_ip_ptr = ur_get_ptr(tmplt, data, UR_DST_IP);
      src_ip_entry_ptr = get_or_insert_ip_entry(&ht_ips, src_ip_ptr, new_ip_entry);
      dst_ip_entry_ptr = get_or_insert_ip_entry(&ht_ips, dst_ip_ptr, new_ip_entry);

      if (src_ip_entry_ptr != NULL) {
         src_ip_entry_ptr->as_ep_from++;
      }
      if (dst_ip_entry_ptr != NULL) {
         dst_ip_entry_ptr->as_ep_to++;
      }
      sip_ip_entry_update_diff_ips(src_ip_entry_ptr, dst_ip_entry_ptr, tmplt, data);
      sip_ip_entry_update_diff_names(src_ip_entry_ptr, dst_ip_entry_ptr, tmplt, data);
      sip_ip_entry_update_calls(src_ip_entry_ptr, dst_ip_entry_ptr, tmplt, data);
      sip_detector_process_via(&ht_ips, tmplt, data);
      //sip_detector_update_counters(tmplt, data);
   }
   
   // ***** Saving statistics to file *****
   sip_detector_save_statistics(&ht_ips);
   // ***** Cleanup *****
#ifdef DEBUG
   printf("***** Cleaning up *****\n");
#endif
   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(tmplt);
   ht_destroy_v2(&ht_ips);

   return 0;
}
