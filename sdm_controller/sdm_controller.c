/**
 * \file sdm_controller.c
 * \brief Nemea module which receives data from detectors or report's aggregators 
 *        and remotely controls probe with filter_storage plugin for capturing packets.
 * \author Matej Vido, xvidom00@stud.fit.vutbr.cz
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <arpa/inet.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>

#include "sdm_controller.h"

trap_module_info_t module_info = {
   "SDM controller module", //Module name
   //Module description
   "Nemea module which receives data from detectors or report's aggregators and remotely\n"
   "controls probe with filter_storage plugin for capturing packets.\n"
   "Interfaces:\n"
   "   Inputs: variable\n"
   "      (UniRec: output of hoststatsnemea, dns_amplification, slowthreatdetector)\n"
   "      hoststatsnemea: EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE\n"
   "      dns_amplification: <AMPLIFICATION_ALERT>\n"
   "      slowthreatdetector: <WARDEN_REPORT>\n"
   "   Outputs: 1 (UniRec: <SDM_CAPTURE_REQUEST>)\n",
   0, //Number of input interfaces - will be set according to command line arguments
   1, //Number of output interfaces
};

static int stop = 0;

//handle SIGTERM and SIGINT signals
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

uint32_t timeout = DEFAULT_TIMEOUT;
uint32_t packets = DEFAULT_PACKETS;
int detectors_interface[DETECTORS_NUMBER];
//new detector add here
char * in_templates_strings[DETECTORS_NUMBER] = {
   "EVENT_TYPE,TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,EVENT_SCALE",//hoststats
   "<AMPLIFICATION_ALERT>",//dns_amplification
   "<WARDEN_REPORT>",//slowthreat
   "",//sip (do not have output yet)
};

/**
 * \brief Function sets value and converts to string IP address of attacker or of victim,
 *        if attacker's is not available.
 *
 * \return  0  on success
 *          1  on failure
 */
int get_correct_ip_str_and_value(ur_template_t * in_template, const void * in_rec, char *ip_str, ip_addr_t *ip_value, unsigned attck_id, unsigned victim_id)
{
   ip_addr_t null_ip = ip_from_int(0);
   if (ur_is_present(in_template, attck_id) && ip_cmp((const ip_addr_t *) ur_get_ptr_by_id(in_template, in_rec, attck_id), (const ip_addr_t *) &null_ip) != 0) {
      ip_to_str(ur_get_ptr_by_id(in_template, in_rec, attck_id), ip_str);
      *ip_value = *((ip_addr_t *)ur_get_ptr_by_id(in_template, in_rec, attck_id));
      return 0;
   } else if (ur_is_present(in_template, victim_id) && ip_cmp((const ip_addr_t *) ur_get_ptr_by_id(in_template, in_rec, victim_id), (const ip_addr_t *) &null_ip) != 0) {
      ip_to_str(ur_get_ptr_by_id(in_template, in_rec, victim_id), ip_str);
      *ip_value = *((ip_addr_t *)ur_get_ptr_by_id(in_template, in_rec, victim_id));
      return 0;
   } else {
      return 1;
   }
}

/**
 * \brief Function converts unirec timestamp to string.
 *
 * \return  0  on success
 *          1  on failure
 */
int get_time_str(ur_template_t * in_template, const void * in_rec, char *time_str, unsigned timestamp_id)
{
   const time_t seconds = ur_time_get_sec(*((ur_time_t *)ur_get_ptr_by_id(in_template, in_rec, timestamp_id)));
   struct tm time_info;

   if (!ur_is_present(in_template, timestamp_id))
      return 1;
   if (localtime_r(&seconds, &time_info) == NULL)
      return 1;
   if (strftime(time_str, TIME_STR_LENGTH, "%Y-%m-%d-%H:%M:%S", &time_info) == 0)
      return 1;
   else
      return 0;
}

/**
 * \brief Main function of every thread reading from one detector.
 */
void *read_from_detector(void *arg)
{
   int detector = *(int *)arg;
   int ret;

   //create unirec templates
   ur_template_t *in_template = ur_create_template(in_templates_strings[detector]);
   ur_template_t *out_template = ur_create_template("<SDM_CAPTURE_REQUEST>");

   //allocate memory for output record
   void *out_rec = ur_create(out_template, MAX_ID_LENGTH);

   // *** Main processing loop ***

   while (!stop) {
      const void * in_rec;
      uint16_t in_rec_size;

      //receive data
      ret = trap_recv(detectors_interface[detector], &in_rec, &in_rec_size);
      //handle errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      //check size, may contain also dynamic fields
      if (in_rec_size < ur_rec_size(in_template, in_rec)) {
         if (in_rec_size <= 1) {
            break; //end of data (testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n", ur_rec_size(in_template, in_rec), in_rec_size);
            break;
         }
      }

      ip_addr_t ip_value;
      char et_str[MAX_EVENT_TYPE_LENGTH] = {0,};
      char ip_str[INET6_ADDRSTRLEN] = {0,};
      char time_str[TIME_STR_LENGTH] = {0,};
      char id_str[MAX_ID_LENGTH] = {0,};
      uint8_t et_str_len;
      uint8_t ip_str_len;
      uint8_t time_str_len;
      uint8_t id_str_len;
      
      //PROCESS DATA

      //get ip string and value
      switch (detector) {
      case HOSTSTATS:
      case DNS_AMPLIFICATION:
      case SLOWTHREAT:
         ret = get_correct_ip_str_and_value(in_template, in_rec, ip_str, &ip_value, UR_SRC_IP, UR_DST_IP);
         if (ret) {
            fprintf(stderr, "Error: record with wrong IP address received.\n");
            continue;
         }
         break;
      }
      
      //get time string in format YYYY-MM-DD-hh:mm:ss
      switch (detector) {
      case HOSTSTATS:
      case DNS_AMPLIFICATION:
         ret = get_time_str(in_template, in_rec, time_str, UR_TIME_LAST);
         if (ret && get_time_str(in_template, in_rec, time_str, UR_TIME_FIRST)) {
            fprintf(stderr, "Error: record with wrong timestamp received.\n");
            continue;
         }
         break;
      case SLOWTHREAT:
         ret = get_time_str(in_template, in_rec, time_str, UR_DETECTION_TIME);
         if (ret) {
            fprintf(stderr, "Error: record with wrong timestamp received.\n");
            continue;
         }
         break;
      }
      
      //get type of event
      switch (detector) {
      case DNS_AMPLIFICATION:
         strcpy(et_str, "DNS_AMPLIFICATION:DA");
         break;
      case HOSTSTATS:
      {
         switch (ur_get(in_template, in_rec, UR_EVENT_TYPE)) {
         case UR_EVT_T_PORTSCAN:
            strcpy(et_str, "PORTSCAN:HS");
            break;
         case UR_EVT_T_PORTSCAN_H:
            strcpy(et_str, "PORTSCAN_H");
            break;
         case UR_EVT_T_PORTSCAN_V:
            strcpy(et_str, "PORTSCAN_V");
            break;
         case UR_EVT_T_DOS:
            strcpy(et_str, "DOS:HS");
            break;
         case UR_EVT_T_SYNFLOOD:
            strcpy(et_str, "SYNFLOOD");
            break;
         case UR_EVT_T_DNSAMP:
            strcpy(et_str, "DNS_AMPLIFICATION:HS");
            break;
         case UR_EVT_T_BRUTEFORCE:
            strcpy(et_str, "BRUTEFORCE:HS");
            break;
         default:
            fprintf(stderr, "Error: record with wrong event type received.\n");
            continue;
         }
         break;
      }
      case SLOWTHREAT:
      {
         switch (ur_get(in_template, in_rec, UR_WARDEN_TYPE)) {
         case UR_WT_PORTSCAN:
            strcpy(et_str, "PORTSCAN:ST");
            break;
         case UR_WT_BRUTEFORCE:
            strcpy(et_str, "BRUTEFORCE:ST");
            break;
         case UR_WT_PROBE:
            strcpy(et_str, "PROBE");
            break;
         case UR_WT_SPAM:
            strcpy(et_str, "SPAM");
            break;
         case UR_WT_PHISHING:
            strcpy(et_str, "PHISHING");
            break;
         case UR_WT_BOTNET_C_C:
            strcpy(et_str, "BOTNET_C_C");
            break;
         case UR_WT_DOS:
            strcpy(et_str, "DOS:ST");
            break;
         case UR_WT_MALWARE:
            strcpy(et_str, "MALWARE");
            break;
         case UR_WT_COPYRIGHT:
            strcpy(et_str, "COPYRIGHT");
            break;
         case UR_WT_WEBATTACK:
            strcpy(et_str, "WEBATTACK");
            break;
         case UR_WT_VULNERABILITY:
            strcpy(et_str, "VULNERABILITY");
            break;
         case UR_WT_TEST:
            strcpy(et_str, "TEST");
            break;
         case UR_WT_OTHER:
            strcpy(et_str, "OTHER");
            break;
         default:
            fprintf(stderr, "Error: record with wrong event type received.\n");
            continue;
         }
         break;
      }//case
      }//switch

      et_str_len = strlen(et_str);
      ip_str_len = strlen(ip_str);
      time_str_len = strlen(time_str);
      //        EVENT_TYPE-IP_ADDRESS-YYYY-MM-DD-hh:mm:ss
      //< et_str >-< ip_str >-< time_str >'\0'
      id_str_len = et_str_len + ip_str_len + time_str_len + 3; //+2 due to matching minuses(-) and +1 due to '\0' at the end;

      strcpy(id_str, et_str);
      id_str[et_str_len] = '-';
      strcpy(&id_str[et_str_len + 1], ip_str);
      id_str[et_str_len + 1 + ip_str_len] = '-';
      strcpy(&id_str[et_str_len + ip_str_len + 2], time_str);

      ur_set(out_template, out_rec, UR_SRC_IP, ip_value);
      ur_set(out_template, out_rec, UR_TIMEOUT, timeout);
      ur_set(out_template, out_rec, UR_PACKETS, packets);
      ur_set_dyn(out_template, out_rec, UR_SDM_CAPTURE_FILE_ID, id_str, id_str_len);

#ifdef DEBUG
      printf("%s\n%s\n", id_str, ip_str);
#endif

      //send record
      ret = trap_send(0, out_rec, (ur_rec_static_size(out_template) + id_str_len));

      //handle errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, 0, break);
   } //while

   ur_free(out_rec);
   ur_free_template(in_template);
   ur_free_template(out_template);

   return NULL;
}

/** Main function **/

int main(int argc, char **argv)
{
   int ret_opt;
   int interface_num = 0;
   bool bad_arguments = false;
   pthread_t detectors_thread[DETECTORS_NUMBER];
   int i;
   int bck_optind = optind;
   int bck_optopt = optopt;
   int bck_opterr = opterr;
   char *bck_optarg = optarg;
   int thread_args[DETECTORS_NUMBER] = {0,};


   //set default value -1, means that detector is not used
   for (i = 0; i < DETECTORS_NUMBER; i++)
      detectors_interface[i] = -1;

   while (1) {
      int option_index = 0;
      //new detector add here
      static struct option long_options[] = {
         {"timeout",              required_argument, 0, 't'               },
         {"packets",              required_argument, 0, 'p'               },
         {"hoststats",            no_argument,       0, HOSTSTATS         },
         {"dns_amplification",    no_argument,       0, DNS_AMPLIFICATION },
         {"slowthreat",           no_argument,       0, SLOWTHREAT        },
//       {"sip",                  no_argument,       0, SIP               },
         {0,                                0,       0, 0                 }
      };
      
      ret_opt = getopt_long(argc, argv, "t:p:i", long_options, &option_index);
      if (ret_opt == -1)
         break;

      switch (ret_opt) {
      //new detector add here
      case HOSTSTATS:
      case DNS_AMPLIFICATION:
      case SLOWTHREAT:
      case SIP:
         detectors_interface[ret_opt] = interface_num++;
         break;
      case 't':
         {
            int64_t tmp_timeout;
            char *endptr;

            errno = 0;
            tmp_timeout = strtol(optarg, &endptr, 0);
            if ((errno == ERANGE && (tmp_timeout == LONG_MAX || tmp_timeout == LONG_MIN)) || (errno != 0 && tmp_timeout == 0)) {
               perror("strtol");
               bad_arguments = true;
               break;
            } else if (endptr == optarg) {
               fprintf(stderr, "--timeout: no digits found\n");
               bad_arguments = true;
               break;
            } else if (*optarg == '\0') {
               fprintf(stderr, "--timeout: missing argument\n");
               bad_arguments = true;
               break;
            } else if (*endptr != '\0') {
               fprintf(stderr, "--timeout: bad argument\n");
               bad_arguments = true;
               break;
            } else if (tmp_timeout < 0 || tmp_timeout > UINT32_MAX) {
               fprintf(stderr, "--timeout: bad value\n"
                               "           (0 <= timeout <= UINT32_MAX)\n");
               bad_arguments = true;
               break;
            }
            timeout = (uint32_t) tmp_timeout;
            break;
         }
      case 'p':
         {
            int64_t tmp_packets;
            char *endptr;

            errno = 0;
            tmp_packets = strtol(optarg, &endptr, 0);
            if ((errno == ERANGE && (tmp_packets == LONG_MAX || tmp_packets == LONG_MIN)) || (errno != 0 && tmp_packets == 0)) {
               perror("strtol");
               bad_arguments = true;
               break;
            } else if (endptr == optarg) {
               fprintf(stderr, "--packets: no digits found\n");
               bad_arguments = true;
               break;
            } else if (*optarg == '\0') {
               fprintf(stderr, "--packets: missing argument\n");
               bad_arguments = true;
               break;
            } else if (*endptr != '\0') {
               fprintf(stderr, "--packets: bad argument\n");
               bad_arguments = true;
               break;
            } else if (tmp_packets < 0 || tmp_packets > UINT32_MAX) {
               fprintf(stderr, "--packets: bad value\n"
                               "           (0 <= packets <= UINT32_MAX)\n");
               bad_arguments = true;
               break;
            }
            packets = (uint32_t) tmp_packets;
            break;
         }
      case 'i': //let trap parse it
         break;
      default:
         break;
      }
   }

   if (bad_arguments) {
      exit(EXIT_FAILURE);
   }

   optind = bck_optind;
   optopt = bck_optopt;
   opterr = bck_opterr;
   optarg = bck_optarg;

   module_info.num_ifc_in = interface_num;

   //TRAP initialization
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   //register signal handler
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();


   //create thread for every input interface
   for (i = 0; i < DETECTORS_NUMBER; i++) {
      if (detectors_interface[i] >= 0) {
         thread_args[i] = i;
         int ret = pthread_create(&detectors_thread[i], NULL, read_from_detector, (void *) &thread_args[i]);
         if (ret != 0) {
            fprintf(stderr, "ERROR while creating thread!\n");
            //all necessary cleanup before exit
            TRAP_DEFAULT_FINALIZATION();
            exit(EXIT_FAILURE);
         }
      }
   }

   for (i = 0; i < DETECTORS_NUMBER; i++) {
      if (detectors_interface[i] >= 0) {
         pthread_join(detectors_thread[i], NULL);
      }
   }

   //all necessary cleanup before exit
   TRAP_DEFAULT_FINALIZATION();
   return 0;
}
