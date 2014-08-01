/**
 * \file tor_detector.c
 * \brief Nemea module for detecting TOR exit nodes.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2014
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

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <unistd.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <ctype.h>

#include "tor_detector.h"
#include <nemea-common.h>

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "TOR Detector", // Module name
   // Module description
   "Module for detecting TOR exit nodes.\n"
   "Parameters:\n"
   "   file        File with network prefixes.\n" 
   "Interfaces:\n"
   "   Inputs: 1 <COLLECTOR_FLOW>\n"
   "   Outputs: 1 <COLLECTOR_FLOW>,TOR_FLAGS\n",
   1, // Number of input interfaces
   1, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;
static int update = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   } else {
      update = 1;
   }
}


void unirec_copy(ur_template_t *tmplt_dst, void *data_dst, ur_template_t *tmplt_src, const void *data_src)
{
   ur_field_id_t id;
   ur_iter_t iter = UR_ITER_BEGIN;
   while ((id = ur_iter_fields_tmplt(tmplt_src, &iter)) != UR_INVALID_FIELD) {
      if (ur_is_present(tmplt_dst, id)) {
         if (ur_is_dynamic(id)) {
            ur_set_dyn(tmplt_dst, data_dst, id, ur_get_dyn(tmplt_src, data_src, id), ur_get_dyn_size(tmplt_src, data_src, id));
         } else {
            memcpy(ur_get_ptr_by_id(tmplt_dst, data_dst, id), ur_get_ptr_by_id(tmplt_src, data_src, id), ur_get_size_by_id(id));
         }
      }
   }
}


tor_list_t *init_tor_list(void)
{
   tor_list_t *tor_list;

   tor_list = malloc(sizeof(tor_list_t));
   if (tor_list == NULL) {
      return NULL;
   }

   tor_list->ip_ar = malloc(sizeof(ip_addr_t) * ALLOC_STEP_COUNT);
   if (tor_list->ip_ar == NULL) {
      free(tor_list);
      return NULL;
   }

   tor_list->count = 0;
   tor_list->allocated = ALLOC_STEP_COUNT;

   return tor_list;
}


void update_tor_list(tor_list_t *tor_list)
{
   FILE *fp;
   char buffer[64] = {0};

   tor_list->count = 0; // No need to free data, we just owrite them with new

   fp = fopen(UPDATE_FILE_NAME, "r");

   while(fgets(buffer, 63, fp) != NULL) {
      // Trim newline character if is present
      if (buffer[strlen(buffer) - 1] == '\n') {
         buffer[strlen(buffer) - 1] = 0;
      }

      // Realloc memory if needed
      if (tor_list->count >= tor_list->allocated) {
         tor_list->ip_ar = realloc(tor_list->ip_ar, sizeof(ip_addr_t) * (tor_list->allocated + ALLOC_STEP_COUNT));
         tor_list->allocated += ALLOC_STEP_COUNT;
      }

      ip_from_str(buffer, &tor_list->ip_ar[tor_list->count]);
      tor_list->count++;
   }

   fclose(fp);
}





uint8_t ip_binary_search(ip_addr_t *ip, tor_list_t *tor_list)
{
   int begin, end, mid, result;

   begin = 0;
   end = tor_list->count;

   while (begin <= end) {
      mid = (begin + end) >> 1;

      result = memcmp(&(tor_list->ip_ar[mid].ui32[2]), &(ip->ui32[2]), 4);

      if (result < 0) {
         begin = mid + 1;
      }
      else if (result > 0) {
         end = mid - 1;
      } else {
         break;
      }
   }

   if (result == 0) {
      return 1;
   }

   return 0;
}



uint8_t check_ips(ur_template_t *tmplt, const void *data, tor_list_t *tor_list)
{
   // IPv6 is not supported at the moment
   if (ip_is6(ur_get_ptr(tmplt, data, UR_SRC_IP))) {
      return 0;
   }

   uint8_t flag = 0;

   if (ip_binary_search(ur_get_ptr(tmplt, data, UR_SRC_IP), tor_list)) {
      flag |= UR_TF_SRC;
   }

   if (ip_binary_search(ur_get_ptr(tmplt, data, UR_DST_IP), tor_list)) {
      flag |= UR_TF_DST;
   }

   return flag;
}


int get_dyn_count(ur_template_t *tmplt)
{
   int dyn_count = 0;
   ur_field_id_t id;
   ur_iter_t iter = UR_ITER_BEGIN;
   while ((id = ur_iter_fields_tmplt(tmplt, &iter)) != UR_INVALID_FIELD) {
      if (ur_is_dynamic(id)) {
         dyn_count++;
      }
   }

   return dyn_count;
}


/*
 * MAIN FUNCTION
 */
int main(int argc, char **argv)
{
   int ret;
   tor_list_t *tor_list = NULL;
   
   // ***** Initialize Blacklist Downloader *****
   pid_t c_id = bl_down_init(&BLACKLIST_URL, &UPDATE_FILE_NAME, 1, UPDATE_DELAY_TIME);

   // ***** TRAP initialization *****
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info); 
   signal(SIGTERM, signal_handler);
   signal(SIGINT,  signal_handler);
   signal(SIGUSR1, signal_handler);


   if (c_id < 0) { // Downloader initialization failed
      printf("Error: Could not fork process!\n");
      trap_finalize();
      return 1;
   }


   // ***** Initialize TOR IP list structure
   tor_list = init_tor_list();
   if (tor_list == NULL) {
      // TOR IP list initialization failed
      trap_finalize();
      kill(c_id, SIGINT);
      return 2;
   }
   
   // Wait for initial update
   while (!update) {
      sleep(1);
   }
   update_tor_list(tor_list);
   update = 0;

   // ***** Create UniRec template *****
   char *unirec_specifier_in = "<COLLECTOR_FLOW>";
   char opt;
   while ((opt = getopt(argc, argv, "u:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier_in = optarg;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 3;
      }
   }
   // Create output UniRec template
   char *unirec_specifier_out = calloc(1, sizeof(char) * (strlen(unirec_specifier_in) + strlen(TOR_FLAGS_FIELD_STRING) + 1));
   if (unirec_specifier_out == NULL) {
      fprintf(stderr, "Error: Could not allocate memory for UniRec output template!\n");
      trap_finalize();
      return 5;
   }
   strcpy(unirec_specifier_out, unirec_specifier_in);
   strcat(unirec_specifier_out, TOR_FLAGS_FIELD_STRING);

   
   ur_template_t *tmplt     = ur_create_template(unirec_specifier_in);
   ur_template_t *tmplt_out = ur_create_template(unirec_specifier_out);
   if (tmplt == NULL || tmplt_out == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      free(unirec_specifier_out);
      trap_finalize();
      return 4;
   }
   free(unirec_specifier_out); // we dont need it anymore


   // Create output data buffer
   void *data_out = ur_create(tmplt_out, MAX_DYN_SIZE * get_dyn_count(tmplt_out));

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from any interface, wait until data are available
      uint8_t tor_flag;
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (data_size < ur_rec_static_size(tmplt)) {
         if (data_size <= 1) {
            break; // End of data (used for testing purposes)
         }
         fprintf(stderr, "Error: data with wrong size received (expected size: %i, received size: %i)\n",
                 ur_rec_static_size(tmplt), data_size);
         break;
      }


      // ***** UPDATE IF NEW UPDATE IS READY *****
      if (update) {
         update_tor_list(tor_list);
         update = 0;
      }
      // ********** DETECT TOR IP ADDRESSES ********
      unirec_copy(tmplt_out, data_out, tmplt, data);
      tor_flag = check_ips(tmplt, data, tor_list);
      ur_set(tmplt_out, data_out, UR_TOR_FLAGS, tor_flag);

      /* DEBUG
      if (!tor_flag) continue;
      */

      trap_send_data(0, data_out, ur_rec_size(tmplt_out, data_out), TRAP_NO_WAIT);
      // ******************************************
      
 
   }

   printf("TOR Detector exiting...\n");

   // Send 1 Byte sized data to output interface to signalize end
   char dummy[1] = {0};
   trap_send_data(0, dummy, 1, TRAP_NO_WAIT);



   // ***** Cleanup *****   
   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();
 

   ur_free_template(tmplt);

   return 0;
}
