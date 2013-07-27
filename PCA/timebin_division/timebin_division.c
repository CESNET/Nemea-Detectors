/**
 * \file timebin_division.c
 * \brief Example module for dividing incoming flows into timebins.
 * \author Pavel Krobot <xkrobo01@stud.fit.vutbr.cz>
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
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <libtrap/trap.h>
#include "../../../unirec/unirec.h"

#define NEW_WAY

#define TIMESTAMP_BUFFER_SIZE 1000000
#define TIMEBIN_SIZE 60 //in seconds

#define WRITE_TO_FILE
#define STATUS_MSG

// Struct with information about module
trap_module_info_t module_info = {
   // Module name
   "Timebin division example module.\n",
   // Module description
   " Example module for dividing incoming flows into timebins.\n"
   ""
   "Interfaces:\n"
   "  Inputs (1):\n"
   "    >> 1. UniRec (SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,"
                     "TIME_LAST,PACKETS,BYTES,TCP_FLAGS)\n"
   "        - flows from network traffic.\n\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};

typedef struct timebin_buffer_s{
   uint32_t item_counter;
   uint32_t *buff;
}timebin_buffer_t;

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

uint8_t process_and_clear_buffer(timebin_buffer_t *buffer, uint32_t time){
   #ifdef WRITE_TO_FILE
   char filename [20];

   #ifdef NEW_WAY
   sprintf(filename, "tb-new.%u", time);
   #else
   sprintf(filename, "tb-old.%u", time);
   #endif

   FILE *out;
   out = fopen(filename, "w");
   if (out == NULL){
      return 0;
   }
   #ifdef STATUS_MSG
   printf("Writing %u.timebin to file: %s\n", time, filename);
   #endif
   #endif//WRITE_TO_FILE
   for (uint32_t i; i < buffer->item_counter; i++){
      #ifdef WRITE_TO_FILE
      fprintf(out, "%u\n",buffer->buff[i]);
      #endif
      buffer->buff[0];
   }
   #ifdef WRITE_TO_FILE
   fclose(out);
   #endif

   buffer->item_counter = 0;

   return 1;
}

uint8_t init_buffer(timebin_buffer_t *buffer){
   if ((buffer->buff = (uint32_t *)malloc(sizeof(uint32_t) * TIMESTAMP_BUFFER_SIZE)) == NULL) {
      return 0;
   }

   memset(buffer->buff, 0, sizeof(buffer->buff[0]) * TIMESTAMP_BUFFER_SIZE);
   buffer->item_counter = 0;

   return 1;
}

void destroy_buffer(timebin_buffer_t *buffer){
   free(buffer->buff);
}

int main(int argc, char **argv)
{
   int ret;
   trap_ifc_spec_t ifc_spec;

   uint8_t timebin_init_flag = 1;

   uint32_t start_of_actual_flow;
   uint32_t start_of_next_timebin;

   uint32_t timebin_counter;// counted from 1 (even if it is initialized to 0) !

   #ifdef NEW_WAY
   uint16_t flip_index;
   uint16_t index_addition;// accesing into actual timebin buffer
   uint16_t inverse_index_addition;// accesing into previous timebin buffer

   timebin_buffer_t timestamp_buffer[2];

   // ***** Init buffers *****
   if (!init_buffer(&timestamp_buffer[0])){
      return EXIT_FAILURE;
   }
   if (!init_buffer(&timestamp_buffer[1])){
      return EXIT_FAILURE;
   }
   // ***** END OF Init buffers *****
   #else
   timebin_buffer_t timestamp_buffer;
   if (!init_buffer(&timestamp_buffer)){
      return EXIT_FAILURE;
   }
   #endif
   // ***** TRAP initialization *****
   // Let TRAP library parse command-line arguments and extract its parameters
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   // ***** END OF TRAP initialization *****

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();


   // ***** Create UniRec templates & allocate memory for output records *****
   ur_template_t *in_tmplt = ur_create_template("<BASIC_FLOW>");
   // ***** END OF Create UniRec templates & allocate memory for output records *****

   // ***** Main processing loop *****
   while (!stop) {
      // *** Get input data ***
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_get_data(TRAP_MASK_ALL, &in_rec, &in_rec_size, TRAP_WAIT);
      // Handle possible errors
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_static_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected"
                    " size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(in_tmplt), in_rec_size);
            break;
         }
      }
      // *** END OF Get input data ***

      // *** Process the data ***

      // * Timebin division (sampling) based on TIMEBIN_SIZE *
      start_of_actual_flow = (ur_get(in_tmplt, in_rec, UR_TIME_FIRST)) >> 32;

      if (timebin_init_flag){ // initialization of counters with first flow
         timebin_init_flag = 0;

         start_of_next_timebin = start_of_actual_flow + TIMEBIN_SIZE;
         timebin_counter = 0;

         #ifdef NEW_WAY
         //first timebin must be actual & previous at the same time
         index_addition = 0;
         inverse_index_addition = 0;
         flip_index = 0;
         #endif
      }

      if (start_of_actual_flow > start_of_next_timebin){
         #ifdef NEW_WAY
         if (index_addition != inverse_index_addition){
            process_and_clear_buffer(&timestamp_buffer[inverse_index_addition], start_of_next_timebin - (TIMEBIN_SIZE * 2));
         }
         #else
         process_and_clear_buffer(&timestamp_buffer, start_of_next_timebin - TIMEBIN_SIZE);
         #endif
         ++timebin_counter;

         #ifdef NEW_WAY
         inverse_index_addition = index_addition;
         index_addition = (index_addition + 1) & 0x0001;

         flip_index = index_addition;
         #endif

         start_of_next_timebin += TIMEBIN_SIZE;
      #ifdef NEW_WAY
      } else if (start_of_actual_flow <= (start_of_next_timebin - TIMEBIN_SIZE)){
         //actual flow belongs to previous timebin (... - (start_of_next_timebin - TIMEBIN_SIZE) >
         flip_index = inverse_index_addition;
      } else {
         //actual flow belongs to actual timebin ((start_of_next_timebin - TIMEBIN_SIZE) - start_of_next_timebin>
         flip_index = index_addition;
      }
      timestamp_buffer[flip_index].buff[timestamp_buffer[flip_index].item_counter] = start_of_actual_flow;
      timestamp_buffer[flip_index].item_counter++;
      #else
      }
      timestamp_buffer.buff[timestamp_buffer.item_counter]=start_of_actual_flow;
      timestamp_buffer.item_counter++;
      #endif


   }
   // ***** END OF Main processing loop *****
   #ifdef NEW_WAY
   process_and_clear_buffer(&timestamp_buffer[inverse_index_addition], start_of_next_timebin - (TIMEBIN_SIZE * 2));
   #endif
   // ***** Cleanup *****

   #ifdef NEW_WAY
   destroy_buffer(&timestamp_buffer[0]);
   destroy_buffer(&timestamp_buffer[1]);
   #else
   destroy_buffer(&timestamp_buffer);
   #endif
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_tmplt);
   // ***** END OF Cleanup *****

   return 0;
}
// END OF timebin_division.c
