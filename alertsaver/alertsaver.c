/**
 * \file alertsaver.c
 * \brief Save incomming alerts into flat file.
 * \author Tomas Cejka <cejkat@cesnet.cz>
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

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

#define MAXERRORS 10
/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Alertsaver module", // Module name
   // Module description
   "Module that accepts messages and store them into log.\n"
   "Parameters:\n"
   "   -f <output file>\n"
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;
static int progress = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   }
}

/* libtrap hack - private method call */
void trap_get_internal_buffer(uint16_t ifc_idx, const void **data, uint32_t *data_size);

int main(int argc, char **argv)
{
   int ret;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   uint64_t error_cntr = 0;
   FILE *fout = NULL;
   char *output_file = NULL;
   
   // ***** TRAP initialization *****
   trap_ifc_spec_t ifc_spec;
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);

   char opt;
   while ((opt = getopt(argc, argv, "f:i:h")) != -1) {
      switch (opt) {
      case 'f':
         output_file = optarg;
         break;
      case 'h':
         fprintf(stderr, "%s -f <output file> -i <libtrap ifc specs>\n",
            argv[0]);
         break;
      }
   }
   if (output_file == NULL) {
      fprintf(stderr, "Output file path was not given.\n");
      exit(1);
   }
   // Let TRAP library parse command-line arguments and extract its parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      return 2;
   }
   trap_free_ifc_spec(ifc_spec);
   
   
   fout = fopen(output_file, "w");
   if (fout == NULL) {
      fprintf(stderr, "Output file could not be opened.\n");
      exit(1);
   }
   
   // ***** Main processing loop *****
   
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint32_t data_size;
      /* read from the only one interface - load to buffer */
      ret = trap_get_data(0x01, &data, (uint16_t *) &data_size, TRAP_WAIT);
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TERMINATED) {
            // Module was terminated (e.g. by Ctrl-C)
            break;
         } else {
            // Some error ocurred
            if (++error_cntr >= MAXERRORS) {
               fprintf(stderr, "Error: %s (%i)\n", ret, trap_last_error_msg);
               break;
            }
            continue;
         }
      }
      /* do not call this function unless You really know, what's going on... */
      trap_get_internal_buffer(0x00, &data, &data_size);
      
      // Check size of received data
      if (data_size <= 1) {
         fflush(fout);
         continue; // End of data (used for testing purposes)
      }
      if (fwrite(data, data_size, 1, fout) != 1) {
         fprintf(stderr, "Error: writing into output file failed.\n");
         break;
      }
   }
   
   fclose(fout); 
   // ***** Cleanup *****
   
   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();
   
   
   return 0;
}

