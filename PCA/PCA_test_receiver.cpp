/**
 * \file PCA_test_receiver.cpp
 * \brief Test receiver for PCA_sketch module.
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
#include <signal.h>
#include <iostream>
#include <fstream>
#include <sstream>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"
#include "PCA_sketch.h"

using namespace std;

// Struct with information about module
trap_module_info_t module_info = {
   (char *) "Test receiver for PCA-sketch module", // Module name
   // Module description
   (char *) "Testing module for PCA_sketch module. This module receiving messages from "
   "PCA_sketch_detector.\n"
   "Interfaces:\n"
   "   Inputs: 1 (UniRec: TIME_FIRST, TIME_LAST)\n",
   1, // Number of input interfaces
};


static int stop = 0;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

int main(int argc, char **argv)
{
   int ret;
   trap_ifc_spec_t ifc_spec;
   uint32_t first, last, timebin_counter = 0;
   ofstream log;//new-testing

   // ***** TRAP initialization *****

   // Let TRAP library parse command-line arguments and extract its parameters
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   char *in_unirec_specifier = (char *) "TIME_FIRST,TIME_LAST";
   char opt;
   #ifndef OFFLINE_MODE
   while ((opt = getopt(argc, argv, "u:")) != -1) {
      switch (opt) {
         case 'u':
            in_unirec_specifier = optarg;
            break;
         default:
            cerr << "Invalid arguments.\n";
            return 2;
      }
   }
   #endif
   if (optind > argc) {
//   if (optind >= argc) {
      cerr << "Wrong number of parameters.\n Usage: " << argv[0] << " -i trap-ifc-specifier";
      #ifndef OFFLINE_MODE
      cerr << " [-u \"UNIREC,FIELDS\"]";
      #endif
      return 2;
   }

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec templates *****
   ur_template_t *in_tmplt = ur_create_template(in_unirec_specifier);

   // ***** Main processing loop *****
   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_get_data(TRAP_MASK_ALL, &in_rec, &in_rec_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_static_size(in_tmplt)) {
         if (in_rec_size <= 1) {
//            break; // End of data (used for testing purposes)
            continue;
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA

      first = ur_get(in_tmplt, in_rec, UR_TIME_FIRST)>>32;
      last = ur_get(in_tmplt, in_rec, UR_TIME_LAST)>>32;
      log.open("PCA-test-receiver-log.txt", ios::in | ios::app);

      if (first){
         log << timebin_counter << ".TB: " << "an ANOMALY in time "
                      << first << " - " << last << " !!! " << endl;
      } else {
      log << timebin_counter << ".TB: " << "NO anomaly in TB " << last << endl;
      }

      log.close();

      ++timebin_counter;
   }

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   trap_finalize();
   ur_free_template(in_tmplt);

   return 0;
}

