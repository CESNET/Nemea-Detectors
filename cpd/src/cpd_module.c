/**
 * \file cpd_module.h
 * \brief NEMEA module implementing anomaly detection based on CPD methods
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
#include <time.h>
#include <libtrap/trap.h>
#include "../../../unirec/unirec.h"
#include "cpd.h"
#include "cpd_common.h"

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "CPD module", // Module name
   // Module description
   "NEMEA module for anomalies detection based on CPD methods.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "   -p N        Show progess - print a dot every N flows.\n"
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

#define FLOWS_TIMEOUT 1

static int stop = 0;
static int progress = 0;

#define STOPCMD do {stop = 1;} while (0);

TRAP_DEFAULT_SIGNAL_HANDLER(STOPCMD);

int main(int argc, char **argv)
{
   int ret;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   struct cpd_method *cpd_methods_flows = NULL;
   struct cpd_method *cpd_methods_packets = NULL;
   struct cpd_method *cpd_methods_bytes = NULL;
   sd_meanvar_data_t sdmv_flows;
   sd_meanvar_data_t sdmv_packets;
   sd_meanvar_data_t sdmv_bytes;

   double thresholds_flows[3] = {
      10000, 1000, 10000
   };
   double thresholds_packets[3] = {
      10000, 1000, 10000
   };
   double thresholds_bytes[3] = {
      10000, 10000, 10000
   };
   UR_PACKETS_T packets_no = 0;
   UR_BYTES_T bytes_no = 0;
   uint64_t flows_no = 0;
   time_t checkpoint_time;
   FILE *history;

   // ***** TRAP initialization *****

   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec template *****

   char *unirec_specifier = "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS";
   char opt;
	uint32_t *ents =NULL;
   while ((opt = getopt(argc, argv, "u:p:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'p':
            progress = atoi(optarg);
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

   cpd_methods_flows = cpd_default_init_methods(thresholds_flows, 1000, 1500, 1, 16, 16);
   cpd_methods_bytes = cpd_default_init_methods(thresholds_bytes, 1000, 1500, 1, 16, 16);
   cpd_methods_packets = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   SD_MEANVAR_INIT(&sdmv_packets, 10);
   SD_MEANVAR_INIT(&sdmv_bytes, 10);
   SD_MEANVAR_INIT(&sdmv_flows, 10);

   // ***** Main processing loop *****
   checkpoint_time = time(NULL);

   history = fopen("history.log", "w");
   fprintf(history, "checkpoint_time, packets_no, sdmv_packets.mean, sdmv_packets.var, bytes_no, sdmv_bytes.mean, sdmv_bytes.var, flows_no, sdmv_flows.mean, sdmv_flows.var, entropy");
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (data_size < ur_rec_static_size(tmplt)) {
         if (data_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(tmplt), data_size);
            break;
         }
      }

      // Update counters
      packets_no = ur_get(tmplt, data, UR_PACKETS);
      bytes_no = ur_get(tmplt, data, UR_BYTES);
      cpd_run_methods(packets_no, cpd_methods_packets, CPD_METHODS_COUNT_DEFAULT);
      cpd_run_methods(bytes_no, cpd_methods_bytes, CPD_METHODS_COUNT_DEFAULT);

      SD_MEANVAR_ADD(&sdmv_packets, packets_no);
      SD_MEANVAR_ADD(&sdmv_bytes, bytes_no);

      /* compute entropy of whole incoming message */
      ent_reset(&ents);
      ent_put_data(ents, (char *) data, data_size);

      flows_no += 1;
      if ((time(NULL) - checkpoint_time) >= FLOWS_TIMEOUT) {
         cpd_run_methods(flows_no, cpd_methods_flows, CPD_METHODS_COUNT_DEFAULT);
         SD_MEANVAR_ADD(&sdmv_flows, flows_no);
         checkpoint_time = time(NULL);
         fprintf(history, "%lu\t%u\t%f\t%f\t%llu\t%f\t%f\t%llu\t%f\t%f\t%f\n",
               checkpoint_time, packets_no, sdmv_packets.mean, sdmv_packets.var,
               (long long unsigned int) bytes_no, sdmv_bytes.mean, sdmv_bytes.var, (long long unsigned int) flows_no,
               sdmv_flows.mean, sdmv_flows.var, ent_get_entropy(ents));
         fflush(history);
         flows_no = 0;
      }
   }
   fclose(history);
   ent_free(&ents);

   SD_MEANVAR_FREE(&sdmv_flows);
   SD_MEANVAR_FREE(&sdmv_packets);
   SD_MEANVAR_FREE(&sdmv_bytes);

   // ***** Print results *****

   printf("Flows:   %20lu\n", cnt_flows);
   printf("Packets: %20lu\n", cnt_packets);
   printf("Bytes:   %20lu\n", cnt_bytes);

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(tmplt);

   return 0;
}
