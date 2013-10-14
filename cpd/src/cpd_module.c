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
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

#define FLOWS_TIMEOUT 1

static int stop = 0;

#define STOPCMD do {stop = 1;} while (0);

TRAP_DEFAULT_SIGNAL_HANDLER(STOPCMD);

int main(int argc, char **argv)
{
   int ret;
   struct cpd_method *cpd_methods_flows = NULL;
   struct cpd_method *cpd_methods_packets = NULL;
   struct cpd_method *cpd_methods_bytes = NULL;

   struct cpd_method *cpd_methods_entsip       = NULL;
   struct cpd_method *cpd_methods_entdip       = NULL;
   struct cpd_method *cpd_methods_entspr       = NULL;
   struct cpd_method *cpd_methods_entdpr       = NULL;
   struct cpd_method *cpd_methods_entsipdip    = NULL;
   struct cpd_method *cpd_methods_entsipspr    = NULL;
   struct cpd_method *cpd_methods_entsipdpr    = NULL;
   struct cpd_method *cpd_methods_entdipspr    = NULL;
   struct cpd_method *cpd_methods_entdipdpr    = NULL;
   struct cpd_method *cpd_methods_entsipdipspr = NULL;
   struct cpd_method *cpd_methods_entsipdipdpr = NULL;

   double thresholds_flows[] = {
      10000, 1000, 10000, 10000
   };
   double thresholds_packets[] = {
      10000, 1000, 10000, 10000
   };
   double thresholds_bytes[] = {
      10000, 10000, 10000, 10000
   };

   // ***** TRAP initialization *****

   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec template *****

   char *unirec_specifier = "TIMESLOT,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT,ENTROPY_SRCIPDSTIP,ENTROPY_SRCIPSRCPORT,ENTROPY_SRCIPDSTPORT,ENTROPY_DSTIPSRCPORT,ENTROPY_DSTIPDSTPORT,ENTROPY_SRCIPDSTIPDSTPORT,ENTROPY_SRCIPDSTIPSRCPORT";
   char opt;
   while ((opt = getopt(argc, argv, "u:p:")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
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

   /*                                                                 npcusum u,   o,  e | ewma */
   cpd_methods_flows        = cpd_default_init_methods(thresholds_flows,   1000, 1500, 1, 16, 16);
   cpd_methods_bytes        = cpd_default_init_methods(thresholds_bytes,   1000, 1500, 1, 16, 16);
   cpd_methods_packets      = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entsip       = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entdip       = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entspr       = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entdpr       = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entsipdip    = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entsipspr    = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entsipdpr    = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entdipspr    = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entdipdpr    = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entsipdipspr = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);
   cpd_methods_entsipdipdpr = cpd_default_init_methods(thresholds_packets, 1000, 1500, 1, 16, 16);

   // ***** Main processing loop *****

   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_HALFWAIT);
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

      #define X(URF, CPDM) do { \
         printf("----------%s---------- New value: %f\n", #URF, (double) *((URF ## _T*)(ur_get_ptr_by_id(tmplt, data, URF)))); \
         cpd_run_methods(*((URF ## _T*)(ur_get_ptr_by_id(tmplt, data, URF))), CPDM, CPD_METHODS_COUNT_DEFAULT); \
      } while(0);

      X(UR_PACKETS                  , cpd_methods_packets     );
      X(UR_BYTES                    , cpd_methods_bytes       );
      X(UR_ENTROPY_SRCIP            , cpd_methods_entsip      );
      X(UR_ENTROPY_DSTIP            , cpd_methods_entdip      );
      X(UR_ENTROPY_SRCPORT          , cpd_methods_entspr      );
      X(UR_ENTROPY_DSTPORT          , cpd_methods_entdpr      );
      X(UR_ENTROPY_SRCIPDSTIP       , cpd_methods_entsipdip   );
      X(UR_ENTROPY_SRCIPSRCPORT     , cpd_methods_entsipspr   );
      X(UR_ENTROPY_SRCIPDSTPORT     , cpd_methods_entsipdpr   );
      X(UR_ENTROPY_DSTIPSRCPORT     , cpd_methods_entdipspr   );
      X(UR_ENTROPY_DSTIPDSTPORT     , cpd_methods_entdipdpr   );
      X(UR_ENTROPY_SRCIPDSTIPSRCPORT, cpd_methods_entsipdipspr);
      X(UR_ENTROPY_SRCIPDSTIPDSTPORT, cpd_methods_entsipdipdpr);

      #undef X
   }

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(tmplt);

   return 0;
}
