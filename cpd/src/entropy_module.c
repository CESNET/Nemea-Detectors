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
#ifdef HAVE_OMP_H
#include <omp.h>
#endif

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Entropy module", // Module name
   // Module description
   "NEMEA module for anomalies detection based on CPD methods.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "   -p N        Show progess - print a dot every N flows.\n"
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 1\n",
   1, // Number of input interfaces
   1, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;
static int stats = 0;
static int progress = 0;
#ifdef DEBUG
extern uint64_t ent_cache_miss;
extern uint64_t ent_cache_hit;
#endif


#define STOPCMD do {stop = 1;} while (0);

TRAP_DEFAULT_SIGNAL_HANDLER(STOPCMD);

enum entindex {
   SRCIP = 0,
   DSTIP = 1,
   SRCPORT = 2,
   DSTPORT = 3,
   SRCIPDSTIP = 4,
   SRCIPSRCPORT = 5,
   SRCIPDSTPORT = 6,
   DSTIPSRCPORT = 7,
   DSTIPDSTPORT = 8,
   SRCIPDSTIPDSTPORT = 9,
   SRCIPDSTIPSRCPORT = 10
};

#define MEMBERCOUNT(array) (sizeof(array)/sizeof(*(array)))

int main(int argc, char **argv)
{
   int ret;
   uint32_t i = 0, i2 = 0;
   uint32_t datasize = 0;
   uint32_t *entropies[] = {
      NULL, //srcIP
      NULL, //dstIP
      NULL, //srcPort
      NULL, //dstPort
      NULL, //srcIP+dstIP
      NULL, //srcIP+srcPort
      NULL, //srcIP+dstPort
      NULL, //dstIP+srcPort
      NULL, //dstIP+dstPort
      NULL, //srcIP+dstIP+dstPort
      NULL  //srcIP+dstIP+srcPort
   };
   #define ENTROPIES_COUNT MEMBERCOUNT(entropies)
   #define TIMEWINDOW   (5*60)
   double entropies_results[ENTROPIES_COUNT];

   int entsdstip[] = {
      SRCIPDSTIP,
      SRCIPDSTIPDSTPORT,
      SRCIPDSTIPSRCPORT,
      DSTIP,
      DSTIPSRCPORT,
   };
   int entsdstport[] = {
      DSTPORT,
      SRCIPDSTPORT,
      SRCIPDSTIPDSTPORT,
   };
   int entssrcport[] = {
      SRCPORT,
      SRCIPDSTIPSRCPORT,
      SRCIPSRCPORT,
   };
   int entssrcip[] = {
      SRCIP,
      SRCIPDSTIP,
      SRCIPSRCPORT,
      SRCIPDSTPORT,
      SRCIPDSTIPDSTPORT,
      SRCIPDSTIPSRCPORT,
   };
   int *entslists[] = {
      entsdstip,
      entsdstport,
      entssrcport,
      entssrcip,
   };
   int entslists_count[] = {
      MEMBERCOUNT(entsdstip),
      MEMBERCOUNT(entsdstport),
      MEMBERCOUNT(entssrcport),
      MEMBERCOUNT(entssrcip)
   };
   int urfieldslist[] = {
      UR_DST_IP,
      UR_DST_PORT,
      UR_SRC_PORT,
      UR_SRC_IP
   };
   int *entpoint = NULL;
   int *entslistpoint = NULL;
   UR_TIME_FIRST_T cur_first_time = 0;
   UR_PACKETS_T packets_total = 0;
   UR_BYTES_T bytes_total = 0;
   uint64_t flows_total = 0;
   uint64_t last_send_time = 0;
   unsigned char *p;
   char long_output = 0;
   char *unirec_output_specifier;
   // ***** TRAP initialization *****

   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0);
   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_AUTOFLUSH_TIMEOUT, (-1l));

   // ***** Create UniRec template *****

   char *unirec_input_specifier = "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS";
   char opt;
   while ((opt = getopt(argc, argv, "u:p:l")) != -1) {
      switch (opt) {
      case 'u':
         unirec_input_specifier = optarg;
         break;
      case 'p':
         progress = atoi(optarg);
         break;
      case 'l':
         long_output = 1;
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         return 3;
      }
   }
   if (long_output == 0) {
      unirec_output_specifier = "TIME_FIRST,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT";
   } else {
      unirec_output_specifier = "TIME_FIRST,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT,ENTROPY_SRCIPDSTIP,ENTROPY_SRCIPSRCPORT,ENTROPY_SRCIPDSTPORT,ENTROPY_DSTIPSRCPORT,ENTROPY_DSTIPDSTPORT,ENTROPY_SRCIPDSTIPDSTPORT,ENTROPY_SRCIPDSTIPSRCPORT";
   }

   ur_template_t *tmpl = ur_create_template(unirec_input_specifier);
   if (tmpl == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return 4;
   }
   ur_template_t *tmplt_out = ur_create_template(unirec_output_specifier);
   void *data_out = ur_create(tmplt_out, 0);

   for (i=0; i<ENTROPIES_COUNT; ++i) {
      ent_reset(&entropies[i]);
   }

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (data_size < ur_rec_static_size(tmpl)) {
         if (data_size <= 1) {
            trap_send_data(0, data, 1, TRAP_NO_WAIT);
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(tmpl), data_size);
            break;
         }
      }
      bytes_total += ur_get(tmpl, data, UR_BYTES);
      flows_total += ur_get(tmpl, data, UR_FLOWS);
      packets_total += ur_get(tmpl, data, UR_PACKETS);
      cur_first_time = ur_get(tmpl, data, UR_TIME_FIRST);

      /* set last_send time during first iteration */
      if (last_send_time == 0) {
         last_send_time = ur_time_get_sec(cur_first_time);
      }

      /* compute entropy of whole incoming message */
      /* Source IP */
      /* iterate over entropies we want to compute */
      for (i=0; i<MEMBERCOUNT(entslists); ++i) {
         switch (urfieldslist[i]) {
         case UR_SRC_IP:
            p = (unsigned char *) ur_get_ptr(tmpl, data, UR_SRC_IP);
            datasize = ur_get_size(UR_SRC_IP);
            break;
         case UR_SRC_PORT:
            p = (unsigned char *) ur_get_ptr(tmpl, data, UR_SRC_PORT);
            datasize = ur_get_size(UR_SRC_PORT);
            break;
         case UR_DST_PORT:
            p = (unsigned char *) ur_get_ptr(tmpl, data, UR_DST_PORT);
            datasize = ur_get_size(UR_DST_PORT);
            break;
         case UR_DST_IP:
            p = (unsigned char *) ur_get_ptr(tmpl, data, UR_DST_IP);
            datasize = ur_get_size(UR_DST_IP);
         break;
      default:
         fprintf(stderr, "ERROR: unexpected unirec field!!!\n");
         goto failed;
      }
      /* iterate over data fields that are needed for entropy */
      entpoint = entslists[i];
      for (i2=0; i2<entslists_count[i]; ++i2) {
         ent_put_data(entropies[entpoint[i2]], p, datasize); /* complete */
         }
      }
      /* All data processed, tables updated */
      if ((ur_time_get_sec(cur_first_time) - last_send_time) >= TIMEWINDOW) {
         /* compute entropies */

#ifdef HAVE_LIBGOMP
#pragma omp parallel for
#endif
         for (i=0; i<ENTROPIES_COUNT; ++i) {
               entropies_results[i] = ent_get_entropy(entropies[i]);
         }

         /* send output message with entropies */
         ur_set(tmplt_out, data_out, UR_TIME_FIRST,      cur_first_time);
         ur_set(tmplt_out, data_out, UR_LINK_BIT_FIELD,   0);
         ur_set(tmplt_out, data_out, UR_FLOWS,            flows_total);
         ur_set(tmplt_out, data_out, UR_PACKETS,         packets_total);
         ur_set(tmplt_out, data_out, UR_BYTES,            bytes_total);
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIP,   entropies_results[SRCIP]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_DSTIP,   entropies_results[DSTIP]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCPORT,   entropies_results[SRCPORT]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_DSTPORT,   entropies_results[SRCPORT]);
         if (long_output != 0) {
            ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTIP,   entropies_results[SRCIPDSTIP]);
            ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPSRCPORT,   entropies_results[SRCIPSRCPORT]);
            ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTPORT,   entropies_results[SRCIPDSTPORT]);
            ur_set(tmplt_out, data_out, UR_ENTROPY_DSTIPSRCPORT,   entropies_results[DSTIPSRCPORT]);
            ur_set(tmplt_out, data_out, UR_ENTROPY_DSTIPDSTPORT,   entropies_results[DSTIPDSTPORT]);
            ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTIPDSTPORT,   entropies_results[SRCIPDSTIPDSTPORT]);
            ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTIPSRCPORT,   entropies_results[SRCIPDSTIPSRCPORT]);
         }

         flows_total = 0;
         packets_total = 0;
         bytes_total = 0;
         last_send_time = ur_time_get_sec(cur_first_time);
         trap_send_data(0, data_out, ur_rec_static_size(tmplt_out), TRAP_WAIT);
      }
   }
failed:
   for (i=0; i<ENTROPIES_COUNT; ++i) {
      ent_free(&entropies[i]);
   }
   #ifdef DEBUG
   printf("ent_cache_miss: %llu\nent_cache_hit: %llu\n", ent_cache_miss, ent_cache_hit);
   #endif

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(tmpl);
   ur_free_template(tmplt_out);

   return 0;
}
