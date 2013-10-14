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
static int progress = 0;
#ifdef DEBUG
extern uint64_t ent_cache_miss;
extern uint64_t ent_cache_hit;
uint64_t gflow_total = 0;
uint64_t gpkts_total = 0;
uint64_t gbyte_total = 0;
#endif
#define BREAK_ON_FIRST_LINK

#define MEMBERCOUNT(array) (sizeof(array)/sizeof(*(array)))

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
const int entsdstip[] = {
   SRCIPDSTIP,
   SRCIPDSTIPDSTPORT,
   SRCIPDSTIPSRCPORT,
   DSTIP,
   DSTIPSRCPORT,
};
const int entsdstport[] = {
   DSTPORT,
   SRCIPDSTPORT,
   SRCIPDSTIPDSTPORT,
};
const int entssrcport[] = {
   SRCPORT,
   SRCIPDSTIPSRCPORT,
   SRCIPSRCPORT,
};
const int entssrcip[] = {
   SRCIP,
   SRCIPDSTIP,
   SRCIPSRCPORT,
   SRCIPDSTPORT,
   SRCIPDSTIPDSTPORT,
   SRCIPDSTIPSRCPORT,
};
const int *entslists[] = {
   entsdstip,
   entsdstport,
   entssrcport,
   entssrcip,
};
const int entslists_count[] = {
   MEMBERCOUNT(entsdstip),
   MEMBERCOUNT(entsdstport),
   MEMBERCOUNT(entssrcport),
   MEMBERCOUNT(entssrcip)
};
const int urfieldslist[] = {
   UR_DST_IP,
   UR_DST_PORT,
   UR_SRC_PORT,
   UR_SRC_IP
};

size_t ent_data_sizes[] = {
   sizeof(UR_SRC_IP_T), //srcIP
   sizeof(UR_DST_IP_T), //dstIP
   sizeof(UR_SRC_PORT_T), //srcPort
   sizeof(UR_DST_PORT_T), //dstPort
   sizeof(UR_SRC_IP_T) + sizeof(UR_DST_IP_T), //srcIP+dstIP
   sizeof(UR_SRC_IP_T) + sizeof(UR_SRC_PORT_T), //srcIP+srcPort
   sizeof(UR_SRC_IP_T) + sizeof(UR_DST_PORT_T), //srcIP+dstPort
   sizeof(UR_DST_IP_T) + sizeof(UR_SRC_PORT_T), //dstIP+srcPort
   sizeof(UR_DST_IP_T) + sizeof(UR_DST_PORT_T), //dstIP+dstPort
   sizeof(UR_SRC_IP_T) + sizeof(UR_DST_IP_T) + sizeof(UR_DST_PORT_T), //srcIP+dstIP+dstPort
   sizeof(UR_SRC_IP_T) + sizeof(UR_DST_IP_T) + sizeof(UR_SRC_PORT_T)  //srcIP+dstIP+srcPort
};

#define ENTROPIES_COUNT MEMBERCOUNT(ent_data_sizes)
#define BREAK_ON_FIRST_LINK

struct link_entdata {
   uint32_t linkid;
   UR_PACKETS_T packets_total;
   UR_BYTES_T bytes_total;
   uint64_t flows_total;
   char *ent_data;
#ifdef BYTEENTROPY
   uint32_t *entropies[ENTROPIES_COUNT];
#else
   ent_shash_t *hash_entropies[ENTROPIES_COUNT];
#endif
   double entropies_results[ENTROPIES_COUNT];
};

static void send_results(struct link_entdata *sdata, uint32_t linkcount,
   ur_template_t *tmplt_out, void *data_out, UR_TIMESLOT_T *cur_timeslot,
   uint32_t timewindow, char long_output)
{
   uint32_t i;
   /* compute entropies */
#ifdef HAVE_LIBGOMP
#pragma omp parallel for
#endif
   for (i=0; i<(ENTROPIES_COUNT*linkcount); ++i) {
#ifdef BYTEENTROPY
      sdata[i/ENTROPIES_COUNT].entropies_results[i%ENTROPIES_COUNT] = ent_get_entropy(sdata[i/ENTROPIES_COUNT].entropies[i%ENTROPIES_COUNT]);
#else
      sdata[i/ENTROPIES_COUNT].entropies_results[i%ENTROPIES_COUNT] = ent_shash_get_entropy(sdata[i/ENTROPIES_COUNT].hash_entropies[i%ENTROPIES_COUNT]);
#endif
   }

   /* send output message with entropies */
   for (i=0; i<linkcount; ++i) {
      ur_set(tmplt_out, data_out, UR_TIMESLOT,      *cur_timeslot);
      ur_set(tmplt_out, data_out, UR_LINK_BIT_FIELD,  sdata[i].linkid);
      ur_set(tmplt_out, data_out, UR_FLOWS,           sdata[i].flows_total);
      ur_set(tmplt_out, data_out, UR_PACKETS,         sdata[i].packets_total);
      ur_set(tmplt_out, data_out, UR_BYTES,           sdata[i].bytes_total);
      ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIP,   sdata[i].entropies_results[SRCIP]);
      ur_set(tmplt_out, data_out, UR_ENTROPY_DSTIP,   sdata[i].entropies_results[DSTIP]);
      ur_set(tmplt_out, data_out, UR_ENTROPY_SRCPORT, sdata[i].entropies_results[SRCPORT]);
      ur_set(tmplt_out, data_out, UR_ENTROPY_DSTPORT, sdata[i].entropies_results[SRCPORT]);
      if (long_output != 0) {
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTIP,   sdata[i].entropies_results[SRCIPDSTIP]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPSRCPORT,   sdata[i].entropies_results[SRCIPSRCPORT]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTPORT,   sdata[i].entropies_results[SRCIPDSTPORT]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_DSTIPSRCPORT,   sdata[i].entropies_results[DSTIPSRCPORT]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_DSTIPDSTPORT,   sdata[i].entropies_results[DSTIPDSTPORT]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTIPDSTPORT,   sdata[i].entropies_results[SRCIPDSTIPDSTPORT]);
         ur_set(tmplt_out, data_out, UR_ENTROPY_SRCIPDSTIPSRCPORT,   sdata[i].entropies_results[SRCIPDSTIPSRCPORT]);
      }
#ifdef DEBUG
      printf("link#%03X timesl:%u flows#%llu pkts#%llu bytes#%llu sip:%.5f dip:%.5f spr:%.5f dpr:%.5f\n", sdata[i].linkid, *cur_timeslot,
         (unsigned long long int) sdata[i].flows_total, (unsigned long long int) sdata[i].packets_total,
         (unsigned long long int) sdata[i].bytes_total, sdata[i].entropies_results[SRCIP], sdata[i].entropies_results[DSTIP],
			sdata[i].entropies_results[SRCPORT], sdata[i].entropies_results[DSTPORT]);
      gflow_total += sdata[i].flows_total;
      gpkts_total += sdata[i].packets_total;
      gbyte_total += sdata[i].bytes_total;
#endif

      sdata[i].flows_total = 0;
      sdata[i].packets_total = 0;
      sdata[i].bytes_total = 0;
      trap_send_data(0, data_out, ur_rec_static_size(tmplt_out), TRAP_HALFWAIT);
   }
   (*cur_timeslot) += timewindow;

#ifdef HAVE_LIBGOMP
#pragma omp parallel for
#endif
   for (i=0; i<(ENTROPIES_COUNT*linkcount); ++i) {
#ifdef BYTEENTROPY
      ent_reset(&sdata[i/ENTROPIES_COUNT].entropies[i%ENTROPIES_COUNT]);
#else
      ent_shash_reset(sdata[i/ENTROPIES_COUNT].hash_entropies[i%ENTROPIES_COUNT]);
#endif
   }
}

int main(int argc, char **argv)
{
   int ret;
   uint32_t i = 0;
   uint32_t datasize = 0;

   #define DEFAULTTIMEWINDOW   (5*60)
   #define TRAPTIMEOUT   1000000

   UR_TIME_FIRST_T cur_first_time = 0;
   UR_TIMESLOT_T cur_timeslot = 0;
   char *p;
   char long_output = 0;
   char *unirec_output_specifier;
   uint32_t link = 0, linkcount = 0;
   UR_LINK_BIT_FIELD_T linkbit = 1, linkbitp = 1;
   uint32_t timewindow = DEFAULTTIMEWINDOW;
#ifdef BYTEENTROPY
   uint32_t i2;
   const int *entpoint;
#else
   char *dp;
   uint32_t ent_data_total = 0;
   uint32_t prev_offset = 0;
#endif
   // ***** TRAP initialization *****

   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0);
   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_AUTOFLUSH_TIMEOUT, (-1l));

   // ***** Create UniRec template *****

   //char *unirec_input_specifier = "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS";
   char *unirec_input_specifier = "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD";
   char opt;
   while ((opt = getopt(argc, argv, "u:p:ln:t:")) != -1) {
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
      case 'n':
         if (sscanf(optarg, "%u", &linkcount) != 1) {
            fprintf(stderr, "Missing 'n' argument with number of links\n");
            goto failed_trap;
         }
         break;
      case 't':
         if (sscanf(optarg, "%u", &timewindow) != 1) {
            fprintf(stderr, "Missing 't' argument with timewindow size in seconds.\n");
            goto failed_trap;
            return 4;
         }
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         goto failed_trap;
         return 3;
      }
   }
   if (linkcount == 0) {
      fprintf(stderr, "Missing 'n' argument with number of links\n");
      goto failed_trap;
   }
   fprintf(stderr, "Using %us time window.\n", timewindow);
   fprintf(stderr, "Using %u links.\n", linkcount);

   if (long_output == 0) {
      unirec_output_specifier = "TIMESLOT,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT";
   } else {
      unirec_output_specifier = "TIMESLOT,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT,ENTROPY_SRCIPDSTIP,ENTROPY_SRCIPSRCPORT,ENTROPY_SRCIPDSTPORT,ENTROPY_DSTIPSRCPORT,ENTROPY_DSTIPDSTPORT,ENTROPY_SRCIPDSTIPDSTPORT,ENTROPY_SRCIPDSTIPSRCPORT";
   }

   struct link_entdata *sdata = calloc(linkcount, sizeof(struct link_entdata));

   ur_template_t *tmpl = ur_create_template(unirec_input_specifier);
   if (tmpl == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      goto failed_trap;
   }
   ur_template_t *tmplt_out = ur_create_template(unirec_output_specifier);
   void *data_out = ur_create(tmplt_out, 0);
   if (data_out == NULL) {
      fprintf(stderr, "Error: Invalid output UniRec specifier.\n");
      goto failed_trap;
   }

#ifdef BYTEENTROPY
   for (link=0; link<linkcount; ++link) {
      for (i=0; i<ENTROPIES_COUNT; ++i) {
         ent_reset(&sdata[link].entropies[i]);
      }
   }
#else
   for (i=0; i<MEMBERCOUNT(ent_data_sizes); ++i) {
      ent_data_total += ent_data_sizes[i];

      for (link=0; link<linkcount; ++link) {
         sdata[link].hash_entropies[i] = ent_shash_init(1000000, ent_data_sizes[i]);
         sdata[link].linkid = 1<<link;
      }
      if (i == 0) {
         prev_offset = ent_data_sizes[i];
         ent_data_sizes[i] = 0;
      } else {
         uint32_t cur_offset = ent_data_sizes[i];
         ent_data_sizes[i] = ent_data_sizes[i-1] + prev_offset;
         prev_offset = cur_offset;
      }
   }
   for (link=0; link<linkcount; ++link) {
      sdata[link].ent_data = (char *) calloc(1, ent_data_total);
   }
#endif

   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, timewindow*TRAPTIMEOUT);
      if (ret == TRAP_E_TIMEOUT) {
         fprintf(stderr, "Timeout -> forced send.\n");
         send_results(sdata, linkcount, tmplt_out, data_out, &cur_timeslot, timewindow, long_output);
         continue;
      } else if (ret != TRAP_E_OK) {
         goto loopend;
      }
      //TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (data_size < ur_rec_static_size(tmpl)) {
         if (data_size > 1) {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(tmpl), data_size);
         }
         goto loopend; // End of data (used for testing purposes)
      }

      cur_first_time = ur_time_get_sec(ur_get(tmpl, data, UR_TIME_FIRST));
      /* set last_send time during first iteration */
      if (cur_timeslot == 0) {
         cur_timeslot = cur_first_time;
      }

      /* send previous data if new unirec does not belong to the same timeslot */
      if ((cur_first_time >= cur_timeslot) && ((cur_first_time - cur_timeslot) >= timewindow)) {
         send_results(sdata, linkcount, tmplt_out, data_out, &cur_timeslot, timewindow, long_output);
      }

      linkbit = ur_get(tmpl, data, UR_LINK_BIT_FIELD);
      for (link=0, linkbitp=1; link<linkcount; linkbitp<<=1,++link) {
         if (((linkbitp & linkbit) == 0) && (linkbit != 0)) {
            /* skip because this link is not mentioned in link_bit_field */
            continue;
         }

         sdata[link].bytes_total += ur_get(tmpl, data, UR_BYTES);
         sdata[link].flows_total += 1;
         sdata[link].packets_total += ur_get(tmpl, data, UR_PACKETS);

         /* compute entropy of whole incoming message */
#ifdef BYTEENTROPY
         /* iterate over entropies we want to compute */
         for (i=0; i<MEMBERCOUNT(entslists); ++i) {
            switch (urfieldslist[i]) {
               case UR_SRC_IP:
                  p = (char *) ur_get_ptr(tmpl, data, UR_SRC_IP);
                  datasize = ur_get_size(UR_SRC_IP);
                  break;
               case UR_SRC_PORT:
                  p = (char *) ur_get_ptr(tmpl, data, UR_SRC_PORT);
                  datasize = ur_get_size(UR_SRC_PORT);
                  break;
               case UR_DST_PORT:
                  p = (char *) ur_get_ptr(tmpl, data, UR_DST_PORT);
                  datasize = ur_get_size(UR_DST_PORT);
                  break;
               case UR_DST_IP:
                  p = (char *) ur_get_ptr(tmpl, data, UR_DST_IP);
                  datasize = ur_get_size(UR_DST_IP);
                  break;
               default:
                  fprintf(stderr, "ERROR: unexpected unirec field!!!\n");
            }
            /* iterate over data fields that are needed for entropy */
            entpoint = entslists[i];
            for (i2=0; i2<entslists_count[i]; ++i2) {
               ent_put_data(sdata[link].entropies[entpoint[i2]], p, datasize); /* complete */
            }
         }
#else
         /* SRCIP */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIP]];
         p = (char *) ur_get_ptr(tmpl, data, UR_SRC_IP);
         datasize = ur_get_size(UR_SRC_IP);
         memcpy(dp, p, datasize); /* complete SRCIP */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIP]];
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPSRCPORT]];
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTPORT]];
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIPSRCPORT]];
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIPDSTPORT]];
         memcpy(dp, p, datasize);

         /* DSTIP */
         dp = &sdata[link].ent_data[ent_data_sizes[DSTIP]];
         p = (char *) ur_get_ptr(tmpl, data, UR_DST_IP);
         datasize = ur_get_size(UR_DST_IP);
         memcpy(dp, p, datasize); /* complete DSTIP */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIP]];
         dp += ur_get_size(UR_SRC_IP);
         memcpy(dp, p, datasize); /* complete SRCIPDSTIP */
         dp = &sdata[link].ent_data[ent_data_sizes[DSTIPSRCPORT]];
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[DSTIPDSTPORT]];
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIPSRCPORT]];
         dp += ur_get_size(UR_SRC_IP);
         memcpy(dp, p, datasize);
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIPDSTPORT]];
         dp += ur_get_size(UR_SRC_IP);
         memcpy(dp, p, datasize);

         /* SRCPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCPORT]];
         p = (char *) ur_get_ptr(tmpl, data, UR_SRC_PORT);
         datasize = ur_get_size(UR_SRC_PORT);
         memcpy(dp, p, datasize); /* complete SRCPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPSRCPORT]];
         dp += ur_get_size(UR_SRC_IP);
         memcpy(dp, p, datasize); /* complete SRCIPSRCPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[DSTIPSRCPORT]];
         dp += ur_get_size(UR_DST_IP);
         memcpy(dp, p, datasize); /* complete DSTIPSRCPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIPSRCPORT]];
         dp += ur_get_size(UR_SRC_IP) + ur_get_size(UR_DST_IP);
         memcpy(dp, p, datasize); /* complete SRCIPDSTIPSRCPORT */

         /* DSTPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[DSTPORT]];
         p = (char *) ur_get_ptr(tmpl, data, UR_DST_PORT);
         datasize = ur_get_size(UR_DST_PORT);
         memcpy(dp, p, datasize); /* complete DSTPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTPORT]];
         dp += ur_get_size(UR_SRC_IP);
         memcpy(dp, p, datasize); /* complete SRCIPDSTPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[DSTIPDSTPORT]];
         dp += ur_get_size(UR_DST_IP);
         memcpy(dp, p, datasize); /* complete DSTIPDSTPORT */
         dp = &sdata[link].ent_data[ent_data_sizes[SRCIPDSTIPDSTPORT]];
         dp += ur_get_size(UR_SRC_IP) + ur_get_size(UR_DST_IP);
         memcpy(dp, p, datasize); /* complete SRCIPDSTIPDSTPORT */

//#   pragma omp parallel for
         for (i=0; i<ENTROPIES_COUNT; ++i) {
            ent_shash_put_data(sdata[link].hash_entropies[i], &sdata[link].ent_data[ent_data_sizes[i]]);
         }
#endif /* BYTEENTROPY */
#ifdef BREAK_ON_FIRST_LINK
         break;
#endif /* BREAK_ON_FIRST_LINK */
         if (linkbit == 0) {
            break;
         }
      }
      /* All data processed, tables updated */
   } /* while (!stop) */
loopend:
   send_results(sdata, linkcount, tmplt_out, data_out, &cur_timeslot, timewindow, long_output);
   trap_send_data(0, data_out, 1, TRAP_NO_WAIT);
   for (i=0; i<(ENTROPIES_COUNT*linkcount); ++i) {
#ifdef BYTEENTROPY
      ent_free(&sdata[i/ENTROPIES_COUNT].entropies[i%ENTROPIES_COUNT]);
#else
      ent_shash_free(&sdata[i/ENTROPIES_COUNT].hash_entropies[i%ENTROPIES_COUNT]);
#endif
   }
   free(sdata);
   #ifdef DEBUG
   printf("ent_cache_miss: %llu\nent_cache_hit: %llu\n", (unsigned long long int) ent_cache_miss, (unsigned long long int) ent_cache_hit);
   printf("Total: flows#%llu pkts#%llu bytes#%llu\n", (unsigned long long int) gflow_total,
   (unsigned long long int) gpkts_total, (unsigned long long int) gbyte_total);
   #endif
   ur_free_template(tmpl);
   ur_free_template(tmplt_out);
failed_trap:
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   return 0;
}
