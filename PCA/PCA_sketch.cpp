/**
 * \file PCA_sketch.c
 * \brief Module for detection of network anomalies using PCA and sketch
 *        subspaces.
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
#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

#include "PCA_sketch.h"
#include "alglib/dataanalysis.h"

// ******** TEMPORARY:  IN FUTURE SHOULD BE IN "common.h ***********************
/*
 * SuperFastHash by Paul Hsieh
 * http://www.azillionmonkeys.com/qed/hash.html
 */

#include <stdint.h>
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif


//#define DEBUG
//#define DEBUG_OUT
      #ifdef DEBUG_OUT
      #include <inttypes.h>
      #endif
uint32_t SuperFastHash (const char *data, int len, int seed) {
   uint32_t hash = len + seed, tmp;
   int rem;

         #ifdef DEBUG_OUT
            uint64_t *data2=data;
            printf("%" PRIu64 "\n", data2[0]);
         #endif

         #ifdef DEBUG_OUT
            uint64_t *data2=data;

            printf("HashKey: ");
            for(int i=0;i<(len/8);i++){
               printf("%016llX:", data2[i]);
            }
//            printf("%" PRIu64 "\n", data2[0]);
            printf("\nLen: %i\n", len);
         #endif

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

// ***************** END OF TEMPORARY ******************************************

// Struct with information about module
trap_module_info_t module_info = {
   "Module for anomaly detection using PCA and sketch subspaces.",// Module name
   // Module description
   "This module detecting network anomalies in data flows.\n"
   ""
   "Interfaces:\n"
   "   Inputs: 1 UniRec (ur_basic_flow_t)\n"
   "   Outputs: 2:\n"
   "     \t1.UniRec - information about time in witch an anomaly(-ies) "
                                                                  "occuring.\n"
   "     \t2.UniRec - flow(s) responsible for an anomaly(-ies)",
   1, // Number of input interfaces
   2, // Number of output interfaces
};


static int stop = 0;

/*
 * Procedure for handling signals SIGTERM and SIGINT
 */
void signal_handler(int signal)
{
   if (trap_get_verbose_level() > 0)
      printf("Signal received\n");
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1; // this breaks the main loop
      trap_terminate(); // this interrupt a possible waiting in recv/send functions
   }
}

int main(int argc, char **argv)
{
   int ret;
   trap_ifc_spec_t ifc_spec;

   int i,j;

   uint8_t timebin_init_flag=1;
   uint32_t start_of_actual_flow;
   uint32_t timebin_counter; // counted from zero
   uint32_t start_of_next_timebin=0;

   uint64_t tmp_addr_part; // for IPv4
   //TODO - dat dohromady v4 a v6 a zapisovat do nektere casti [0]/[3]
   uint64_t hash_key [4];
   int hk_size;

   uint32_t row_in_sketch;

   static uint32_t address_sketches [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][ADDRESS_SKETCH_WIDTH*2];
   static uint32_t port_sketches [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH*2];

   uint64_t pkt_cnt_in_actual_timebin=0;

//   void (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(type1 *, type2, ...);
   uint32_t (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(const char *, int , int );
   ptrHashFunc [0] = SuperFastHash;
   ptrHashFunc [1] = SuperFastHash;
   ptrHashFunc [2] = SuperFastHash;
   ptrHashFunc [NUMBER_OF_HASH_FUNCTION - 1] = SuperFastHash;

   // ***** TRAP initialization *****

   // Let TRAP library parse command-line arguments and extract its parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n",
              trap_last_error_msg);
      return 1;
   }

   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      return 2;
   }

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);


   // ***** Create UniRec templates *****
   // From ../../nfreader/nfdump_reader.c
   ur_template_t *in_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
                                                "TIME_LAST,PACKETS,BYTES,"
                                                "TCP_FLAGS");
//   ur_template_t *work_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,TIME_FIRST,PACKETS");
//////   ur_template_t *out_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS");

   // Allocate memory for output record
//   void *work_rec = ur_create(work_tmplt, 0);
//////   void *out_rec = ur_create(out_tmplt, 0);

   // ***** Main processing loop *****
//   printf("Size of sketches is: %u\n", sizeof(address_sketches[0][0][0])*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION+
//                                       sizeof(port_sketches[0][0][0])*SKETCH_SIZE*PORT_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION);
//   stop=1;
   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_get_data(TRAP_MASK_ALL, &in_rec, &in_rec_size, TRAP_WAIT);
      if (ret == TRAP_E_TERMINATED) {
         break; // Module was terminated while waiting for data (e.g. by Ctrl-C)
      } else if (ret != TRAP_E_OK) {
         // Some error ocurred
         fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret,
                 trap_last_error_msg);
         break;
      }

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

      // PROCESS THE DATA

      // *** Timebin division (sampling) based on TIMEBIN_SIZE (in seconds) ***
      start_of_actual_flow = (ur_get(in_tmplt,in_rec,UR_TIME_FIRST))>>32;
      if(timebin_init_flag){ // initialization of counters with first flow
         timebin_init_flag = 0;
         start_of_next_timebin = start_of_actual_flow + TIMEBIN_SIZE;
         timebin_counter = 1; // timebin_counter-1 == 1st index in DataTable
         memset(address_sketches, 0, sizeof(address_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH*2);
         memset(port_sketches, 0, sizeof(address_sketches[0][0][0])*SKETCH_SIZE*PORT_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION);
               #ifdef DEBUG_OUT
                  printf("Start of %u. timebin in %u------------------------------"
                        "--------------\n",timebin_counter,start_of_next_timebin);
               #endif
      }

      if(start_of_actual_flow>start_of_next_timebin){
         for(i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
            for(j = 0; j < SKETCH_SIZE; j++){
//               //// !!! OVERFLOW timebin_counter
//               data_matrix[i][timebin_counter-1][j]=compute_entropy(address_sketches[i][j]);
//               data_matrix[i][timebin_counter-1][j+SKETCH_SIZE]=compute_entropy(address_sketches[i][j]);
//               data_matrix[i][timebin_counter-1][j+SKETCH_SIZE*2]=compute_entropy(address_sketches[i][j]);
//               data_matrix[i][timebin_counter-1][j+SKETCH_SIZE*3]=compute_entropy(address_sketches[i][j]);
            }
            // preprocess_data_matrix();
            // normalize_data_matrix();
            // proceed_with_detection();
            //// PCA();
            //// find_normal_subspace_size();
            //// compute_C-Residual();
            //// detection_by_SPE_test();
          }
         // merge_results();
         // IF DETECTED:
         //>YES> proceed_with_identification >> sending identificated flows
         // drop_actual_flows ... proceed with another timebin

         // !!!TODO overflow?
         ++timebin_counter;
         start_of_next_timebin += TIMEBIN_SIZE;
         pkt_cnt_in_actual_timebin=0;
         memset(address_sketches, 0, sizeof(address_sketches[0][0][0])*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION);
         memset(port_sketches, 0, sizeof(address_sketches[0][0][0])*SKETCH_SIZE*PORT_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION);
         printf("Detection...\n");
               #ifdef DEBUG_OUT
                  printf("Start of %u. timebin in %u------------------------------"
                        "--------------\n",timebin_counter,start_of_next_timebin);
               #endif
      } else {
         // *** Getting HashKey ***
         memset(hash_key,0,sizeof(hash_key));
         if(ip_is4(ur_get_ptr(in_tmplt,in_rec,UR_SRC_IP))){
            tmp_addr_part = ip_get_v4_as_int(ur_get_ptr(in_tmplt, in_rec, UR_SRC_IP)) & V4_HASH_KEY_MASK;
            hash_key[0] |= tmp_addr_part << (V4_BIT_LENGTH); // left aligment on 64 bits of uint64_t
            tmp_addr_part = ip_get_v4_as_int(ur_get_ptr(in_tmplt, in_rec, UR_DST_IP)) & V4_HASH_KEY_MASK;
            hash_key[0] |= tmp_addr_part << (V4_BIT_LENGTH - V4_HASH_KEY_PART);
         } else {
            if(V6_HASH_KEY_PART == V6_BIT_PART_LENGTH){
               hash_key[0] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0];
               hash_key[1] = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0];
               hk_size = sizeof(hash_key[0])*2;
            } else if(V6_HASH_KEY_PART == V6_BIT_PART_LENGTH*2) {
               hash_key[0] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0];
               hash_key[1] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[1];
               hash_key[2] = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0];
               hash_key[3] = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[1];
               hk_size = sizeof(hash_key);
            } else if(V6_HASH_KEY_PART < V6_BIT_PART_LENGTH) {
               tmp_addr_part = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0] & V6_HASH_KEY_MASK;
               hash_key[0] |= tmp_addr_part;
               tmp_addr_part = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0] & V6_HASH_KEY_MASK;
               hash_key[0] |= tmp_addr_part >> V6_HASH_KEY_PART;
               hash_key[1] |= tmp_addr_part << (V6_BIT_PART_LENGTH - V6_HASH_KEY_PART);
               hk_size = sizeof(hash_key[0])*2;
            } else { // V6_HASH_KEY_PART > V6_BIT_PART_LENGTH
               hash_key[0] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0];
               tmp_addr_part = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[1] & V6_HASH_KEY_MASK;
               hash_key[1] |= tmp_addr_part;
               tmp_addr_part = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0];
               hash_key[1] |= tmp_addr_part >> (V6_HASH_KEY_PART % 64);
               hash_key[2] |= tmp_addr_part << (V6_BIT_PART_LENGTH - (V6_HASH_KEY_PART % 64));
               tmp_addr_part = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[1] & V6_HASH_KEY_MASK;
               hash_key[2] |= tmp_addr_part >> (V6_HASH_KEY_PART % 64);
               hash_key[3] |= tmp_addr_part << (V6_BIT_PART_LENGTH - (V6_HASH_KEY_PART % 64));
               hk_size = sizeof(hash_key);
            }
//                  #ifdef DEBUG
//                     printf("SRC_IP_v6: %016llX:%016llX \tSRC_IP_v6: %016llX:%016"
//                            "llX \n", ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0],
//                            ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[1],
//                            ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0],
//                            ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[1]);
//                     printf("HashKey_v6: %016llX:%016llX:%016llX:%016llX \n",
//                         hash_key[0], hash_key[1], hash_key[2], hash_key[3]);
//   //               printf("%" PRIu64 "\n", hash_key[0]);
//                  #endif
//                  #ifdef DEBUG
//                     printf("pos_v6:\t%u\n", row_in_sketch);
//                  #endif
         }
         // *** END OF Getting HashKey ***
         // *** Adding feature occurrence in all sketches ***
         for(i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){/*
            row_in_sketch = SuperFastHash((char *)hash_key, hk_size, seeds[i]) % SKETCH_SIZE;
            address_sketches [i][row_in_sketch]
                             [SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_SRC_IP),
                                            sizeof(ur_get(in_tmplt, in_rec, UR_SRC_IP)), SEED_DEFAULT) % ADDRESS_SKETCH_WIDTH]
                             += ur_get(in_tmplt, in_rec, UR_PACKETS);
            address_sketches [i][row_in_sketch]
                             [(SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_DST_IP),
                                            sizeof(ur_get(in_tmplt, in_rec, UR_DST_IP)), SEED_DEFAULT) % ADDRESS_SKETCH_WIDTH) + ADDRESS_SKETCH_WIDTH]
                             += ur_get(in_tmplt, in_rec, UR_PACKETS);
            port_sketches [i][row_in_sketch]
                          [SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_SRC_PORT),
                                         sizeof(ur_get(in_tmplt, in_rec, UR_SRC_IP)), SEED_DEFAULT) % PORT_SKETCH_WIDTH]
                          += ur_get(in_tmplt, in_rec, UR_PACKETS);
            port_sketches [i][row_in_sketch]
                          [(SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_DST_PORT),
                                         sizeof(ur_get(in_tmplt, in_rec, UR_DST_IP)), SEED_DEFAULT) % PORT_SKETCH_WIDTH) + PORT_SKETCH_WIDTH]
                          += ur_get(in_tmplt, in_rec, UR_PACKETS);
            pkt_cnt_in_actual_timebin += ur_get(in_tmplt, in_rec, UR_PACKETS);
         */}
         // *** END OF Adding feature occurrence in all sketches ***
      }
      // *** END OF Timebin division ***

//////      // Read FOO and BAR from input record and compute their sum
//////      uint32_t baz = ur_get(in_tmplt, in_rec, UR_FOO) +
//////                     ur_get(in_tmplt, in_rec, UR_BAR);
//////
//////      // Fill output record
//////      ur_set(out_tmplt, out_rec, UR_FOO, ur_get(in_tmplt, in_rec, UR_FOO));
//////      ur_set(out_tmplt, out_rec, UR_BAR, ur_get(in_tmplt, in_rec, UR_BAR));
//////      ur_set(out_tmplt, out_rec, UR_BAZ, baz);


      // Send record to interface 0, if ifc is not ready, wait at most 10ms
//////      trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), 10000);
   }

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   trap_finalize();
//////   ur_free(out_rec);
   ur_free_template(in_tmplt);
//////   ur_free_template(out_tmplt);

   return 0;
}

