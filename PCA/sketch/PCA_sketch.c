/**
 * \file PCA_sketch.c
 * \brief Module for detection of network anomalies using PCA and sketch subspaces.
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
#include "../../unirec.h"

#include "PCA_sketch.h"

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
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();// this interrupt a possible waiting in recv/send functions
   }
}

/* !!!TODO - make it better...
 * Dumb hash-IP-address functions for IPv4, IPv6 and port number
 */
uint16_t hash_ipv4(uint32_t address)
{
   return(address%SKETCH_WIDTH);
}

uint16_t hash_ipv6(uint64_t lower_half_of_address)
{
   return(lower_half_of_address%SKETCH_WIDTH);
}

uint16_t hash_port(uint16_t port_number)
{
   return(port_number%SKETCH_WIDTH);
}
/*
 * END OF DUMMIES !!!TODO
 */

int main(int argc, char **argv)
{
   int ret;
   int i;
   uint8_t new_timebin_flag=1;
   uint32_t start_of_timebin=0;
   uint32_t start_of_actual_flow;
   uint32_t timebin_counter=0;
   uint32_t sketches [SKETCH_WIDTH][NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_HASH_FUNCTION];
   uint16_t ft_hash_values [NUMBER_OF_FEATURES];
   trap_ifc_spec_t ifc_spec;

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

   // ***** Main processing loop *****

   // Read data from input, process them and write to output
   while (!stop) {
      const void *data_ptr;
      uint16_t data_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_get_data(TRAP_MASK_ALL, &data_ptr, &data_size, TRAP_WAIT);
      if (ret == TRAP_E_TERMINATED) {
         break; // Module was terminated while waiting for new data (e.g. by Ctrl-C)
      } else if (ret != TRAP_E_OK) {
         // Some error ocurred
         fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret,
                 trap_last_error_msg);
         break;
      }

      // CAST THE DATA TO THE EXPECTED TYPE/STRUCT (but first check the size)
      if (data_size != sizeof(ur_basic_flow_t)) {
         fprintf(stderr, "Error: data with wrong size received (expected size:"
                 "%lu, received size: %hu)\n",
                 sizeof(ur_basic_flow_t),data_size);
         break;
      }
      const ur_basic_flow_t *received_data = (ur_basic_flow_t *)data_ptr;

      // PROCESS THE DATA
      ur_basic_flow_t flow_data;
      flow_data.src_addr = received_data->src_addr;
      flow_data.dst_addr = received_data->dst_addr;
      flow_data.src_port = received_data->src_port;
      flow_data.dst_port = received_data->dst_port;
      start_of_actual_flow = (received_data->first)>>32;

      if(start_of_actual_flow>start_of_timebin+TIMEBIN_SIZE){
         new_timebin_flag=1;
      }
      // !!!TODO overflow?
      if (new_timebin_flag){
         new_timebin_flag=0;
         ++timebin_counter;
         start_of_timebin=start_of_actual_flow;
         printf("Start of %u. timebin in %u\n",timebin_counter,start_of_actual_flow);
      }

     /* if(ip_is4(&(flow_data.src_addr))){
         ft_hash_values[FSRCIP]=hash_ipv4(ip_get_v4_as_int(&(flow_data.src_addr)));
         ft_hash_values[FDSTIP]=hash_ipv4(ip_get_v4_as_int(&(flow_data.dst_addr)));
      } else {
         ft_hash_values[FSRCIP]=hash_ipv6(flow_data.src_addr.ui64[1]);
         ft_hash_values[FDSTIP]=hash_ipv6(flow_data.dst_addr.ui64[1]);
      }
      ft_hash_values[FSRCPORT]=hash_port(flow_data.src_port);
      ft_hash_values[FDSTPORT]=hash_port(flow_data.dst_port);

      printf("%u : %u : %u : %u \n",ft_hash_values[0],ft_hash_values[1],ft_hash_values[2],ft_hash_values[3]);

      for (i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
         //hash it
      }*/

      // Send data to interface 0, if ifc is not ready, wait at most 10ms
      //trap_send_data(0, (void*)&new_data, sizeof(my_data_struct_t), 10000);
   }

//   printf("\nTotal flows count: %u\n",v4counter+v6counter);

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();

   return 0;
}
