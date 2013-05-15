/**
 * \file flow_counter.h
 * \brief Example module for counting number of incoming flow records. 
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */

#include <signal.h>
#include <stdio.h>
#include <stdint.h>

#include <libtrap/trap.h>
#include "unirec.h"

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Flow-counter module", // Module name
   // Module description
   "Example module for counting number of incoming flow records.\n"
   "Interfaes:\n"
   "   Inputs: 1 (ur_basic_flow)"
   "   Outputs: 0",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM) {
      stop = 1;
      trap_terminate();
   }
}

int main(int argc, char **argv)
{
   int ret;
   unsigned long cnt_flows = 0;
   unsigned long cnt_packets = 0;
   unsigned long cnt_bytes = 0;
   
   // ***** TRAP initialization *****
   trap_ifc_spec_t ifc_spec;
   
   // Let TRAP library parse command-line arguments and extract its parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
   }
   trap_free_ifc_spec(ifc_spec);
   
   signal(SIGTERM, signal_handler);
   
   // ***** Main processing loop *****
   
   while (!stop) {
      // Receive data from any interface, wait until data are available
      const void *data;
      uint16_t data_size;
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TERMINATED) {
            // Module was terminated (e.g. by Ctrl-C)
            break;
         } else {
            // Some error ocurred
            fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret, trap_last_error_msg);
            break;
         }
      }
      
      
      // Check size of received data
      if (data_size != sizeof(ur_basic_flow_t)) {
         if (data_size <= 1) {
            // End of data, print counters
            printf("Flows: %lu\n", cnt_flows);
            printf("Packets: %lu\n", cnt_packets);
            printf("Bytes: %lu\n", cnt_bytes);
            break;
         }
         else {
            fprintf(stderr, "Error: data with wrong size received (expected size: %i, received size: %i)\n",
                    sizeof(ur_basic_flow_t), data_size);
            break;
         }
      }
      
      // Reinterpret data as flow record
      ur_basic_flow_t *rec = (ur_basic_flow_t*)data;
      
      // Update counters
      cnt_flows += 1;
      cnt_packets += rec->packets;
      cnt_bytes += rec->bytes;
      
   }
   
   // ***** Cleanup *****
   
   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();
   
   return 0;
}

