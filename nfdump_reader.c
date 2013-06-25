/**
 * \file nfdump_reader.h
 * \brief Nfdump reader module reads a given nfdump file and outputs flow
 *  records in UniRec format.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */

#include <signal.h>
#include <stdio.h>
#include <getopt.h>

#include <libtrap/trap.h>
#include "nfreader.h"
#include "unirec.h"

// Struct with information about module
trap_module_info_t module_info = {
   "Nfdump-reader module", // Module name
   // Module description
   "This module module reads a given nfdump file and outputs flow records in \n"
   "UniRec format.\n"
   "Interfaces:\n"
   "   Inputs: 0\n"
   "   Outputs: 1 (ur_basic_flow)\n",
   0, // Number of input interfaces
   1, // Number of output interfaces
};

static int stop = 0;

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1;
      trap_terminate();
   }
}

int main(int argc, char **argv)
{
   int ret;
   nf_file_t file;
   trap_ifc_spec_t ifc_spec;
   unsigned long counter = 0;
   unsigned long max_records = 0;
   int send_eof = 1;
   int verbose = 0;
   
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
   
   verbose = (trap_get_verbose_level() >= 0);
   
   char opt;
   while ((opt = getopt(argc, argv, "c:n")) != -1) {
      switch (opt) {
         case 'c':
            max_records = atoi(optarg);
            if (max_records == 0) {
               fprintf(stderr, "Invalid maximal number of records.\n");
               return 2;
            }
            break;
         case 'n':
            send_eof = 0;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 2;
      }
   }
   
   if (optind >= argc) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier [-n] [-c NUM] nfdump-file\n", argv[0]);
      return 2;
   }

   // Open nfdump file
   if (verbose) {
      printf("Opening file %s ...\n", argv[optind]);
   }
   ret = nf_open(&file, argv[optind]);
   if (ret != 0) {
      fprintf(stderr, "Error when trying to open file \"%s\"\n", argv[optind]);
      return 3;
   }
   
   // Initialize TRAP library (create and init all interfaces)
   if (verbose) {
      printf("Initializing TRAP library ...\n");
   }
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      nf_close(&file);
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
   }
   trap_free_ifc_spec(ifc_spec); // We don't need ifc_spec anymore
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);

   // Read a record from file, convert to UniRec and send to output ifc
   if (verbose) {
      printf("Sending records ...\n");
   }
   while (!stop && (max_records == 0 || counter < max_records)) {
      master_record_t rec;

      ret = nf_next_record(&file, &rec);
      if (ret != 0) {
         if (ret == 1) { // no more records
            break;
         }
         fprintf(stderr, "Error during reading file.\n");
         nf_close(&file);
         trap_finalize();
         return 3;
      }

 

     ur_basic_flow_t rec2;
     uint64_t tmp_ip_v6_addr; 

      // Copy data from master_record_t to ur_basic_flow_t
      // TODO check endinanness
      if (rec.flags & 0x01) { // IPv6
         // Swap IPv6 halves
         tmp_ip_v6_addr = rec.ip_union._v6.srcaddr[0];
         rec.ip_union._v6.srcaddr[0] = rec.ip_union._v6.srcaddr[1];
         rec.ip_union._v6.srcaddr[1] = tmp_ip_v6_addr;
         tmp_ip_v6_addr = rec.ip_union._v6.dstaddr[0];
         rec.ip_union._v6.dstaddr[0] = rec.ip_union._v6.dstaddr[1];
         rec.ip_union._v6.dstaddr[1] = tmp_ip_v6_addr;

          rec2.src_addr = ip_from_16_bytes_le((char *)rec.ip_union._v6.srcaddr);
          rec2.dst_addr = ip_from_16_bytes_le((char *)rec.ip_union._v6.dstaddr);

         /*// rec.ip_union._v6.srcaddr is uint64_t[2]
         rec2.src_addr.ui32[0] = rec.ip_union._v6.srcaddr[0];
         rec2.src_addr.ui32[1] = rec.ip_union._v6.srcaddr[0] >> 32;
         rec2.src_addr.ui32[2] = rec.ip_union._v6.srcaddr[1];
         rec2.src_addr.ui32[3] = rec.ip_union._v6.srcaddr[1] >> 32;
         rec2.dst_addr.ui32[0] = rec.ip_union._v6.dstaddr[0];
         rec2.dst_addr.ui32[1] = rec.ip_union._v6.dstaddr[0] >> 32;
         rec2.dst_addr.ui32[2] = rec.ip_union._v6.dstaddr[1];
         rec2.dst_addr.ui32[3] = rec.ip_union._v6.dstaddr[1] >> 32;*/
      }
      else { // IPv4  
         rec2.src_addr = ip_from_4_bytes_le((char *)&rec.ip_union._v4.srcaddr);
         rec2.dst_addr = ip_from_4_bytes_le((char *)&rec.ip_union._v4.dstaddr);

         /*rec2.src_addr.ui32[0] = rec.ip_union._v4.srcaddr;
         rec2.src_addr.ui32[1] = 0;
         rec2.src_addr.ui32[2] = 0;
         rec2.src_addr.ui32[3] = 0;
         rec2.dst_addr.ui32[0] = rec.ip_union._v4.dstaddr;
         rec2.dst_addr.ui32[1] = 0;
         rec2.dst_addr.ui32[2] = 0;
         rec2.dst_addr.ui32[3] = 0;*/
      }
      rec2.src_port = rec.srcport;
      rec2.dst_port = rec.dstport;
      rec2.proto = rec.prot;
      rec2.tcp_flags = rec.tcp_flags;
      rec2.packets = rec.dPkts;
      rec2.bytes = rec.dOctets;
      rec2.first = (((uint64_t)rec.first)<<32) | rec.msec_first; // Merge secs and msecs together
      rec2.last = (((uint64_t)rec.last)<<32) | rec.msec_last;    // Merge secs and msecs together
      

      // Send data to output interface
      trap_send_data(0, &rec2, sizeof(rec2), TRAP_WAIT);
      counter++;
      //usleep(100);
      
      if (verbose && counter % 1000 == 1) {
         printf(".");
         fflush(stdout);
      }
   }

   if (verbose) {
      printf("done\n");
   }
   
   nf_close(&file);

   printf("%lu flow records sent\n", counter);
   
   // Send data with zero length to signalize end
   char dummy[1] = {0};
   if (!stop && send_eof) { // if EOF enabled and program wasn't interrupted
      if (verbose) {
         printf("Sending EOF message (zero-length record)\n");
      }
      trap_send_data(0, dummy, 1, TRAP_WAIT); // FIXME: zero-length messages doesn't work, send message of length 1
   }
   
   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();

   return 0;
}

