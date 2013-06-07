/**
 * \file nfdump_reader_test.cpp
 * \brief Special version of nfdump reader for throughput testing - it reads
 *  whole file into memory before sending flows to the output.
 * \author Vaclav Bartos <ibartosv@fit.vutbr.cz>
 * \date 2013
 */

#include <signal.h>
#include <stdio.h>
#include <vector>
#include <iostream>

extern "C" {
#include <libtrap/trap.h>
#include "nfreader.h"
}
#include "unirec.h"

using namespace std;

// Struct with information about module
trap_module_info_t module_info = {
   (char *) "Nfdump-reader module", // Module name
   // Module description
   (char *) "This module module reads a given nfdump file and outputs flow records in \n"
   "UniRec format (special version for throughput testing).\n"
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

   if (argc != 2) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier nfdump-file\n", argv[0]);
      trap_finalize();
      return 2;
   }

   ret = nf_open(&file, argv[1]);
   if (ret != 0) {
      fprintf(stderr, "Error when trying to open file \"%s\"\n", argv[1]);
      trap_finalize();
      return 3;
   }
   
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      nf_close(&file);
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
   }
   trap_free_ifc_spec(ifc_spec); // We don't need ifc_spec anymore
   
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   
   
   vector<ur_basic_flow_t> records;

   cout << "Loading data from file..." << endl;
   while (1) {
      master_record_t rec;

      ret = nf_next_record(&file, &rec);
      if (ret != 0) {
         if (ret == 1) { // no more records
            break;
         }
         fprintf(stderr, "Error during reading file.\n", argv[1]);
         nf_close(&file);
         trap_finalize();
         return 3;
      }

      records.push_back(ur_basic_flow_t());
      ur_basic_flow_t &rec2 = records.back();

      // Copy data from master_record_t to ur_basic_flow_t
      // TODO check endinanness
      if (rec.flags & 0x01) { // IPv6
         // rec.ip_union._v6.srcaddr is uint64_t[2]
         rec2.src_addr.ad[0] = rec.ip_union._v6.srcaddr[0];
         rec2.src_addr.ad[1] = rec.ip_union._v6.srcaddr[0] >> 32;
         rec2.src_addr.ad[2] = rec.ip_union._v6.srcaddr[1];
         rec2.src_addr.ad[3] = rec.ip_union._v6.srcaddr[1] >> 32;
         rec2.dst_addr.ad[0] = rec.ip_union._v6.dstaddr[0];
         rec2.dst_addr.ad[1] = rec.ip_union._v6.dstaddr[0] >> 32;
         rec2.dst_addr.ad[2] = rec.ip_union._v6.dstaddr[1];
         rec2.dst_addr.ad[3] = rec.ip_union._v6.dstaddr[1] >> 32;
      }
      else { // IPv4
         rec2.src_addr.ad[0] = rec.ip_union._v4.srcaddr;
         rec2.src_addr.ad[1] = 0;
         rec2.src_addr.ad[2] = 0;
         rec2.src_addr.ad[3] = 0;
         rec2.dst_addr.ad[0] = rec.ip_union._v4.dstaddr;
         rec2.dst_addr.ad[1] = 0;
         rec2.dst_addr.ad[2] = 0;
         rec2.dst_addr.ad[3] = 0;
      }
      rec2.src_port = rec.srcport;
      rec2.dst_port = rec.dstport;
      rec2.proto = rec.prot;
      rec2.tcp_flags = rec.tcp_flags;
      rec2.packets = rec.dPkts;
      rec2.bytes = rec.dOctets;
      rec2.first = rec.first;
      rec2.msec_first = rec.msec_first;
      rec2.last = rec.last;
      rec2.msec_last = rec.msec_last;
   }

   nf_close(&file);

   cout << "Sending (" << records.size() << ") records..." << endl;

   // Read a record from file, convert to UniRec and send to output ifc
   for (int i = 0; i < records.size() && !stop; i++)
   {
      // Send data to output interface
      trap_send_data(0, &records[i], sizeof(records[i]), TRAP_WAIT);
      //usleep(100);
   }
   cout << "Sending terminating record..." << endl;

   // Send data with zero length to signalize end
   if (!stop)
      trap_send_data(0, &records[0], 1, TRAP_WAIT); // FIXME: zero-length messages doesn't work, send message of length 1

   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
   trap_finalize();

   return 0;
}

