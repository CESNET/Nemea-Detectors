#include <iostream>
#include <vector>
#include <string>
#include <syslog.h>

#include "hoststats.h"
#include "processdata.h"
#include "database.h"

using namespace std;

bool background = false; // Run in background
int log_syslog = false;  // Log into syslog
int log_upto = LOG_WARNING; // Log up to level 


int main(int argc, char **argv)
{
   if (argc != 3) {
      cout << "Usage:\n"
           << "   " << argv[0] << " input output\n"
           << "\n"
           << "   input    input file with flow records (nfdump format)\n"
           << "   output   output file with host statistics\n";
      return 1;
   }
   
   // Load flows
   flow_map_t flow_map;
   
   vector<string> filenames;
   vector<int> priorities;
   filenames.push_back(string(argv[1]));
   priorities.push_back(0);
   
   load_flows(filenames, priorities, flow_map);
   
   // Compute host statistics
   stat_map_t stat_map;   
   compute_host_stats(flow_map, NULL, stat_map);
   
   // Store statistics
   Database::storeToFile(string(argv[2]), stat_map);
   
   return 0;
}
