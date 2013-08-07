#include <iostream>
#include <sstream>
#include <map>
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint8_t, uint16_t, uint32_t, uint64_t
#include <arpa/inet.h> // inet_pton(), AF_INET, AF_INET6
#include <assert.h>

#include "hoststats.h"
#include "processdata.h"
#include "../aux_func.h" // various simple conversion functions
#include "../config.h"
#include "profile.h"
#include "database.h"
#include "../wardenreport.h"
#include "../eventhandler.h"
#include "../BloomFilter.hpp"
#include "../detectionrules.h"

extern "C" {
   #include <libtrap/trap.h>
}

using namespace std;

#define SIZEOFTIMESLOT   300
#define GET_DATA_TIMEOUT 1 //seconds
#define MSEC             1000000

const uint64_t MEMORY_LIMIT = 2LL*1024LL*1024LL*1024LL; // Maximum number of bytes consumed by host-stats (2GB)
const uint64_t MAX_NUM_OF_HOSTS = MEMORY_LIMIT / sizeof(hosts_record_t);

///////////////////////////
// Global variables
extern ur_template_t *tmpl_in;
extern ur_template_t *tmpl_out;

// Status information
bool processing_data = false;
//bool data_available = false;
//unsigned int flows_loaded = 0;
//unsigned int hosts_loaded = 0;
string last_timeslot = "none";


static bool threads_terminated = 0; // Threads for stat maps

/////////////////////////////////////////
// Host stats processing functions


/**
 * UpdateStatsRecord()
 * Update records in the stat_map by data form a given flow.
 *
 * Find two host records acoording to source and destination address of the
 * flow and update these records
 *
 * @param flow_key Key of the flow.
 * @param flow_rec Record of the flow.
 * @param bf Bloom filter used to approximate uniqueips statistic
 */
void UpdateStatsRecord(stat_map_t &stat_map, const flow_key_t &flow_key, 
                       const flow_record_t &flow_rec, bloom_filter &bf) {
   // find/add record in bloom filter
   ip_addr_t bkey[2] = {flow_key.sad, flow_key.dad};
   bool present = false;
   present = bf.containsinsert((const unsigned char *) bkey, 32);
   
   hosts_key_t src_host_key = flow_key.sad;
   hosts_key_t dst_host_key = flow_key.dad;

   hosts_record_t& src_host_rec = stat_map[src_host_key];
   hosts_record_t& dst_host_rec = stat_map[dst_host_key];

   src_host_rec.out_bytes += flow_rec.bytes;
   src_host_rec.out_packets += flow_rec.packets;
   if (!present) src_host_rec.out_uniqueips++;
   src_host_rec.out_flows++;

   if (flow_rec.tcp_flags & 0x1)
      src_host_rec.out_fin_cnt++;
   if (flow_rec.tcp_flags & 0x2)
      src_host_rec.out_syn_cnt++;
   if (flow_rec.tcp_flags & 0x4)
      src_host_rec.out_rst_cnt++;
   if (flow_rec.tcp_flags & 0x8)
      src_host_rec.out_psh_cnt++;
   if (flow_rec.tcp_flags & 0x10)
      src_host_rec.out_ack_cnt++;
   if (flow_rec.tcp_flags & 0x20)
      src_host_rec.out_urg_cnt++;

   src_host_rec.out_linkbitfield |= flow_rec.linkbitfield;

   dst_host_rec.in_bytes += flow_rec.bytes;
   dst_host_rec.in_packets += flow_rec.packets;
   if (!present) dst_host_rec.in_uniqueips++;
   dst_host_rec.in_flows++;

   if (flow_rec.tcp_flags & 0x1)
      dst_host_rec.in_fin_cnt++;
   if (flow_rec.tcp_flags & 0x2)
      dst_host_rec.in_syn_cnt++;
   if (flow_rec.tcp_flags & 0x4)
      dst_host_rec.in_rst_cnt++;
   if (flow_rec.tcp_flags & 0x8)
      dst_host_rec.in_psh_cnt++;
   if (flow_rec.tcp_flags & 0x10)
      dst_host_rec.in_ack_cnt++;
   if (flow_rec.tcp_flags & 0x20)
      dst_host_rec.in_urg_cnt++;

   dst_host_rec.in_linkbitfield |= flow_rec.linkbitfield;
}

/*
// Fill given stat_map using data from given flow_map
int compute_host_stats(const flow_map_t &flow_map, flow_filter_func_ptr filter, stat_map_t &stat_map)
{
   // Create bloom filter used for approximation of uniqueips statistic
   bloom_parameters bp;
   bp.projected_element_count = 5000000;
   bp.false_positive_probability = 0.01;
   bp.compute_optimal_parameters();
   log(LOG_DEBUG, "process_data: Creating Bloom Filter, table size: %d, hashes: %d",
       bp.optimal_parameters.table_size, bp.optimal_parameters.number_of_hashes);
   bloom_filter bf(bp);
   
   // Convert flow map into the stat map (i.e. compute statistics)
   flow_map_t::const_iterator it;
   for (it = flow_map.begin(); it != flow_map.end(); it++) {
      if (filter != NULL && filter(it->first, it->second) == false)
         continue;
      
      UpdateStatsRecord(stat_map, it->first, it->second, bf);

      if ((int) stat_map.size() > MAX_NUM_OF_HOSTS) {
         log(LOG_ERR, "Too much hosts (more than %li), memory limit reached. "
                "Processing of this timeslot will not continue.",
                MAX_NUM_OF_HOSTS);
         return 1;
      }
   }
   return 0;
}
*/

/////////////////////////////////////////
// Flow processing functions

/*
int FillFlowMap(nf_file_t &file, flow_map_t &flow_map, uint64_t linkbitfield)
{
   master_record_t master_record;
   int cnt = 0;
   while (nf_next_record(&file, &master_record) == E_OK) {
      // Create a flow map key
      flow_key_t flow_key;

      // Update the key with source address
      if (master_record.flags & 0x1) { // IPv6
         flow_key.sad = IPAddr(master_record.ip_union._v6.srcaddr).swapBlocks();
      }
      else { // IPv4
         flow_key.sad = IPAddr(master_record.ip_union._v4.srcaddr);
      }

      // Update the key with destination address
      if (master_record.flags & 0x1) { // IPv6
         flow_key.dad = IPAddr(master_record.ip_union._v6.dstaddr).swapBlocks();
      }
      else { // IPv4
         flow_key.dad = IPAddr(master_record.ip_union._v4.dstaddr);
      }

      // Update the key with remaining info
      flow_key.sport = master_record.srcport;
      flow_key.dport = master_record.dstport;
      flow_key.proto = master_record.prot;

      // Find or create a flow map record
      flow_record_t& flow_record = flow_map[flow_key];

      // Update the record with required info
      flow_record.packets      += master_record.dPkts;
      flow_record.bytes        += master_record.dOctets;
      flow_record.tcp_flags    |= master_record.tcp_flags;
      flow_record.linkbitfield |= linkbitfield;
      flow_record.dirbitfield  |= (0x1 << master_record.input);

      cnt++;
   }
   return cnt;
}

*/
/*
void UpdateFlow(flow_record_t & dest_flow, const flow_record_t & src_flow)
{
   dest_flow.packets      += src_flow.packets;
   dest_flow.bytes        += src_flow.bytes;
   dest_flow.tcp_flags    |= src_flow.tcp_flags;
   dest_flow.linkbitfield |= src_flow.linkbitfield;
   dest_flow.dirbitfield  |= src_flow.dirbitfield;

}
*/
/*
void JoinFlowMaps(flow_map_t &dest_map, flow_map_t &src_map)
{
   for (flow_map_iter it = src_map.begin(); it != src_map.end(); it++) {
      UpdateFlow(dest_map[it->first], it->second);
   }
}
*/
/*
void UpdateFlowLinkbitfield(flow_record_t & dest_flow, const flow_record_t & src_flow)
{
   dest_flow.linkbitfield |= src_flow.linkbitfield;
}
void UpdateFlowDirbitfield(flow_record_t & dest_flow, const flow_record_t & src_flow)
{
   dest_flow.dirbitfield |= src_flow.dirbitfield;
}
*/
/*
// Flows are loaded into flow_map (if it's not empty, it's cleared before loading)
void load_flows(vector<string> source_filenames, vector<int> source_priorities, flow_map_t &flow_map)
{
   assert(source_filenames.size() == source_priorities.size());
   
   vector<flow_map_t*> flow_map_vector;
   flow_map_vector.reserve(source_filenames.size());
   
   flow_map.clear(); // Clear main flow map
   flow_map_vector.push_back(&flow_map); // Put main flow map at the first pos in flow_map_vector
   
   // Open and read each file
   for (unsigned int i = 0; i < source_filenames.size(); i++) {
      const char *filename = source_filenames[i].c_str();
      // Open file with nfreader
      nf_file_t file;
      if (nf_open(&file, const_cast<char*>(filename)) != E_OK) {
         log(LOG_WARNING, "process_data: Can't open file \"%s\".", filename);
         continue;
      }
      
      // Create new flow_map (if i > 0, first map is already there)
      if (i > 0)
         flow_map_vector.push_back( new flow_map_t() );
      
      // Read all flows from file into the flow_map
      int rec_cnt = FillFlowMap(file, *flow_map_vector.back(), (0x1 << i));
//       log(LOG_DEBUG, "Link '%s': %i records loaded, %i unique flows", 
//           source_names[i].c_str(), rec_cnt, flow_map_vector.back().size());
      
      // Close file
      nf_close(&file);
   }
   
   // Check that at least one file was loaded successfully
   if (flow_map_vector.empty()) {
      log(LOG_WARNING, "process_data: Nothing loaded.");
      processing_data = false;
      return;
   }

   // Merge same priorities
   for (unsigned int i = 0; i < (source_priorities.size()-1); i++) {
      for (unsigned int j = i+1; j < source_priorities.size(); j++) {
         if (source_priorities[i] == source_priorities[j]) {
//             log(LOG_DEBUG, "Merging source '%s' into '%s' (same priorities).",
//                 source_names[j].c_str(), source_names[i].c_str());
            // Merge j-th flow map into i-th flow map
            JoinFlowMaps(*flow_map_vector[i], *flow_map_vector[j]);
            // Erase j-th source
            source_priorities.erase(source_priorities.begin() + j);
            source_filenames.erase(source_filenames.begin() + j);
            delete flow_map_vector[j];
            flow_map_vector.erase(flow_map_vector.begin() + j);
            j--;
         }
      }
   }

   // Create one final flow map
   for (unsigned int i = 1; i < flow_map_vector.size(); i++) {
      // TODO: process it in the order given by priorities            *****************
      // If a flow is already there, it's not rewritten nor updated
//       log(LOG_DEBUG, "Merging source '%s' into the first flow map.", source_names[i].c_str());
      for (flow_map_iter itflow = flow_map_vector[i]->begin(); itflow != flow_map_vector[i]->end(); itflow++) {
         flow_map_iter updatedflow;
         if ( (updatedflow = flow_map_vector[0]->find(itflow->first)) != flow_map_vector[0]->end() ) {
            UpdateFlowLinkbitfield(updatedflow->second, itflow->second);
            UpdateFlowDirbitfield(updatedflow->second, itflow->second);
         }
         else {
            flow_map_vector[0]->insert(*itflow);
         }
      }
      delete flow_map_vector[i];
   }

   // Now, all flow records should be loaded into flow_map_vector[0], which points to flow_map
}
*/


///////////////////////////////////////////////////////////////////////////////
// Main processing function
/*
void process_data(const string& ts)
{
   ///////////////////////////////////////////////////
   // Check and parse parameters and configuration
   
   // Check timeslot
   if (ts.size() != 12 || ts.find_first_not_of("0123456789") != string::npos) {
      log(LOG_ERR, "process_data: Invalid timeslot \"%s\"", ts.c_str());
      return;
   }
   
   // Safety check - if processing of previous timeslot is not completed,
   // don't start processing of new one to avoid machine overload
   if (processing_data) {
      log(LOG_NOTICE, "Can't process timeslot %s, previous timeslot hasn't been finished yet.", ts.c_str());
      return;
   }
   
   // Read configuration
   Configuration *conf = Configuration::getInstance();
   conf->lock();
   string flow_path = conf->getValue("flow-data-path");
   string sources_str = conf->getValue("flow-sources");
   bool rules_generic = (conf->getValue("rules-generic") == "1");
   bool rules_ssh = (conf->getValue("rules-ssh") == "1");
   conf->unlock();
   
   if (flow_path == "") {
      log(LOG_WARNING, "process_data: Path to flow files not specified in configuration.");
      return;
   }
   if (sources_str == "") {
      log(LOG_WARNING, "process_data: No source specified in configuration.");
      return;
   }
   
   // Fill in time in flow_path
   replace(flow_path, "%y", ts.substr(0,4));
   replace(flow_path, "%m", ts.substr(4,2));
   replace(flow_path, "%d", ts.substr(6,2));
   replace(flow_path, "%H", ts.substr(8,2));
   replace(flow_path, "%M", ts.substr(10,2));
   
   // Parse flow-sources
   vector<string> source_filenames;
   vector<int> source_priorities;
   
   {
      // Split sources_str by ';'
      vector<string> source_name_prior = split(sources_str, ';');
      // Split each source spec by ',' into name and priority
      for (unsigned int i = 0; i < source_name_prior.size(); i++) {
         vector<string> tmp = split(source_name_prior[i], ',');
         if (tmp.size() != 2) {
            log(LOG_ERR, "process_data: Invalid sources specifier in configuration.");
            return;
         }
         // Put source name into flow_path to get filename
         string filename = flow_path;
         replace(filename, "%source", tmp[0]);
         // Store filename and priority
         source_filenames.push_back(filename);
         source_priorities.push_back(str2int(tmp[1]));
      }
   }
   
   //////////////////////////////////////////////////////////////
   // All parameters loaded and parsed, start data processing
   
   // Set status information
   //data_available = false;
   //timeslot = ts;
   flows_loaded = 0;
   //hosts_loaded = 0;
   processing_data = true;
   
   log(LOG_INFO, "Processing timeslot %s ...", ts.c_str());
   
   // ** Load flow records from all files **
   flow_map_t flow_map;
   load_flows(source_filenames, source_priorities, flow_map);
   
   flows_loaded = flow_map.size();
   
   // Count transit flows/packets/bytes
   uint64_t transitflowcount   = 0;
   uint64_t transitpacketcount = 0;
   uint64_t transitbytecount   = 0;

   for (flow_map_iter itflow = flow_map.begin(); itflow != flow_map.end(); itflow++) {
      if (itflow->second.dirbitfield == 0x3) {
         transitflowcount++;
         transitpacketcount += itflow->second.packets;
         transitbytecount   += itflow->second.bytes;
      }
   }

   log(LOG_INFO, "Number of flows: %u", flows_loaded);
   log(LOG_INFO, "Transit flows, packets, bytes: %llu, %llu, %llu", 
       transitflowcount, transitpacketcount,transitbytecount);
   
   // ** Compute host statistics for each profile and store and analyze them **
   // TODO: run processing of each profile in separate thread
   for (int i = 0; i < profiles.size(); i++) {
      log(LOG_INFO, "Processing profile \"%s\" ...", profiles[i]->name.c_str());
      profiles[i]->new_data(ts, flow_map);
      log(LOG_DEBUG, "Profile \"%s\": Stats computed, storing ...", profiles[i]->name.c_str());
      profiles[i]->store();
      log(LOG_DEBUG, "Profile \"%s\": Stats stored, running detectors ...", profiles[i]->name.c_str());
      // run all detectors associated with this profile
      // TODO: abstract class for detectors(or "analyzers"?), global list of active detectors, here loop over this list
      if (rules_generic && profiles[i]->name == "all")
         check_rules(profiles[i]);
      if (rules_ssh && profiles[i]->name == "ssh")
         check_rules_ssh(profiles[i]);
      
      log(LOG_DEBUG, "Profile \"%s\": Detectors done, releasing stats from memory ...", profiles[i]->name.c_str());
      profiles[i]->release();
      log(LOG_INFO, "Processing of profile \"%s\" done.", profiles[i]->name.c_str());
   }
   //join all threads
   
   // Delete flow records
   flow_map.clear();
   
   log(LOG_INFO, "Processing of timeslot %s done.", ts.c_str());
   last_timeslot = ts;
   processing_data = false;
}
*/

/////////////////////////////////////////////////////////////////
// NEW FUNCTIONS FOR DATA FROM TRAP
void new_trap_data(const void *record)
{
   flow_key_t flow_key;

   // Update the key with source address
   if (ip_is4(&(ur_get(tmpl_in, record, UR_SRC_IP)))) { //IPv4
      flow_key.sad = ur_get(tmpl_in, record, UR_SRC_IP);
   } 
   else { //IPv6
      flow_key.sad = ur_get(tmpl_in, record, UR_SRC_IP);
   }

   // Update the key with destination address
   if (ip_is4(&(ur_get(tmpl_in, record, UR_DST_IP)))) {  //IPv4
      flow_key.dad = ur_get(tmpl_in, record, UR_DST_IP);
   }
   else { //IPv6
      flow_key.dad = ur_get(tmpl_in, record, UR_DST_IP);
   }

   // Update the key with remaining info
   flow_key.sport = ur_get(tmpl_in, record, UR_SRC_PORT);
   flow_key.dport = ur_get(tmpl_in, record, UR_DST_PORT);
   flow_key.proto = ur_get(tmpl_in, record, UR_PROTOCOL);

   flow_record_t flow_record;

   // Update the record with required info
   flow_record.packets      = ur_get(tmpl_in, record, UR_PACKETS);
   flow_record.bytes        = ur_get(tmpl_in, record, UR_BYTES);
   flow_record.tcp_flags    = ur_get(tmpl_in, record, UR_TCP_FLAGS);
   flow_record.linkbitfield = ur_get(tmpl_in, record, UR_LINK_BIT_FIELD);
   flow_record.dirbitfield  = ur_get(tmpl_in, record, UR_DIR_BIT_FIELD);

   for (int i = 0; i < profiles.size(); i++)
      profiles[i]->new_data(flow_key, flow_record);

}


// Swap stat_maps in all profiles
void swap_all_stat_maps(uint32_t &next_swap_time, const uint32_t &current_time,
   stat_map_mutex_t *mutexes)
{
   if (!(current_time > next_swap_time - 1)) {
      return;
   }

   // Convert uint32_t timeslot to string
   time_t temp = next_swap_time;
   struct tm *timeinfo = localtime(&temp);
   char buff[13]; //12 signs + '/0'
   strftime(buff, 13, "%4Y%2m%2d%2H%2M", timeinfo);
   string st_timeslot = string(buff);

   // Swap
   pthread_mutex_lock(&mutexes->swap_mutex);
   for (int i = 0; i < profiles.size(); i++) {
      profiles[i]->swap_stat_maps(st_timeslot);
      profiles[i]->bf->clear();
   }
   pthread_mutex_unlock(&mutexes->start_processing);

   next_swap_time += SIZEOFTIMESLOT;
   log (LOG_INFO, "Tables swapped - next_swap_time: %d", next_swap_time);
}

/////////////////////////////////////////////////////////////
// Threads

/** 
 * Thread function for get data from TRAP and store them. 
 */
void *data_reader_trap(void *mutex_map)
{
   int ret;
   stat_map_mutex_t *mutex = (stat_map_mutex_t*) (mutex_map);
   uint32_t next_swap_time = 0;
   uint32_t first_sec = 0; // seconds from rec->first

   while (!threads_terminated) {
      const void *data;
      uint16_t data_size;

      // Get new data from TRAP
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, GET_DATA_TIMEOUT * MSEC);
      if (ret != TRAP_E_OK) {
         if (ret == TRAP_E_TERMINATED) {
            threads_terminated = 1;
            break;
         }
         else if (ret == TRAP_E_TIMEOUT) {
            if (next_swap_time) {
               first_sec += GET_DATA_TIMEOUT;
               swap_all_stat_maps(next_swap_time, first_sec, mutex);
            }
            continue;
         } else {
            log(LOG_ERR, "Error: getting new data from TRAP failed: %s)\n",
               trap_last_error_msg);
            continue;
         }
      }

      // Check the correctness of recieved data
      if (data_size < ur_rec_static_size(tmpl_in)) {
         if (data_size <= 1) {
            threads_terminated = 1;
         }
         else {
            log(LOG_ERR, "Error: data with wrong size received (expected size: %lu,\
               received size: %i)\n", ur_rec_static_size(tmpl_in), data_size);
         }
         threads_terminated = 1;
         break;
      }

      first_sec = ur_get(tmpl_in, data, UR_TIME_FIRST) >> 32;

      // Get next swap time from first flow data
      if (!next_swap_time){
         if (first_sec % SIZEOFTIMESLOT == 0) {
            next_swap_time = first_sec + SIZEOFTIMESLOT;
         } else {
            next_swap_time = static_cast<uint32_t>((first_sec/SIZEOFTIMESLOT + 1)*SIZEOFTIMESLOT);
         }
         log (LOG_INFO, "Next_swap_time: %d", next_swap_time);
      }

      // Check timeslot and store new data
      swap_all_stat_maps(next_swap_time, first_sec, mutex);
      new_trap_data(data);
   }

   // TRAP TERMINATED, exiting... 
   log(LOG_INFO, "Reading from trap terminated.");

   // Clear all profiles stat map for loading
   for (int i = 0; i < profiles.size(); i++) {
      (*profiles[i]->stat_map_to_load).clear();
   }

   // wait until data_process_trap thread finish
   pthread_mutex_lock(&mutex->swap_mutex);
   pthread_mutex_unlock(&mutex->start_processing);

   pthread_exit(NULL);
}

/** 
 * Thread function for process data after stat map swap
 */
void *data_process_trap(void *mutex_map)
{  
   stat_map_mutex_t *mutex = (stat_map_mutex_t*) (mutex_map);

   while (!threads_terminated) {
      // Wait until swap of stat maps
      pthread_mutex_lock(&mutex->start_processing);
      processing_data = true;

      // Get timeslot in string from first profile (if exists)
      string ts; 
      if (profiles.size())
         ts = profiles.front()->current_timeslot;

      // Read configuration
      Configuration *conf = Configuration::getInstance();
      conf->lock();
      bool rules_generic = (conf->getValue("rules-generic") == "1");
      bool rules_ssh = (conf->getValue("rules-ssh") == "1");
      conf->unlock();

      // TODO: run processing of each profile in separate thread
      for (int i = 0; i < profiles.size(); i++) {
         // Skip empty profiles
         if ((*profiles[i]->stat_map_to_check).empty()) {
            continue;
         }

         log(LOG_DEBUG, "Profile \"%s\": Storing ...", profiles[i]->name.c_str());
         profiles[i]->store();
         log(LOG_DEBUG, "Profile \"%s\": Stats stored, running detectors ...", profiles[i]->name.c_str());
         // run all detectors associated with this profile
         if (rules_generic && profiles[i]->name == "all")
            check_rules(profiles[i]);
         if (rules_ssh && profiles[i]->name == "ssh")
            check_rules_ssh(profiles[i]);

         log(LOG_DEBUG, "Profile \"%s\": Detectors done, releasing stats from memory ...", profiles[i]->name.c_str());
         profiles[i]->release();
         log(LOG_INFO, "Processing of profile \"%s\" done.", profiles[i]->name.c_str());
      }

      if (!ts.empty()) {
         log(LOG_INFO, "Processing of timeslot %s done.", ts.c_str());
         last_timeslot = ts;   
      }
      // Processing of timeslot complete - allow to swap stat maps
      pthread_mutex_unlock(&mutex->swap_mutex);
      processing_data = false;
   }

   log(LOG_INFO, "Profiles processing complete.");
   pthread_exit(NULL);
}
