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
#include <unistd.h>

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

#define D_ACTIVE_TIMEOUT   300   // default value (in seconds)
#define D_INACTIVE_TIMEOUT 30    // default value (in seconds)
#define D_DET_START_PAUSE  10    // default time between starts of detector (in seconds)

const uint64_t MEMORY_LIMIT = 2LL*1024LL*1024LL*1024LL; // Maximum number of bytes consumed by host-stats (2GB)
const uint64_t MAX_NUM_OF_HOSTS = MEMORY_LIMIT / sizeof(hosts_record_t);

///////////////////////////
// Global variables
extern ur_template_t *tmpl_in;
extern ur_template_t *tmpl_out;

uint32_t active_timeout        = D_ACTIVE_TIMEOUT;
uint32_t inactive_timeout      = D_INACTIVE_TIMEOUT;
static uint32_t det_start_time = D_DET_START_PAUSE; // time between the starts of detector

pthread_mutex_t detector_start = PTHREAD_MUTEX_INITIALIZER;
uint32_t hs_time               = 0; 

// Status information
bool processing_data = false;
string last_timeslot = "none";
static bool threads_terminated = 0; // Threads for stat maps

/////////////////////////////////////////
// Host stats processing functions

void alarm_handler(int signal)
{
   if (signal != SIGALRM) {
      return;
   }

   if (!threads_terminated) {
      alarm(1);   
   }

   ++hs_time;

   if (hs_time % det_start_time != 0) {
      return;
   }

   if (processing_data) {
      log(LOG_DEBUG, "New start of detectors failed. Last start is still in progress.");
      return;
   }

   log(LOG_DEBUG, "Starting detectors.");
   pthread_mutex_unlock(&detector_start);
}

/**
 * UpdateStatsRecord()
 * Update records in the stat_map by data form a given flow.
 *
 * Find two host records acoording to source and destination address of the
 * flow and update these records
 *
 * @param flow_key Key of the flow.
 * @param flow_rec Record of the flow.
 * @param flow_time Time for info about add/upload flow record
 * @param bf Bloom filter used to approximate uniqueips statistic
 */
void UpdateStatsRecord(stat_map_t &stat_map, const flow_key_t &flow_key, 
                       const flow_record_t &flow_rec,
                       bloom_filter *bf_active, bloom_filter *bf_learn) {
   // find/add record in bloom filter
   ip_addr_t bkey[2] = {flow_key.sad, flow_key.dad};
   bool present = false;
   present = bf_active->containsinsert((const unsigned char *) bkey, 32);
   bf_learn->insert((const unsigned char *) bkey, 32);
   
   hosts_key_t src_host_key = flow_key.sad;
   hosts_key_t dst_host_key = flow_key.dad;

   hosts_record_t& src_host_rec = stat_map[src_host_key];
   hosts_record_t& dst_host_rec = stat_map[dst_host_key];

   // source --------------------------------------------------------
   if (!src_host_rec.in_flows && !src_host_rec.out_flows)
      src_host_rec.first_record_timestamp = hs_time;

   src_host_rec.last_record_timestamp = hs_time;

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

   // destination ---------------------------------------------------
   if (!dst_host_rec.in_flows && !dst_host_rec.out_flows)
      dst_host_rec.first_record_timestamp = hs_time;

   dst_host_rec.last_record_timestamp = hs_time;

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

/////////////////////////////////////////////////////////////////
// NEW FUNCTIONS FOR DATA FROM TRAP
void new_trap_data(const void *record)
{
   flow_key_t flow_key;

   flow_key.sad = ur_get(tmpl_in, record, UR_SRC_IP);
   flow_key.dad = ur_get(tmpl_in, record, UR_DST_IP);

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


// Detect and change timeslot when new flow data are from next timeslot 
void check_time(uint32_t &next_ts_start, uint32_t &next_bf_change, const uint32_t &current_time)
{
   // BloomFilter swap
   if (current_time > next_bf_change - 1) {
      for (int i = 0; i < profiles.size(); i++) {
         profiles[i]->swap_bf();
      }
      next_bf_change += (active_timeout/2);
   }

   // Is current time in new timeslot?
   if (!(current_time > next_ts_start - 1)) {
      return;
   }

   // Finished timeslot
   time_t temp = next_ts_start - SIZEOFTIMESLOT;
   struct tm *timeinfo = localtime(&temp);
   char buff[13]; //12 signs + '/0'
   strftime(buff, 13, "%4Y%2m%2d%2H%2M", timeinfo);
   last_timeslot = string(buff);

   // Store to new timeslot
   temp = next_ts_start;
   timeinfo = localtime(&temp);
   strftime(buff, 13, "%4Y%2m%2d%2H%2M", timeinfo);
   string st_timeslot = string(buff);

   for (int i = 0; i < profiles.size(); i++) {
      //TODO: what happens when change_timeslot changes the value during storing of data
      profiles[i]->change_timeslot(st_timeslot);
   }

   log (LOG_INFO, "Storing data to new timeslot: %d", next_ts_start);
   next_ts_start += SIZEOFTIMESLOT;
}

/////////////////////////////////////////////////////////////
// Threads

/** 
 * Thread function for get data from TRAP and store them. 
 */
void *data_reader_trap(void *share_struct)
{
   int ret;
   thread_share_t *share = (thread_share_t*) (share_struct);
   uint32_t next_timeslot_start = 0;
   uint32_t next_bf_change      = 0;
   uint32_t last_change         = 0; 
   uint32_t flow_time           = 0; // seconds from rec->first
   
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
            if (next_timeslot_start) {
               flow_time += GET_DATA_TIMEOUT;
               check_time(next_timeslot_start, next_bf_change, flow_time);
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

      flow_time = ur_get(tmpl_in, data, UR_TIME_FIRST) >> 32;

      // Get time of next timeslot start from first flow data
      if (!next_timeslot_start){
         if (flow_time % SIZEOFTIMESLOT == 0) {
            next_timeslot_start = flow_time + SIZEOFTIMESLOT;
         } else {
            next_timeslot_start = static_cast<uint32_t>((flow_time/SIZEOFTIMESLOT + 1)*SIZEOFTIMESLOT);
         }

         // Setup alarm for the activation of time counter (hs_time)  
         alarm(1);
         cout << "aktivuji alarm" << endl;

         next_bf_change = flow_time + active_timeout/2;
         last_change = flow_time;
         log (LOG_INFO, "Next time of change store file: %d", next_timeslot_start);
      }

      if (flow_time > last_change) {
         last_change = flow_time;
         check_time(next_timeslot_start, next_bf_change, flow_time);
      }

      // Store new data
      new_trap_data(data);
   }

   // TRAP TERMINATED, exiting... 
   log(LOG_INFO, "Reading from trap terminated.");

   // Wait until end of current processing
   pthread_mutex_lock(&share->det_processing);

   // TODO: mapy bude mazat až končící kontrolní vlákno, protože i při skončení
   //       čtení se bude kontrolovat obsah dat...
   // Clear all profiles stat map for loading
   for (int i = 0; i < profiles.size(); i++) {
      (*profiles[i]->stat_map_to_check).clear();
   }
   pthread_mutex_unlock(&share->det_processing);
   pthread_mutex_unlock(&detector_start);

   pthread_exit(NULL);
}

/** 
 * Thread function for process data after stat map swap
 */
void *data_process_trap(void *share_struct)
{  
   thread_share_t *share = (thread_share_t*) (share_struct);

   // TODO: check configuration on every start of detector
   // Check configuration
   Configuration *conf = Configuration::getInstance();
   conf->lock();
   active_timeout = atoi(conf->getValue("timeout-active").c_str());
   inactive_timeout = atoi(conf->getValue("timeout-inactive").c_str());
   det_start_time = atoi(conf->getValue("detectors-starts-pause").c_str());
   bool rules_generic = (conf->getValue("rules-generic") == "1");
   bool rules_ssh = (conf->getValue("rules-ssh") == "1");
   conf->unlock();

   if (det_start_time <= 0)   det_start_time   = D_DET_START_PAUSE;
   if (active_timeout <= 0)   active_timeout   = D_ACTIVE_TIMEOUT;
   if (inactive_timeout <= 0) inactive_timeout = D_INACTIVE_TIMEOUT;
   
   /* alarm signal*/
   signal(SIGALRM, alarm_handler);

   while (!threads_terminated) {
      // Wait until swap of stat maps
      pthread_mutex_lock(&detector_start);

      pthread_mutex_lock(&share->det_processing);
      processing_data = true;

      // TODO: run processing of each profile in separate thread
      for (int i = 0; i < profiles.size(); i++) {
         // Skip empty profiles
         if ((*profiles[i]->stat_map_to_check).empty()) {
            continue;
         }

         //log(LOG_DEBUG, "Profile \"%s\": Storing ...", profiles[i]->name.c_str());
         //profiles[i]->store(); //WARNING: before uncomment, check timeslot string
         //log(LOG_DEBUG, "Profile \"%s\": Stats stored, running detectors ...", profiles[i]->name.c_str());

         // run all detectors associated with this profile
         if (rules_generic && profiles[i]->name == "all")
            check_rules(profiles[i]);
         if (rules_ssh && profiles[i]->name == "ssh")
            check_rules_ssh(profiles[i]);

         //log(LOG_DEBUG, "Profile \"%s\": Detectors done", profiles[i]->name.c_str());
      }

      // Processing of timeslot complete - allow to swap stat maps
      processing_data = false;
      pthread_mutex_unlock(&share->det_processing);
   }

   log(LOG_INFO, "Profiles processing complete.");
   pthread_exit(NULL);
}
