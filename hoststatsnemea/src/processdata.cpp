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
#include <time.h>

#include "processdata.h"
#include "aux_func.h" // various simple conversion functions
// #include "database.h"
#include "wardenreport.h"
#include "eventhandler.h"
#include "detectionrules.h"

extern "C" {
   #include <libtrap/trap.h>
   #include <unirec/unirec.h>
}

using namespace std;

#define SIZEOFTIMESLOT   300
#define GET_DATA_TIMEOUT 1 //seconds
#define MSEC             1000000

///////////////////////////
// Global variables
extern ur_template_t *tmpl_in;
extern ur_template_t *tmpl_out;

// Global profile
HostProfile MainProfile;

pthread_mutex_t detector_start = PTHREAD_MUTEX_INITIALIZER;
uint32_t hs_time               = 0; 

// Status information
bool processing_data = false;
string last_timeslot = "not available in this version";
static bool threads_terminated = 0; // TRAP threads general stop

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

   hs_time = time(NULL);


   if (hs_time % MainProfile.det_start_time != 0) {
      return;
   }

   if (processing_data) {
      log(LOG_DEBUG, "New start of detectors failed. Last start is still in progress.");
      return;
   }

   log(LOG_DEBUG, "Starting detectors.");
   pthread_mutex_unlock(&detector_start);
}



// Detect and change timeslot when new flow data are from next timeslot 
void check_time(uint32_t &next_ts_start, uint32_t &next_bf_change, 
                const uint32_t &current_time)
{
   // BloomFilter swap
   if (current_time >= next_bf_change) {
      MainProfile.swap_bf();
      next_bf_change += (MainProfile.active_timeout/2);
   }

   // Is current time in new timeslot?
   if (!(current_time >= next_ts_start)) {
      return;
   }

   // log (LOG_INFO, "New timeslot: %d", next_ts_start);
   next_ts_start += SIZEOFTIMESLOT;
}

// TODO: add comment
bool record_validity(HostProfile &profile, int index, thread_share_t *share)
{
   // Get record and check timestamps
   const hosts_record_t &rec = profile.get_record_at_index(index);
   if (rec.first_rec_ts + profile.active_timeout > hs_time &&
      rec.last_rec_ts + profile.inactive_timeout > hs_time) {
      return 0;
   }

   // Get key and check validity of record
   const hosts_key_t &key = profile.get_key_at_index(index);
   if (profile.is_valid(key, index) == 0) {
      return 0;
   }

   profile.check_record(key, rec);

   // Add the item to remove to vector
   remove_item_t item = {key};

   pthread_mutex_lock(&share->remove_mutex);
   std::vector<remove_item_t>::iterator it = find(share->remove_vector.begin(),
      share->remove_vector.end(), item);
   if (it == share->remove_vector.end()) {
      share->remove_vector.push_back(item);
   }
   pthread_mutex_unlock(&share->remove_mutex);

   if (share->remove_vector.size() >= 100) {
      share->remove_ready = true;
      sched_yield();
   }

   return 1;
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
         if (ret == TRAP_E_TIMEOUT) {
            if (next_timeslot_start) {
               flow_time += GET_DATA_TIMEOUT;
               check_time(next_timeslot_start, next_bf_change, flow_time);
            }
            continue;
         } else {
            if (ret != TRAP_E_TERMINATED) {
               log(LOG_ERR, "Error: getting new data from TRAP failed: %s)\n",
                  trap_last_error_msg);
            }
            threads_terminated = 1;
            break;
         }
      }

      // Check the correctness of recieved data
      if (data_size < ur_rec_static_size(tmpl_in)) {
         if (data_size > 1) {
            log(LOG_ERR, "Error: data with wrong size received (expected size: %lu,\
               received size: %i)\n", ur_rec_static_size(tmpl_in), data_size);
         }
         threads_terminated = 1;
         break;
      }

      flow_time = ur_time_get_sec(ur_get(tmpl_in, data, UR_TIME_FIRST));

      // Get time of next timeslot start from first flow data
      if (!next_timeslot_start){
         if (flow_time % SIZEOFTIMESLOT == 0) {
            next_timeslot_start = flow_time + SIZEOFTIMESLOT;
         } else {
            next_timeslot_start = static_cast<uint32_t>
               ((flow_time/SIZEOFTIMESLOT + 1)*SIZEOFTIMESLOT);
         }

         // Setup alarm for the activation of a time counter (hs_time) 
         hs_time = time(NULL);
         alarm(1);

         next_bf_change = flow_time + MainProfile.active_timeout/2;
         last_change = flow_time;
      }

      if (flow_time > last_change) {
         last_change = flow_time;
         check_time(next_timeslot_start, next_bf_change, flow_time);
      }

      // Remove old items
      if (share->remove_ready) {
         // TODO: change lock --> try_lock 
         pthread_mutex_lock(&share->remove_mutex);

         while(!share->remove_vector.empty()) {
            remove_item_t &item = share->remove_vector.back();
            MainProfile.remove_by_key(item.key);
            share->remove_vector.pop_back();
         }
         share->remove_ready = false;
         pthread_mutex_unlock(&share->remove_mutex);
      }

      // Update main profile and subprofiles
      MainProfile.update(data, tmpl_in, true);
   }

   // TRAP TERMINATED, exiting... 
   log(LOG_INFO, "Reading from trap terminated.");

   // Wait until the end of the current processing and run it again (to end)
   pthread_mutex_lock(&share->det_processing);
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

   // First lock of this mutex
   pthread_mutex_lock(&detector_start);

   /* alarm signal*/
   signal(SIGALRM, alarm_handler);

   while (!threads_terminated) {
      // Wait on start
      pthread_mutex_lock(&detector_start);

      pthread_mutex_lock(&share->det_processing);
      processing_data = true;

      for (int i = 0; i < MainProfile.get_table_size(); ++i) {
         record_validity(MainProfile, i, share);

         if (threads_terminated) {
            break;
         }
      }

      processing_data = false;
      pthread_mutex_unlock(&share->det_processing);
   }

   // TRAP TERMINATED, exiting... 

   log(LOG_INFO, "Main profile processing terminated.");
   pthread_exit(NULL);
}
