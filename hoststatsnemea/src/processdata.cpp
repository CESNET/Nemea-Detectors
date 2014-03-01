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
#include <signal.h>

#include "processdata.h"
#include "aux_func.h" // various simple conversion functions
// #include "database.h"
#include "eventhandler.h"
#include "detectionrules.h"

extern "C" {
   #include <libtrap/trap.h>
   #include <unirec/unirec.h>
}

using namespace std;

#define GET_DATA_TIMEOUT 1 //seconds
#define MSEC             1000000

// Global variables
extern ur_template_t *tmpl_in;
extern ur_template_t *tmpl_out;
extern bool offline_mode;

HostProfile *MainProfile       = NULL; // Global profile
uint32_t hs_time               = 0; 

// Status information
bool processing_data = false;
string last_timeslot = "not available in this version";

static bool terminated  = false;     // TRAP terminated by the user
static bool end_of_steam = false;   // TRAP the end of stream (no new data)

// only for ONLINE mode
static pthread_mutex_t detector_start = PTHREAD_MUTEX_INITIALIZER; 
static pthread_mutex_t det_processing = PTHREAD_MUTEX_INITIALIZER;

/////////////////////////////////////////
// Host stats processing functions

/** \brief Signal alarm handling
 * Use only in ONLINE mode!
 * Based on the alarm signal runs in regular (user defined) intervals thread
 * that goes throught the content of cuckoo hash table with flow records and 
 * checks flow validity.
 *
 * \param signal Signal for processing
 */
void alarm_handler(int signal)
{
   if (signal != SIGALRM) {
      return;
   }

   if (end_of_steam || terminated) {
      return;
   }

   alarm(1);   
   hs_time = time(NULL);

   if (hs_time % MainProfile->det_start_time != 0) {
      return;
   }

   if (processing_data) {
      log(LOG_DEBUG, "New start of detectors failed. Last start is still in progress.");
      return;
   }

   log(LOG_DEBUG, "Starting detectors.");
   pthread_mutex_unlock(&detector_start);
}

/** \breif Check all flow records in table
 * If a record is valid and it is in the table longer than a specified 
 * time or has not been updated for specified time then the record is 
 * checked by detectors and invalidated. 
 * Warning: using global variable "offline_mode" to change behavior. 
 *    If offline_mode is true, removes old records directly, otherwise stores 
 *    records to the old_rec_list in MainProfile.
 * \param check_all If true, ignore time and check every valid flow
 */
void check_flow_table(bool check_all) 
{
   for (int index = 0; index < MainProfile->get_table_size(); ++index) {
      if (terminated) {
         break;
      }

      // Get record and check timestamps
      const hosts_record_t &rec = MainProfile->get_record_at_index(index);
      if (!check_all &&
         rec.first_rec_ts + MainProfile->active_timeout > hs_time &&
         rec.last_rec_ts + MainProfile->inactive_timeout > hs_time) {
         continue;
      }

      // Get key and check validity of record
      const hosts_key_t &key = MainProfile->get_key_at_index(index);
      if (MainProfile->is_valid(key, index) == 0) {
         continue;
      }

      MainProfile->check_record(key, rec);

      if (!offline_mode) {
         // ONLINE MODE
         // Add the item to remove to vector
         MainProfile->old_rec_list_insert(key);
      } else {
         // OFFLINE MODE
         // Delete item immediately
         MainProfile->remove_by_key(key);
      }
   }

   // no new items for now... remove all
   if (!offline_mode) {
      MainProfile->set_old_rec_ready();
   }
}

////////////////////////////////////////////////////////////////////////////////
// ONLINE mode
////////////////////////////////////////////////////////////////////////////////

/** 
 * Thread function for get data from TRAP and store them. 
 */
void *data_reader_trap(void *args)
{
   int ret;
   uint32_t next_bf_change      = 0;
   uint32_t last_change         = 0; 
   uint32_t flow_time           = 0; // seconds from rec->first
   
   while (!end_of_steam && !terminated) {
      const void *data;
      uint16_t data_size;

      // Get new data from TRAP with exception catch
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, GET_DATA_TIMEOUT * MSEC);
      if (ret != TRAP_E_OK) {
         switch (ret) {
         case TRAP_E_TIMEOUT:
            if (flow_time != 0) {
               flow_time += GET_DATA_TIMEOUT;
               if (flow_time >= next_bf_change) {
                  MainProfile->swap_bf();
                  next_bf_change += (MainProfile->active_timeout/2);
               }
               MainProfile->old_rec_list_clean();
            }
            continue;
         case TRAP_E_TERMINATED:
            terminated = true;
            continue;
         default:
            log(LOG_ERR, "Error: getting new data from TRAP failed: %s)\n",
               trap_last_error_msg);
            terminated = true;
            continue;
         }
      }

      // Check the correctness of recieved data
      if (data_size < ur_rec_static_size(tmpl_in)) {
         if (data_size > 1) {
            log(LOG_ERR, "Error: data with wrong size received (expected size: %lu,\
               received size: %i)\n", ur_rec_static_size(tmpl_in), data_size);
            terminated = true;
         }
         end_of_steam = true;
         break;
      }

      // First flow
      if (flow_time == 0) {
         // Get time and setup alarm
         hs_time = time(NULL);
         alarm(1);

         last_change = ur_time_get_sec(ur_get(tmpl_in, data, UR_TIME_LAST));
         next_bf_change = last_change + MainProfile->active_timeout/2;
      }

      flow_time = ur_time_get_sec(ur_get(tmpl_in, data, UR_TIME_LAST));

      if (flow_time > last_change) {
         last_change = flow_time;
         if (flow_time >= next_bf_change) {
            // Swap/clear BloomFilters
            MainProfile->swap_bf();
            next_bf_change += (MainProfile->active_timeout/2);
         }
      }

      // Remove old records (prepared by the checking thread)
      if (MainProfile->is_old_rec_list_ready()) {
         MainProfile->old_rec_list_clean();
      }

      // Update main profile and subprofiles
      MainProfile->update(data, tmpl_in, true);
   }

   // TRAP TERMINATED, exiting... 
   log(LOG_INFO, "Reading from the TRAP ended.");

   // Wait until the end of the current processing and run it again (to end)
   pthread_mutex_lock(&det_processing);
   pthread_mutex_unlock(&det_processing);
   pthread_mutex_unlock(&detector_start);

   pthread_exit(NULL);
}


/** 
 * Thread for check validity of flow records
 */
void *data_process_trap(void *args)
{  
   // First lock of this mutex
   pthread_mutex_lock(&detector_start);

   /* alarm signal handler */
   signal(SIGALRM, alarm_handler);

   while (!end_of_steam && !terminated) {
      // Wait on start
      pthread_mutex_lock(&detector_start);
      pthread_mutex_lock(&det_processing);
      processing_data = true;

      check_flow_table(false);

      processing_data = false;
      pthread_mutex_unlock(&det_processing);
   }

   // TRAP CONNECTION CLOSED or TRAP TERMINATED, exiting... 
   if (!terminated && end_of_steam) {
      log(LOG_INFO, "Main profile processing ended. Checking the remaining records");
      check_flow_table(true);
   } else {
      log(LOG_INFO, "Main profile processing terminated.");
   }

   pthread_exit(NULL);
}

////////////////////////////////////////////////////////////////////////////////
// OFFLINE mode
////////////////////////////////////////////////////////////////////////////////

/** \brief Analysis of already captured data in Offline mode
 * Simulates the activity of two threads (manipulating and cheching) used in
 * online mode. Reads data from the TRAP and after a specified period of time 
 * based on time of the incoming flows (unreal time), suspend reading from 
 * the TRAP and checks flow table for suspicious behavior. Then resume reading 
 * from TRAP and this is repeated until a stream ends.
 */
void offline_analyzer()
{
   int ret;
   uint32_t next_bf_change      = 0;
   uint32_t flow_time           = 0; // seconds from rec->last
   uint32_t check_time          = 0;
   
   while (!end_of_steam && !terminated) {
      const void *data;
      uint16_t data_size;

      // Get new data from TRAP with exception catch
      ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      if (ret != TRAP_E_OK) {
         switch (ret) {
         case TRAP_E_TERMINATED:
            terminated = true;
            continue;
         default:
            log(LOG_ERR, "Error: getting new data from TRAP failed: %s)\n",
               trap_last_error_msg);
            return;
         }
      }

      // Check the correctness of recieved data
      if (data_size < ur_rec_static_size(tmpl_in)) {
         if (data_size > 1) {
            log(LOG_ERR, "Error: data with wrong size received (expected size: %lu,\
               received size: %i)\n", ur_rec_static_size(tmpl_in), data_size);
            return;
         }
         end_of_steam = true;
         break;
      }

      // First flow
      if (flow_time == 0) {
         hs_time = ur_time_get_sec(ur_get(tmpl_in, data, UR_TIME_LAST));
         next_bf_change = hs_time + MainProfile->active_timeout/2;
         check_time = hs_time + MainProfile->det_start_time;
      }

      flow_time = ur_time_get_sec(ur_get(tmpl_in, data, UR_TIME_LAST));

      if (flow_time > hs_time) {
         hs_time = flow_time;
         if (flow_time >= next_bf_change) {
            MainProfile->swap_bf();
            next_bf_change += (MainProfile->active_timeout/2);
         }
      }

      // Update main profile and subprofiles
      MainProfile->update(data, tmpl_in, true);

      if (hs_time < check_time) {
         // Get new data from TRAP 
         continue;
      }

      // Check records in table
      check_flow_table(false);
      check_time += MainProfile->det_start_time;
   }

   // TRAP CONNECTION CLOSED or TRAP TERMINATED, exiting... 
   if (!terminated && end_of_steam) {
      log(LOG_INFO, "Reading from the TRAP ended. Checking the remaining records.");
      check_flow_table(true);
   }
}