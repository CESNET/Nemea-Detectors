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
#include <string>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint8_t, uint16_t, uint32_t, uint64_t
#include <time.h>
#include <signal.h>

#include "processdata.h"
#include "aux_func.h" // various simple conversion functions
#include "eventhandler.h"
#include "detectionrules.h"

extern "C" {
   #include <libtrap/trap.h>
   #include <unirec/unirec.h>
}

using namespace std;

#define GET_DATA_TIMEOUT 1 //seconds

HostProfile *MainProfile       = NULL; // Global profile
uint32_t hs_time               = 0; 

// Status information
bool processing_data = false;

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
 * that goes throught the content of hosts stats table with flow records and 
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

   log(LOG_DEBUG, "Starting detectors...");
   pthread_mutex_unlock(&detector_start);
}

/**
 * \brief Start time updater
 * Start automatic update of global variable hs_time with system time for online
 * mode
 */
void start_alarm() 
{
   if (hs_time != 0) {
      return;
   }
   
   hs_time = time(NULL);
   alarm(1);
}

////////////////////////////////////////////////////////////////////////////////
// ONLINE mode
////////////////////////////////////////////////////////////////////////////////

/** 
 * Thread function for get data from TRAP and store them. 
 */
void *data_reader_trap(void *args)
{   
   const hs_in_ifc_spec_t &ifc_spec = *(hs_in_ifc_spec_t *) args;
   int ret;
   
   /* TRAP data and data size */
   const void *data;
   uint16_t data_size;
   
   /* only for first thread (index 0) */
   uint32_t next_bf_change      = 0;
   uint32_t flow_time           = 0; // seconds from rec->first
   
   /* -- begin of main loop -- */
   while (!end_of_steam && !terminated) {
      // Get new data from TRAP with exception handling
      ret = trap_recv(ifc_spec.ifc_index, &data, &data_size);
      if (ret != TRAP_E_OK) {
         switch (ret) {
         case TRAP_E_TIMEOUT:
            /* swap BloomFilters, only one (first) thread can do this */
            if (ifc_spec.ifc_index == 0 && flow_time != 0) {
               flow_time += GET_DATA_TIMEOUT;
               if (flow_time >= next_bf_change) {
                  MainProfile->swap_bf();
                  next_bf_change += (MainProfile->active_timeout/2);
               }
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
      if (data_size < ur_rec_static_size(ifc_spec.tmpl)) {
         if (data_size > 1) {
            log(LOG_ERR, "Error: data with wrong size received on interface "
               "'%s' (expected size: %lu, received size: %i.)\nHint: if you "
               "are using this module without flowdirection module change "
               "value 'port_flowdir' in the configuration file "
               "(hoststats.conf by default)", ifc_spec.name.c_str(),
               ur_rec_static_size(ifc_spec.tmpl), data_size);
            trap_terminate();
            terminated = true;
         }
         end_of_steam = true;
         break;
      }

      // Update data for BloomFilter swapping 
      if (ifc_spec.ifc_index == 0) {
         // First flow
         if (flow_time == 0) {
            next_bf_change = ur_time_get_sec(ur_get(ifc_spec.tmpl, data, 
               UR_TIME_LAST)) + MainProfile->active_timeout/2;
         }
         
         flow_time = ur_time_get_sec(ur_get(ifc_spec.tmpl, data, UR_TIME_LAST));

         if (flow_time >= next_bf_change) {
            // Swap/clear BloomFilters
            MainProfile->swap_bf();
            next_bf_change += (MainProfile->active_timeout/2);
         }
      }

      // Update main profile and subprofiles
      MainProfile->update(data, ifc_spec, true);
   }
   // -- end of main loop --

   // TRAP TERMINATED, exiting... 
   if (ifc_spec.ifc_index == 0) {
      log(LOG_INFO, "Reading from the TRAP ended. Please wait until the "
         "HostStats is finished processing.");

      // Wait until the end of the current processing and run it again
      pthread_mutex_lock(&det_processing);
      pthread_mutex_unlock(&det_processing);
      pthread_mutex_unlock(&detector_start);
   }

   log(LOG_DEBUG, "Input thread '%s' terminated.", ifc_spec.name.c_str());
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

      MainProfile->check_table(false);

      processing_data = false;
      pthread_mutex_unlock(&det_processing);
   }

   // TRAP CONNECTION CLOSED or TRAP TERMINATED, exiting... 
   if (!terminated && end_of_steam) {
      log(LOG_INFO, "Main profile processing ended. Checking the remaining records");
      MainProfile->check_table(true);
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
/*void offline_analyzer()
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
            log(LOG_ERR, "Error: data with wrong size received (expected size: "
               "%lu, received size: %i)", ur_rec_static_size(tmpl_in), data_size);
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
      MainProfile->check_table(false);
      check_time += MainProfile->det_start_time;
   }

   // TRAP CONNECTION CLOSED or TRAP TERMINATED, exiting... 
   if (!terminated && end_of_steam) {
      log(LOG_INFO, "Reading from the TRAP ended. Checking the remaining records.");
      MainProfile->check_table(true);
   }
}
*/
