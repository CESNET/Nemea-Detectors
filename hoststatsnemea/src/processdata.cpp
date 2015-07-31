/**
 * \file processdata.cpp
 * \brief TRAP data processing
 * \author Lukas Hutak <xhutak01@stud.fit.vutbr.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2013-2015 CESNET
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

#include <ctime>
#include <csignal>
#include <pthread.h>
#include <unistd.h>
#include "processdata.h"
#include "aux_func.h" // various simple conversion functions
#include "profile.h"

extern "C" {
   #include <libtrap/trap.h>
   #include <unirec/unirec.h>
   #include "fields.h"
}

using namespace std;

// Global variables
extern ur_template_t *tmpl_in;
HostProfile *MainProfile       = NULL; // Global profile
uint32_t hs_time               = 0;

// Status information
static bool processing_data = false;
static bool terminated  = false;    // TRAP terminated by the user
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
   uint32_t flow_time           = 0; // seconds from rec->first

   // Set timeout on input ifc, so we can check whither it is needed to swap BF
   // even if no records are coming
   trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, RECV_TIMEOUT * MSEC);

   while (!end_of_steam && !terminated) {
      const void *data;
      uint16_t data_size;

      // Get new data from TRAP with exception handling
      ret = TRAP_RECEIVE(0, data, data_size, tmpl_in);
      if (ret != TRAP_E_OK) {
         switch (ret) {
         case TRAP_E_TIMEOUT:
            if (flow_time != 0) {
               flow_time += RECV_TIMEOUT;
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
            log(LOG_ERR, "Error: getting new data from TRAP failed: %s",
               trap_last_error_msg);
            terminated = true;
            continue;
         }
      }

      // Check the correctness of recieved data
      if (data_size < ur_rec_fixlen_size(tmpl_in)) {
         if (data_size > 1) {
            log(LOG_ERR, "Error: data with wrong size received (expected size: "
               "%lu, received size: %i.)\nHint: if you are using this module "
               "without flowdirection module change value 'port-flowdir' in "
               "the configuration file (hoststats.conf by default)",
               ur_rec_fixlen_size(tmpl_in), data_size);
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

         next_bf_change = ur_time_get_sec(ur_get(tmpl_in, data, F_TIME_LAST))
            + MainProfile->active_timeout/2;
      }

      flow_time = ur_time_get_sec(ur_get(tmpl_in, data, F_TIME_LAST));

      if (flow_time >= next_bf_change) {
         // Swap/clear BloomFilters
         MainProfile->swap_bf();
         next_bf_change += (MainProfile->active_timeout/2);
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

      MainProfile->check_table(false);

      processing_data = false;
      pthread_mutex_unlock(&det_processing);
   }

   // TRAP CONNECTION CLOSED or TRAP TERMINATED, exiting...
   if (!terminated && end_of_steam) {
      log(LOG_INFO, "Main profile processing ended. Checking the remaining records");
      MainProfile->check_table(true);
   } else {
      log(LOG_INFO, "Main profile processing ended.");
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
      ret = trap_recv(0, data, data_size, tmpl_in);
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
      if (data_size < ur_rec_fixlen_size(tmpl_in)) {
         if (data_size > 1) {
            log(LOG_ERR, "Error: data with wrong size received (expected size: "
               "%lu, received size: %i)", ur_rec_fixlen_size(tmpl_in), data_size);
            return;
         }
         end_of_steam = true;
         break;
      }

      // First flow
      if (flow_time == 0) {
         hs_time = ur_time_get_sec(ur_get(tmpl_in, data, F_TIME_LAST));
         next_bf_change = hs_time + MainProfile->active_timeout/2;
         check_time = hs_time + MainProfile->det_start_time;
      }

      flow_time = ur_time_get_sec(ur_get(tmpl_in, data, F_TIME_LAST));

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
