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

#ifndef _REQUESTHANDLERS_H_
#define _REQUESTHANDLERS_H_
// Functions for handling requests from frontend

#include <string>

////////////////////////////////////////////////////
// Request codes
#define NEW_DATA 1   // message called when new data are available

#define GET_STATUS 10 // get basic statistics about program (time, flows & host loaded, etc.)
#define GET_HOST_CNT_HISTORY 11 // get history of number of hosts
#define GET_FLOW_CNT_HISTORY 12 // get history of number of flows

#define GET_PROFILES 20 // get list of available profiles

#define GET_FIELD_LIST 30 // get list of fields of a record
#define GET_TIMESLOT_DATA 31 // get stats about all addresses from a given timeslot
#define GET_TIMESLOT_IPMAP 32 // get stats aggregated by given prefix to create an IP map
#define GET_HOST_HISTORY 35 // get all records of one host in given time range

#define GET_DETECTION_LOG_LIST 40 // get list of available detection log files
#define GET_DETECTION_LOG 41 // get contents of detection log file



// Request handler functions
std::string get_status(const std::string &params);
std::string get_flow_cnt_history(const std::string &params);
std::string get_host_cnt_history(const std::string &params);
std::string get_profiles(const std::string &params);
std::string get_field_list(const std::string &params);
std::string get_timeslot(const std::string &params);
std::string get_timeslot_ipmap(const std::string &params);
std::string get_host_history(const std::string &params);
std::string get_detection_log_list(const std::string &params);
std::string get_detection_log(const std::string &params);

// Pointer to request handler function
typedef std::string (*request_handler_p)(const std::string& params);

// Table mapping request codes to handler functions
const request_handler_p request_handlers[] = {
   0,                      // 0 unused
   0,                      // 1 (NEW_DATA) handled specially
   0,0,0,0,0,0,0,0,        // 2-9 unused
   get_status,             // 10
   get_host_cnt_history,   // 11
   get_flow_cnt_history,   // 12
   0,0,0,0,0,0,0,          // 13-19 unused
   get_profiles,           // 20
   0,0,0,0,0,0,0,0,0,      // 21-29 unused
   get_field_list,         // 30
   get_timeslot,           // 31
   get_timeslot_ipmap,     // 32
   0,0,                    // 33-34
   get_host_history,       // 35
   0,0,0,0,                // 36-39 unused
   get_detection_log_list, // 40
   get_detection_log,      // 41
};
const int num_request_handlers = sizeof(request_handlers) / sizeof(request_handler_p);

#endif
