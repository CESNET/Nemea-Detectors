/**
 * \file dns_amplification.h
 * \brief Nemea module for detection of DNS amplification attacks based on NetFlow - header file
 * \author Michal Kovacik <ikovacik@fit.vutbr.cz>, Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 25.10.2013
 */

/*
 * Copyright (C) 2013, 2014 CESNET
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

#include <unirec/unirec.h>
#include <vector>
#include <map>

#ifndef SIMPLE_DNSAMP_DETECTOR_H
#define SIMPLE_DNSAMP_DETECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#define BYTES_MAX 5000  // max bytes of flow checked in q dividing
#define PACKETS      0
#define BYTES     1
#define KEY    0
#define VALUE     1
#define ERROR     -1
#define OK     1

#define LOG_FILE_PREFIX ""
#define LOG_FILE_SUFFIX ".log"

#define BOOL_QUERY false
#define BOOL_RESPONSE true

using namespace std;

enum report_codes{
   DO_NOT_REPORT = 0,
   REPORT_BIG,
   REPORT_COMPLEX,
};

enum direction_codes{// codes and indexes of direction (type)
   QUERY = 0,
   RESPONSE,
   Q_REPORTED,
   R_REPORTED,
};


/**
 * Configuration structure keeping module's settings from parameters
 */
typedef struct config_s {

   int port;      /** port */
   int n;         /** number of topN chosen */
   int min_flows;    /** minimal threshold for number of flows in TOP-N */
   int q;         /** histogram step */
   int min_a;     /** minimal amplification effect considered as attack */
   float min_flows_norm;   /** minimal normalized threshold for count of flows in TOP-N */
   int min_resp_packets;   /** minimal average of response packets in TOP-N */
   int min_resp_bytes;  /** minimal threshold for average size of responses in bytes in TOP-N */
   int max_quer_bytes;  /** maximal threshold for average size of queries in bytes in TOP-N */
   int max_quer_flow_packets; /** maximal threshold for number of packets in one flow for requests */
   int max_quer_flow_bytes;   /** maximal threshold for number of bytes in one flow for requests */
   int max_resp_flow_packets; /** maximal threshold for number of packets in one flow for responses */
   int max_resp_flow_bytes;   /** maximal threshold for number of bytes in one flow for responses */
   int det_window;      /** length of detection window */
   int del_time;     /** length of delete window after detection */

   config_s() {
      port = 53;
      n = 5;
      min_flows = 300;
      q = 2;
      min_a = 10;
      min_flows_norm = 0.9;
      min_resp_packets = 2;
      min_resp_bytes = 2000;
      max_quer_bytes = 400;
      max_quer_flow_packets = 1000;
      max_quer_flow_bytes = 40000;
      max_resp_flow_packets = 1000;
      max_resp_flow_bytes = 100000;
//    det_window = 3600;
//    del_time = 300;
      det_window = 900;
      del_time = 300;
   }

} config_t;


/**
 * Key used for detection history model structure
 */
struct flow_key_t {

   ip_addr_t src; // source ip address
   ip_addr_t dst; // destination ip address

   // operator for comparison in .find()
   bool operator<(const flow_key_t &key2) const {
      return (memcmp((char*)this, (char*)&key2, sizeof(flow_key_t)) < 0);
   }
};


/**
 * Structure of flow item for detection used for each incoming flow to store its stats to history
 */
struct flow_item_t {

   ur_time_t t;   // timestamp of flow
   int bytes;  // bytes in flow
   int packets;   // packets in flow
};


/**
 * Structure of stored flow data in history. For each flow key.
 */
struct flow_data_t {

   vector<flow_item_t> q;     // vector of query flows
   vector<flow_item_t> r;     // vector of response flows
   uint64_t total_bytes [4];     // total bytes of flows
   uint32_t total_packets [4];      // total packets of flows
   uint32_t total_flows [4];     // total number of flows
   ur_time_t first_t;      // timestamp of first flow
   ur_time_t last_t;    // timestamp of last flow - for inactivity detection
   uint32_t identifier;    // unique identifier
   ur_time_t last_logged;     // timestamp of last logged flow
};

/** Map storing history model of flows */
typedef map <flow_key_t, flow_data_t> history_t;
/** History model iterator */
typedef history_t::iterator history_iter;

/** Map storing histogram */
typedef map<unsigned int, unsigned int> histogram_t;
/** Histogram iterator */
typedef histogram_t::iterator histogram_iter;

/** Map storing normalized histogram */
typedef map<unsigned int, float> histogram_norm_t;
/** Normalized histogram iterator */
typedef histogram_norm_t::iterator histogram_norm_iter;

#ifdef __cplusplus
}
#endif

#endif /* SIMPLE_BOTNET_DETECTOR_H */
