/**
 * \file dns_amplification.h
 * \brief Nemea module for detection of DNS amplification attacks based on NetFlow - header file
 * \author Michal Kovacik <ikovacik@fit.vutbr.cz>#
 * \date 25.10.2013
 */

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

#include "../../unirec/unirec.h"
#include <vector>
#include <map>

#ifndef SIMPLE_DNSAMP_DETECTOR_H
#define SIMPLE_DNSAMP_DETECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#define BYTES_MAX 	5000
#define QUERY		0
#define RESPONSE	1
#define PACKETS		0
#define BYTES		1
#define ERROR 		-1
#define OK 		1

using namespace std;

/**
 * Configuration structure keeping module's settings from parameters
 */
typedef struct config_s {
    int port;			/** port */
    int n;			/** number of topN chosen */
    int min_flows;		/** minimal threshold for number of flows in TOP-N */
    int q;			/** histogram step */
    int min_a;			/** minimal amplification effect considered as attack */
    float min_flows_norm;	/** minimal normalized threshold for count of flows in TOP-N */
    int min_resp_packets;	/** minimal average of response packets in TOP-N */
    int min_resp_bytes;		/** minimal threshold for average size of responses in bytes in TOP-N */
    int max_quer_bytes;		/** maximal threshold for average size of queries in bytes in TOP-N */
    int det_window;		/** length of detection window */
    int del_time;		/** length of delete window after detection */
} config_t;


/**
 * Key used for detection structure
 */
struct flow_key_t {
    ip_addr_t src;
    ip_addr_t dst;
    
    // operator for comparison in .find()
    bool operator<(const flow_key_t &key2) const {
	    return (memcmp((char*)this, (char*)&key2, sizeof(flow_key_t)) < 0);
    }
};


/**
 * Structure of flow item for detection
 */
struct flow_item_t {
    ur_time_t t;
    int bytes;
    int packets;
};


/**
 * Structure of stored flow data in history
 */
struct flow_data_t {
    vector<flow_item_t> q;
    vector<flow_item_t> r;
    int total_bytes;
    int total_packets;
    ur_time_t first_t;
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
