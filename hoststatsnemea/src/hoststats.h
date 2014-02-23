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

#ifndef _HOSTSTATS_H_
#define _HOSTSTATS_H_

#include <stdint.h>
#include <string.h>
#include <map>
#include <vector>
#include <pthread.h>

extern "C" {
   #include <unirec/ipaddr.h>
   #include <cuckoo_hash_v2.h>
}

/////////////////////////////////////////////////////////////////
// List of subprofiles
class DNSHostProfile;
class SSHHostProfile;

// Record with statistics about a host
// TODO: update this comment !!! 
struct hosts_record_t {
   uint32_t in_all_flows;
   uint32_t in_req_flows;
   uint32_t in_rsp_flows;
   uint32_t in_all_packets;
   uint32_t in_req_packets;
   uint32_t in_rsp_packets;
   uint32_t in_all_bytes;
   uint16_t in_req_bytes;
   uint16_t in_req_rst_cnt;
   uint16_t in_all_rst_cnt;
   uint16_t in_req_psh_cnt;
   uint16_t in_all_psh_cnt;
   uint16_t in_req_ack_cnt;
   uint16_t in_all_ack_cnt;
   uint16_t in_rsp_ack_cnt;
   uint16_t in_all_syn_cnt;
   uint16_t in_all_fin_cnt;
   uint16_t in_all_urg_cnt;
   uint16_t in_req_uniqueips;
   uint16_t in_all_uniqueips;
   uint32_t in_linkbitfield;

   uint32_t out_all_flows;
   uint32_t out_req_flows;
   uint32_t out_rsp_flows;
   uint32_t out_all_packets;
   uint32_t out_req_packets;
   uint32_t out_rsp_packets;
   uint32_t out_all_bytes;
   uint16_t out_req_bytes;
   uint16_t out_all_rst_cnt;
   uint16_t out_req_rst_cnt;
   uint16_t out_all_psh_cnt;
   uint16_t out_req_psh_cnt;
   uint16_t out_all_ack_cnt;
   uint16_t out_req_ack_cnt;
   uint16_t out_rsp_ack_cnt;
   uint16_t out_all_syn_cnt;
   uint16_t out_req_syn_cnt;
   uint16_t out_rsp_syn_cnt;
   uint16_t out_all_fin_cnt;
   uint16_t out_all_urg_cnt;
   uint16_t out_req_uniqueips;
   uint16_t out_all_uniqueips;
   uint32_t out_linkbitfield;

   uint32_t first_rec_ts; // timestamp of first flow
   uint32_t last_rec_ts;  // timestamp of last flow

   DNSHostProfile *dnshostprofile;
   SSHHostProfile *sshhostprofile;


   hosts_record_t() { // Constructor sets all values to zeros.
      memset(this, 0, sizeof(hosts_record_t));
   }
} __attribute__((packed));


typedef ip_addr_t hosts_key_t;

// hash table
typedef cc_hash_table_v2_t stat_table_t;

// The identification of item to remove from stat_table
typedef struct remove_item_s {
   hosts_key_t key;

   bool operator== (const remove_item_s& second) const
   {
      return (memcmp(&key, &second.key, sizeof(hosts_key_t)) == 0);   
   }
} remove_item_t;

// Shared structure for TRAP reader and process threads
typedef struct thread_share_s {
   pthread_t data_reader_thread;
   pthread_t data_process_thread;
   pthread_mutex_t det_processing;
   pthread_mutex_t remove_mutex;                // to protect remove_vector
   std::vector<remove_item_t> remove_vector;    // items to remove from stat_map
   bool remove_ready;                           // info about remove_vector 

   thread_share_s() { // Constructor
      pthread_mutex_init(&det_processing, NULL);
      pthread_mutex_init(&remove_mutex, NULL);
      remove_vector.reserve(8192);
      remove_ready = false;
   }

   ~thread_share_s() { // Destructor
      pthread_mutex_destroy(&det_processing);
      pthread_mutex_destroy(&remove_mutex);
   }
} thread_share_t;

////////////////////////////////////

// Status information
//TODO: check if this still exists
extern bool processing_data;

#endif
