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
#include <string>

extern "C" {
   #include <unirec/ipaddr.h>
   #include <fast_hash_table.h>
   #include <unirec/unirec.h>
}

/** \brief Generate a name of the subprofile class
 * \param subprofile_name Name of the subprofile
 */
#define SUBPROFILE_CLASS(subprofile_name) \
   subprofile_name ## _host_profile

/** \brief Generate the name of a pointer to the subprofile instance in hosts_record_t
 * \param subprofile_name Name of the subprofile
 */
#define SUBPROFILE_DATA(subprofile_name) \
   subprofile_name ## hostprofile

/** \brief Generate the name of pointer to the functions of the subprofile
 * \param subprofile_name Name of the subprofile
 */
#define SUBPROFILE_POINTERS(subprofile_name) \
   subprofile_name ## _pointers

/////////////////////////////////////////////////////////////////
// List of subprofiles
class SUBPROFILE_CLASS(dns);
class SUBPROFILE_CLASS(ssh);

// Record with statistics about a host
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

   SUBPROFILE_CLASS(dns) *SUBPROFILE_DATA(dns);
   SUBPROFILE_CLASS(ssh) *SUBPROFILE_DATA(ssh);

   hosts_record_t() { // Constructor sets all values to zeros.
      memset(this, 0, sizeof(hosts_record_t));
   }
};


// key
typedef ip_addr_t hosts_key_t;

// hash table
typedef fht_table_t stat_table_t;

// ------------------------------------
// BloomFilter key
struct bloom_key_t {
   ip_addr_t src_ip;
   ip_addr_t dst_ip;
   uint16_t rec_time;
} __attribute__((packed));

// Type of operations with BloomFilter
typedef enum {
   BF_CREATE,
   BF_SWAP,
   BF_DESTROY  
} sp_bf_action;

// ------------------------------------
// Structure of subprofiles - more in subprofile.h
struct subprofile_t;

// Typedefs for the vector of pointers on subprofiles
typedef std::vector<subprofile_t *> sp_list_ptr_v;
typedef sp_list_ptr_v::iterator sp_list_ptr_iter;
typedef sp_list_ptr_v::const_iterator sp_list_ptr_citer;

// Input interface specification
struct hs_in_ifc_spec_t {
   std::string name;          // Name of input interface
   uint32_t ifc_index;        // Index of input interface
   uint32_t ifc_total;        // Total count of input interfaces
   bool port_flowdir;         // Type of flow direction source is this module
   ur_template_t *tmpl;       // Interface template
   sp_list_ptr_v subprofiles; // List of subprofiles to update
};

#endif
