/**
 * \file hoststats.h
 * \brief Definition of statistics about a host
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

#ifndef _HOSTSTATS_H_
#define _HOSTSTATS_H_

#include <stdint.h>

extern "C" {
   #include <unirec/ipaddr.h>
   #include <fast_hash_table.h>
}

/////////////////////////////////////////////////////////////////
// List of subprofiles' data structures
struct ssh_data_t;
struct dns_data_t;

// Record with statistics about a host
struct hosts_record_t {
   // Incomming
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
   uint16_t in_all_psh_cnt;
   uint16_t in_req_psh_cnt;
   uint32_t in_all_ack_cnt;
   uint32_t in_req_ack_cnt;
   uint32_t in_rsp_ack_cnt;
   uint32_t in_all_syn_cnt;
   uint16_t in_all_fin_cnt;
   uint16_t in_all_urg_cnt;
   uint16_t in_req_uniqueips;
   uint16_t in_all_uniqueips;
   uint32_t in_linkbitfield;
   // Outgoing
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
   uint32_t out_all_ack_cnt;
   uint32_t out_req_ack_cnt;
   uint32_t out_rsp_ack_cnt;
   uint32_t out_all_syn_cnt;
   uint32_t out_req_syn_cnt;
   uint32_t out_rsp_syn_cnt;
   uint16_t out_all_fin_cnt;
   uint16_t out_all_urg_cnt;
   uint16_t out_req_uniqueips;
   uint16_t out_all_uniqueips;
   uint32_t out_linkbitfield;
   // Timestamps
   uint32_t first_rec_ts; ///< timestamp of first flow
   uint32_t last_rec_ts;  ///< timestamp of last flow
   // Subprofiles
   ssh_data_t *ssh_data;  ///< SSH subprofile
   dns_data_t *dns_data;  ///< DNS subprofile

   hosts_record_t() { // Constructor sets all values to zeros.
      memset(this, 0, sizeof(hosts_record_t));
   }
};

// key
typedef ip_addr_t hosts_key_t;

// hash table
typedef fht_table_t stat_table_t;

////////////////////////////////////

// BloomFilter key
struct bloom_key_t {
   ip_addr_t src_ip;
   ip_addr_t dst_ip;
   uint16_t rec_time;
} __attribute__((packed));

#endif
