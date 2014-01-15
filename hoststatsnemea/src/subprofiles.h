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

#ifndef _SUBPROFILES_H_
#define _SUBPROFILES_H_

#include <string>
#include <stdint.h>

#include "config.h"
#include "hoststats.h"
#include "BloomFilter.hpp"

extern "C" {
   #include <unirec/unirec.h>
}

// Type of operations with BloomFilter over 
typedef enum {
   BF_CREATE,
   BF_SWAP,
   BF_DESTROY  
} sp_bf_action;


// Function pointer to update the subprofile
typedef bool (*sp_update)(const ip_addr_t (*)[2],hosts_record_t&, hosts_record_t&, 
   const void *, const ur_template_t *);

// Function pointer to check a record of the subprofile
typedef bool (*sp_check)(const hosts_key_t&, const hosts_record_t&);

// Function pointer to delete the subprofile
typedef bool (*sp_delete)(hosts_record_t&);

// Function pointers to manipulation with subprofile's BloomFilter
typedef void (*sp_bf_config)(sp_bf_action);

// General stucture for subprofile pointers
typedef struct sp_pointers_s {
   sp_update update_ptr;
   sp_check check_ptr;
   sp_delete delete_ptr;
   sp_bf_config bf_config_ptr;
} sp_pointers_t;


// Structure with information about subprofile 
struct subprofile_t{
   std::string name;
   bool sp_status;         // active (1) or inactive (0)
   std::string detector_name;
   bool detector_status;   // active (1) or inactive (0)
   sp_pointers_t pointers;

   // Structure constructor
   subprofile_t(std::string name, std::string detector_name, sp_pointers_t ptr)
   :  name(name), detector_name (detector_name), pointers(ptr)
   {
   }

   // Load status information from configuration file
   void check_config() {
      Configuration *conf = Configuration::getInstance();
      conf->lock();
      sp_status =       (conf->getValue(name) == "1");
      detector_status = (conf->getValue(detector_name) == "1"); 
      conf->unlock();
   }

   // Operator overloading for sorting function
   bool operator<(const subprofile_t &b) const {
      return (sp_status && !b.sp_status) || 
               (sp_status == b.sp_status && detector_status && !b.detector_status);
   }
};

/******************************* DNS subprofile *******************************/
// record structure
struct dns_record_t {
   uint32_t in_dns_flows;
   uint32_t out_dns_flows;

   dns_record_t() {
      memset(this, 0, sizeof(dns_record_t));
   }
} __attribute((packed));

// class
class DNSHostProfile {
private:
   dns_record_t record;

   // Flow filter for update function
   static bool flow_filter(const void *data, const ur_template_t *tmplt);

public:
   // Update a DNS subprofile
   static bool update(const ip_addr_t (*ips)[2], hosts_record_t &src_record, 
      hosts_record_t &dst_record, const void *data, const ur_template_t *tmplt);

   // Check rules in a DNS subprofile
   static bool check_record(const hosts_key_t &key, const hosts_record_t &record);

   // Remove a subprofile from a main profile
   static bool delete_record(hosts_record_t &record);
};

const sp_pointers_t dns_pointers = {
   DNSHostProfile::update,
   DNSHostProfile::check_record,
   DNSHostProfile::delete_record,
   NULL
};

/******************************* SSH subprofile *******************************/
// record structure
struct ssh_record_t {
   uint16_t out_req_packets;
   uint16_t out_rsp_packets;
   uint16_t out_req_syn_cnt;
   uint16_t out_rsp_syn_cnt;
   uint16_t out_all_uniqueips;

   uint16_t in_req_packets;
   uint16_t in_rsp_packets;
   uint16_t in_req_syn_cnt;
   uint16_t in_rsp_syn_cnt;
   uint16_t in_all_uniqueips;

   ssh_record_t() {
      memset(this, 0, sizeof(ssh_record_t));
   }
} __attribute((packed));

// class
class SSHHostProfile {
private:
   // BloomFilters only for all SSH flows
   static bloom_filter *ssh_bf_active;
   static bloom_filter *ssh_bf_learn;

   // Flow filter for update function
   static bool flow_filter(const void *data, const ur_template_t *tmplt);
   
public:
   // SSH record 
   ssh_record_t record;

   // Update a SSH subprofile
   static bool update(const ip_addr_t (*ips)[2], hosts_record_t &src_record, 
      hosts_record_t &dst_record, const void *data, const ur_template_t *tmplt);

   // Check rules in a SSH subprofile
   static bool check_record(const hosts_key_t &key, const hosts_record_t &record);

   // Remove a subprofile from a main profile
   static bool delete_record(hosts_record_t &record);

   // Create/swap/destroy BloomFilters
   static void bloom_filter_config(sp_bf_action arg);
};

const sp_pointers_t ssh_pointers = {
   SSHHostProfile::update,
   SSHHostProfile::check_record,
   SSHHostProfile::delete_record,
   SSHHostProfile::bloom_filter_config
};

#endif