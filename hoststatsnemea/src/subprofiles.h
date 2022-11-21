/**
 * \file subprofiles.h
 * \brief Optional processing of flow data (header file)
 * \author Lukas Hutak <xhutak01@stud.fit.vutbr.cz>
 * \date 2014
 * \data 2015
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

#ifndef _SUBPROFILES_H_
#define _SUBPROFILES_H_

#include <string>
#include <vector>
#include <BloomFilter.hpp> /* BloomFilter from nemea-common */
#include "hoststats.h"
#include "aux_func.h"

extern "C" {
   #include <unirec/unirec.h>
}

class SubprofileBase;

// Typedefs for the vector of pointers on subprofiles
typedef std::vector<SubprofileBase *> sp_list_ptr_v;
typedef sp_list_ptr_v::iterator sp_list_ptr_iter;
typedef sp_list_ptr_v::const_iterator sp_list_ptr_citer;

// Registration of all subprofiles
void register_subprofiles();
// Deregistration of all subprofiles
void unregister_subprofiles();


/** \brief Subprofile base
 * This abstract class is a base for all derived subprofile classes.
 */
class SubprofileBase {
private:
   // Name of subprofile
   std::string sbp_name;
   // Unirec items (template)
   std::string sbp_tmpl;
   // Status of the subprofile
   bool sbp_enabled;
   // Bloom filters pairs
   int sbp_bloom_cnt;

   // Structure for active and learning Bloom Filters
   struct bloom_filters_t {
      bloom_filter *bf_active;
      bloom_filter *bf_learn;
   };
   // BloomFilters
   std::vector<bloom_filters_t> bloom_filters;

public:
   // Constructor
   SubprofileBase(std::string name, std::string tmpl_str, int bloom_filters_cnt = 0);
   // Destructor
   virtual ~SubprofileBase();

   // Name of the subprofile
   std::string get_name() {return sbp_name;};
   // UniRec template of the subprofile
   std::string get_template() {return sbp_tmpl;};
   // Status of the subprofile
   bool is_enabled() {return sbp_enabled;};
   // Disable subprofile
   void disable() {sbp_enabled = false;};
   // Enable subprofile
   void enable() {sbp_enabled = true;};

   // Init BloomFilters
   void bloomfilters_init(int size);
   // Destroy BloomFilters
   void bloomfilters_destroy();
   // Swap BloomFilters
   void bloomfilters_swap();
   // Test whether key is in the set and than insert key
   bool bloomfilters_get_presence(const bloom_key_t &key, int index = 0);

   /** \brief Update a record of source IP address
    * Update the record with new data from TRAP. The record is updated if
    * a flow data belongs to the subprofile. If the record does not exist,
    * new one is created.
    * \param[in,out] main_record Main record to update
    * \param[in] data New data from TRAP
    * \param[in] tmplt Input template
    * \param[in] dir_flags Direction flag (request, response,...)
    * \param[in] ips BloomFilter key
    * \return True when data belongs to the subprofile, false otherwise
    */
   virtual bool update_src_ip(hosts_record_t &main_record, const void *data,
      const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips) = 0;

   /** \brief Update a record of destination IP address
    * See description for #update_src_ip
    */
   virtual bool update_dst_ip(hosts_record_t &main_record, const void *data,
      const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips) = 0;

   /** \brief Check rules in a record
    * Use detection rules only if subprofile exists
    * \param[in] key Key of a record
    * \param[in] record Main record with general statistics
    * \return True, if subprofile exists, false otherwise
    */
   virtual bool check_record(const hosts_key_t &key, const hosts_record_t &record) = 0;

   /** \brief Remove a subprofile from a main profile
    * \param[in,out] record Main record with general statistics
    */
   virtual bool delete_record(hosts_record_t &record) = 0;
};



/******************************* SSH subprofile *******************************/
// SSH record structure
struct ssh_data_t {
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

   ssh_data_t() {
      memset(this, 0, sizeof(ssh_data_t));
   };
};

/** \brief SSH subprofile
 */
class SSHSubprofile : public SubprofileBase {
private:
   // A filter for incomming flows
   bool flow_filter(const void *data, const ur_template_t *tmplt);

public:
   SSHSubprofile();
   ~SSHSubprofile();

   // Definition of required functions
   bool update_src_ip(hosts_record_t &main_record, const void *data,
      const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips);
   bool update_dst_ip(hosts_record_t &main_record, const void *data,
      const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips);
   bool check_record(const hosts_key_t &key, const hosts_record_t &record);
   bool delete_record(hosts_record_t &record);
};

/******************************* DNS subprofile *******************************/
// DNS record structure
struct dns_data_t {
   uint32_t in_rsp_overlimit_cnt;
   uint32_t out_rsp_overlimit_cnt;

   dns_data_t() {
      memset(this, 0, sizeof(dns_data_t));
   }
};

// DNS subprofile
class DNSSubprofile : public SubprofileBase {
private:
   // A threshold for excessive average packet size in flows
   static const unsigned DNS_BYTES_OVERLIMIT = 1000;

   // A filter for incomming flows
   bool flow_filter(const void *data, const ur_template_t *tmplt);

public:
   DNSSubprofile();
   ~DNSSubprofile();

   // Definition of required functions
   bool update_src_ip(hosts_record_t &main_record, const void *data,
      const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips);
   bool update_dst_ip(hosts_record_t &main_record, const void *data,
      const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips);
   bool check_record(const hosts_key_t &key, const hosts_record_t &record);
   bool delete_record(hosts_record_t &record);
};

/* Add your new subprofile here ... */

#endif
