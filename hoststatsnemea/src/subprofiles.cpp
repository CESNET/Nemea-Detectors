/**
 * \file subprofiles.cpp
 * \brief Optional processing of flow data
 * \author Lukas Hutak <xhutak01@stud.fit.vutbr.cz>
 * \date 2014
 * \date 2015
 */
/*
 * Copyright (C) 2013,2014 CESNET
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

#include "subprofiles.h"
#include "detectionrules.h"


/* HOW TO ADD NEW SUBPROFILE:
 * 1) In subprofiles.h create new class derived from class "SubprofileBase".
 *    This class must consists of 4 required functions from base class:
 *       - update_src_ip(...)
 *       - update_dst_ip(...)
 *       - check_record(...)
 *       - delete record(...)
 *    Also define data structure for statistic record about a host.
 *
 * 2) In hoststats.h add a declaration of data structure to "List of
 *    subprofiles's data structures".
 *    Then append struct hosts_record_t with new line:
 *       <data_structure> *<structure_id>;
 *
 * 3) In subprofile.cpp (this file) find function "register_subprofiles()" and
 *    add your subprofile to the list of available subprofiles.
 *
 *    Then add definition of required class functions of your subprofile.
 *    The constructor/destructor of the class is called on start/exit of
 *    this module.
 *    Keep in mind that the constructor of subprofile class use base class
 *    constructor to specify:
 *       - name of the subprofile
 *       - required UniRec template
 *       - number of required BloomFilters (optional)
 *    Note: check_record() function is a function with detector of a suspicious
 *       behavior. You should add this function to detection_rules.cpp(/.h).
 * 
 * 4) In a configuration file add value "rules-<name_of_subprofile> = 1" to
 *    enable your new subprofile. You can easily deactivate it by value
 *    "rules-<name> = 0".
 * 
 * Note: There are two sample subprofiles (SSH and DNS) where you can inspire...
 */

/**************************** Subprofile registration *************************/
// Global list of all subprofiles
sp_list_ptr_v subprofile_list;

/** \brief Registration of all subprofiles */
void register_subprofiles() {
   // DNS subprofile
   subprofile_list.push_back(new DNSSubprofile());   
   // SSH subprofile
   subprofile_list.push_back(new SSHSubprofile());
   // Add here your new subprofile...
}

/** \brief Deregistration of all subprofiles */
void unregister_subprofiles() {
   while(!subprofile_list.empty()) {
      delete subprofile_list.back();
      subprofile_list.pop_back();
   }
}

// Macros
#define ADD(dst, src) \
   safe_add(dst, src);

#define INC(value) \
   safe_inc(value);


/***************************** Base class definition **************************/

/** \brief Abstract class constructor
 * \param[in] name Name of new subprofile
 * \param[in] tmpl_str Required UniRec items
 * \param[in] bloom_filters_cnt A number of required BloomFilter pairs
 */
SubprofileBase::SubprofileBase(std::string name, std::string tmpl_str, 
   int bloom_filters_cnt)
{
   sbp_enabled = false;
   sbp_name = trim(name);
   sbp_tmpl = trim(tmpl_str);
   sbp_bloom_cnt = bloom_filters_cnt;
   
   log(LOG_DEBUG, "Subprofile '%s' created.", sbp_name.c_str());
}

/** \brief Abstract class destructor
 */
SubprofileBase::~SubprofileBase()
{
   bloomfilters_destroy();
   log(LOG_DEBUG, "Subprofile '%s' destroyed.", sbp_name.c_str());
}

/** \brief Initialization of BloomFilters
 * Create new instances of BloomFilters with specified size
 * \param[in] size Size of each BloomFilter
 */
void SubprofileBase::bloomfilters_init(int size)
{
   if (sbp_bloom_cnt <= 0) {
      // No bloomfilters required
      return;
   }
   
   // Create BloomFilters
   bloom_parameters bp;
   bp.projected_element_count = size;
   bp.false_positive_probability = 0.01;
   bp.compute_optimal_parameters();
   
   for (int i = 0; i < sbp_bloom_cnt; ++i) {
      bloom_filters_t pair;
      pair.bf_active = new bloom_filter(bp);
      pair.bf_learn = new bloom_filter(bp);
      bloom_filters.push_back(pair);
   }
}

/** \brief Destruction of BloomFilters
 */
void SubprofileBase::bloomfilters_destroy() {
   while (!bloom_filters.empty()) {
      bloom_filters_t &pair = bloom_filters.back();
      delete pair.bf_active;
      delete pair.bf_learn;
      bloom_filters.pop_back();
   }
}

/** \brief Swap BloomFilters
 * Clear active BloomFilter and swap active and learning BloomFilter.
 */
void SubprofileBase::bloomfilters_swap()
{
   std::vector<bloom_filters_t>::iterator it = bloom_filters.begin();
   while (it != bloom_filters.end()) {
      it->bf_active->clear();
      bloom_filter *tmp = it->bf_active;
      it->bf_active = it->bf_learn;
      it->bf_learn = tmp;
      ++it;
   }
}

/** \brief Test whether key is in the set and than insert key
 * 
 * \param[in] key Key
 * \param[in] index Index of BloomFilter pair according to the number of pairs
 * defined in the constructor (0th pair by default).
 * \return True if key is known, otherwise false.
 */
bool SubprofileBase::bloomfilters_get_presence(const bloom_key_t &key, int index) {
   bloom_filters_t &filter = bloom_filters[index];
   bool status = filter.bf_active->containsinsert((const unsigned char *) &key,
      sizeof(bloom_key_t));
   filter.bf_learn->insert((const unsigned char *) &key, sizeof(bloom_key_t));
   return status;
}


/******************************* SSH subprofile *******************************/
// Constructor
SSHSubprofile::SSHSubprofile() : SubprofileBase("ssh", "<COLLECTOR_FLOW>", 1)
{
}

// Destructor
SSHSubprofile::~SSHSubprofile()
{
}

// Flow filter
bool SSHSubprofile::flow_filter(const void* data, const ur_template_t* tmplt)
{
   return (ur_get(tmplt, data, UR_PROTOCOL) == 6
      && (
         ur_get(tmplt, data, UR_SRC_PORT) == 22 ||
         ur_get(tmplt, data, UR_DST_PORT) == 22
      ));
}

// Update a record of source IP address
bool SSHSubprofile::update_src_ip(hosts_record_t &main_record, const void *data,
   const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips)
{
   /* Flow filter and record creator */
   if (!flow_filter(data, tmplt)) {
      return 0;
   }
   if (main_record.ssh_data == NULL) {
      main_record.ssh_data = new ssh_data_t;
   }

   /* Update items */
   bool src_present = bloomfilters_get_presence(ips);
   uint8_t tcp_flags = ur_get(tmplt, data, UR_TCP_FLAGS);
   ssh_data_t &src_host_rec = *main_record.ssh_data;
   
   if (!src_present) INC(src_host_rec.out_all_uniqueips);
   
   if (dir_flags & UR_DIR_FLAG_REQ) {
      // request flows
      ADD(src_host_rec.out_req_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & UR_TCP_SYN) INC(src_host_rec.out_req_syn_cnt);
   } else if (dir_flags & UR_DIR_FLAG_RSP) {
      // respose flows
      ADD(src_host_rec.out_rsp_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & UR_TCP_SYN) INC(src_host_rec.out_rsp_syn_cnt);
   }
   return 1;
}

// Update a record of destination IP address
bool SSHSubprofile::update_dst_ip(hosts_record_t &main_record, const void *data,
   const ur_template_t *tmplt, uint8_t dir_flags, const bloom_key_t &ips)
{
   /* Flow filter and record creator */
   if (!flow_filter(data, tmplt)) {
      return 0;
   }
   if (main_record.ssh_data == NULL) {
      main_record.ssh_data = new ssh_data_t;
   }

   /* Update items */
   bool dst_present = bloomfilters_get_presence(ips);
   uint8_t tcp_flags = ur_get(tmplt, data, UR_TCP_FLAGS);
   ssh_data_t &dst_host_rec = *main_record.ssh_data;
   
   if (!dst_present) INC(dst_host_rec.in_all_uniqueips);

   if (dir_flags & UR_DIR_FLAG_REQ) {
      // request flows
      ADD(dst_host_rec.in_req_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & UR_TCP_SYN) INC(dst_host_rec.in_req_syn_cnt);
   } else if (dir_flags & UR_DIR_FLAG_RSP) {
      // respose flows
      ADD(dst_host_rec.in_rsp_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & UR_TCP_SYN) INC(dst_host_rec.in_rsp_syn_cnt);
   }
   return 1;
}

// Check rules in a record
bool SSHSubprofile::check_record(const hosts_key_t &key, const hosts_record_t &record)
{
   if (record.ssh_data == NULL) {
      return 0;  
   }
   
   check_new_rules_ssh(key, record);
   return 1;
}

// Delete record
bool SSHSubprofile::delete_record(hosts_record_t &record)
{
   if (record.ssh_data == NULL) {
      return 0;
   } else {
      delete record.ssh_data;
      return 1;
   }
}

/******************************* DNS subprofile *******************************/
// Constructor
DNSSubprofile::DNSSubprofile() : SubprofileBase("dns", "<COLLECTOR_FLOW>")
{
}

// Destructor
DNSSubprofile::~DNSSubprofile()
{
}

// Flow filter
bool DNSSubprofile::flow_filter(const void* data, const ur_template_t* tmplt)
{
   return ((ur_get(tmplt, data, UR_PROTOCOL) == 6  ||
            ur_get(tmplt, data, UR_PROTOCOL) == 17)
            &&
           (ur_get(tmplt, data, UR_SRC_PORT) == 53 ||
            ur_get(tmplt, data, UR_DST_PORT) == 53));
}

// Update a record of source IP address
bool DNSSubprofile::update_src_ip(hosts_record_t& main_record, const void* data,
   const ur_template_t* tmplt, uint8_t dir_flags, const bloom_key_t& ips)
{
   /* Flow filter and record creator */
   if (!flow_filter(data, tmplt)) {
      return 0;
   }
   if (main_record.dns_data == NULL) {
      main_record.dns_data = new dns_data_t;
   }

   /* Update items */
   dns_data_t &src_host_rec = *main_record.dns_data;
   if (dir_flags & UR_DIR_FLAG_RSP && ur_get(tmplt, data, UR_BYTES) >=
      DNS_BYTES_OVERLIMIT) {
      INC(src_host_rec.out_rsp_overlimit_cnt);
   }
   return 1;
}

// Update a record of destination IP address
bool DNSSubprofile::update_dst_ip(hosts_record_t& main_record, const void* data,
   const ur_template_t* tmplt, uint8_t dir_flags, const bloom_key_t& ips)
{
   /* Flow filter and record creator */
   if (!flow_filter(data, tmplt)) {
      return 0;
   }
   if (main_record.dns_data == NULL) {
      main_record.dns_data = new dns_data_t;
   }

   /* Update items */
   dns_data_t &dst_host_rec = *main_record.dns_data;
   if (dir_flags & UR_DIR_FLAG_RSP && ur_get(tmplt, data, UR_BYTES) >=
      DNS_BYTES_OVERLIMIT) {
      INC(dst_host_rec.in_rsp_overlimit_cnt);
   }

   return 1;
}

// Check rules in a record
bool DNSSubprofile::check_record(const hosts_key_t& key, const hosts_record_t& record)
{
   if (record.dns_data == NULL) {
      return 0;  
   }
   
   check_new_rules_dns(key, record);
   return 1;
}

// Delete record
bool DNSSubprofile::delete_record(hosts_record_t &record)
{
   if (record.dns_data == NULL) {
      return 0;
   } else {
      delete record.dns_data;
      return 1;
   }
}

/* Add your new subprofile here ... */
