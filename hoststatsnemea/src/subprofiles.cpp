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

#include "subprofiles.h"
#include "aux_func.h"
#include "detectionrules.h"

//TODO: remove - only for testing
#include <unirec/ipaddr_cpp.h>

// Macros
#define ADD(dst, src) \
   dst = safe_add(dst, src);

#define INC(value) \
   value = safe_inc(value);

#define REQ 8  // request
#define RSP 4  // response
#define SF  2  // single flow
#define NRC 1  // not recognize


/* How to add new subprofile:
   1) Create new class in subprofiles(.cpp/.h) with static methods corresponding
      to function pointers sp_update, sp_check, sp_delete (see subprofiles.h). 
      If new subprofile requires its own BloomFilter, implement a method derived
      from function pointer sp_bf_config.
   2) Add this class pointer to "hosts_record_t" in hoststats.h
   2) Your subprofile should have a flow filtering function. Call this function
      at the start of your new update function to ensure that only the desired
      flows will be stored.
   3) Create "const sp_pointers_t your_class_name" structure in subprofiles.h 
      with name of functions corresponding to sp_update, sp_check, sp_delete and
      sp_bf_config. If you have not implemented BloomFilter use NULL instead of
      sp_bf_config function.
   4) In constructor of HostProfile (profile.cpp) add your identificator of 
      new subprofile (created in step 3) to sp_list.


/******************************* DNS subprofile *******************************/
#define DNS_BYTES_OVERLIMIT 1000
/* 
 * flow_filter()
 * Check if the flow data belongs to subprofile.
 * 
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @return True when data belongs to subprofile, false otherwise
 */
bool DNSHostProfile::flow_filter(const void *data, const ur_template_t *tmplt)
{
   return ((ur_get(tmplt, data, UR_PROTOCOL) == 6  || 
            ur_get(tmplt, data, UR_PROTOCOL) == 17) 
            &&
           (ur_get(tmplt, data, UR_SRC_PORT) == 53 || 
            ur_get(tmplt, data, UR_DST_PORT) == 53));
}

/*
 * update()
 * Update record with new data from TRAP
 *
 * DNS records are updated if the new flow data belongs to DNS subprofile. 
 * If record(s) does not exist, new one is created.
 * 
 * @param ips Structure of two IP addresses (not used in this module - can be NULL)
 * @param src_record Source record to update
 * @param dst_record Destination record to update
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @return True when data belongs to subprofile, false otherwise
 */
bool DNSHostProfile::update(bloom_key_t *ips, hosts_record_t &src_record, 
      hosts_record_t &dst_record, const void *data, const ur_template_t *tmplt)
{
   // DNS flow filter
   if (!flow_filter(data, tmplt)) {
      return 0;
   }

   uint8_t dir_flags = ur_get(tmplt, data, UR_DIRECTION_FLAGS);

   // create new DNS record(s)
   if (src_record.dnshostprofile == NULL) {
      src_record.dnshostprofile = new DNSHostProfile;
   }
   if (dst_record.dnshostprofile == NULL) {
      dst_record.dnshostprofile = new DNSHostProfile;
   }

   // update items
   dns_record_t &src_host_rec = src_record.dnshostprofile->record;
   dns_record_t &dst_host_rec = dst_record.dnshostprofile->record;

   if (dir_flags & RSP && ur_get(tmplt, data, UR_BYTES) >= DNS_BYTES_OVERLIMIT) {
      // source --------------------------------
      INC(src_host_rec.out_rsp_overlimit_cnt);
      // destination ---------------------------
      INC(dst_host_rec.in_rsp_overlimit_cnt);
   }

   return 1;
}

/*
 * check_record()
 * Check detection rules only if subprofile exists
 *
 * @param key HostProfile key of a record
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool DNSHostProfile::check_record(const hosts_key_t &key, const hosts_record_t &record)
{
   if (record.dnshostprofile == NULL)
      return 0;

   check_new_rules_dns(key, record);

   // cout << IPaddr_cpp(&key) << endl;
   // dns_record_t &ssh = record.dnshostprofile->record;
   // cout << "OUT RSP OVERLIMIT:  " << ssh.out_rsp_overlimit_cnt   << endl;
   // cout << "IN RSP OVERLIMIT:   " << ssh.in_rsp_overlimit_cnt    << endl;
   // cout << "------------------------------------------"   << endl;

   return 1;
}

/*
 * delete_record()
 * Delete a DNS record from a main record.
 *
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool DNSHostProfile::delete_record(hosts_record_t &record)
{
   if (record.dnshostprofile == NULL) {
      return 0;
   }
   else {
      delete record.dnshostprofile;
      return 1;
   }
}


/******************************* SSH subprofile *******************************/
/* static variables inicialization */
bloom_filter *SSHHostProfile::ssh_bf_active = NULL;
bloom_filter *SSHHostProfile::ssh_bf_learn = NULL;

/* 
 * flow_filter()
 * Check if the flow data belongs to subprofile.
 * 
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @return True when data belongs to subprofile, false otherwise
 */
bool SSHHostProfile::flow_filter(const void *data, const ur_template_t *tmplt)
{
   return 
      (ur_get(tmplt, data, UR_PROTOCOL) == 6 
      &&
      (
         ur_get(tmplt, data, UR_SRC_PORT) == 22 || 
         ur_get(tmplt, data, UR_DST_PORT) == 22
      ));
}

/*
 * update()
 * Update record with new data from TRAP
 *
 * SSH records are updated if the new flow data belongs to SSH subprofile. 
 * If record(s) does not exist, new one is created.
 * 
 * @param ips Structure of two IP addresses [source IP, destination IP] + timestamp
 * @param src_record Source record to update
 * @param dst_record Destination record to update
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @return True when data belongs to subprofile, false otherwise
 */
bool SSHHostProfile::update(bloom_key_t *ips, hosts_record_t &src_record, 
      hosts_record_t &dst_record, const void *data, const ur_template_t *tmplt)
{
   // SSH flow filter
   if (!flow_filter(data, tmplt)) {
      return 0;
   }

   // find/add record in the BloomFilter
   bool src_present = false;
   bool dst_present = false;
   
   ips->rec_time = src_record.first_rec_ts % (std::numeric_limits<uint16_t>::max() + 1);
   ips->rec_time &= ((1 << 15) - 1);
   src_present = ssh_bf_active->containsinsert((const unsigned char *) ips,
      sizeof(bloom_key_t));
   ssh_bf_learn->insert((const unsigned char *) ips, sizeof(bloom_key_t));

   ips->rec_time = dst_record.first_rec_ts % (std::numeric_limits<uint16_t>::max() + 1);
   ips->rec_time |= (1 << 15);
   dst_present = ssh_bf_active->containsinsert((const unsigned char *) ips,
      sizeof(bloom_key_t));
   ssh_bf_learn->insert((const unsigned char *) ips, sizeof(bloom_key_t));

   uint8_t tcp_flags = ur_get(tmplt, data, UR_TCP_FLAGS);
   uint8_t dir_flags = ur_get(tmplt, data, UR_DIRECTION_FLAGS);

   // create new SSH record(s)
   if (src_record.sshhostprofile == NULL) {
      src_record.sshhostprofile = new SSHHostProfile;
   }
   if (dst_record.sshhostprofile == NULL) {
      dst_record.sshhostprofile = new SSHHostProfile;
   }

   // update items
   ssh_record_t &src_host_rec = src_record.sshhostprofile->record;
   ssh_record_t &dst_host_rec = dst_record.sshhostprofile->record;

   // source ------------------------------------------
   if (!src_present) INC(src_host_rec.out_all_uniqueips);

   if (dir_flags & REQ) {
      // request flows
      ADD(src_host_rec.out_req_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(src_host_rec.out_req_syn_cnt);
   } else if (dir_flags & RSP) {
      // respose flows
      ADD(src_host_rec.out_rsp_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(src_host_rec.out_rsp_syn_cnt);
   }

   // destination -------------------------------------
   if (!dst_present) INC(dst_host_rec.in_all_uniqueips);

   if (dir_flags & REQ) {
      // request flows
      ADD(dst_host_rec.in_req_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(dst_host_rec.in_req_syn_cnt);
   } else if (dir_flags & RSP) {
      // respose flows
      ADD(dst_host_rec.in_rsp_packets, ur_get(tmplt, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(dst_host_rec.in_rsp_syn_cnt);
   }

   return 1;
}

/*
 * check_record()
 * Check detection rules only if subprofile exists
 *
 * @param key HostProfile key of a record
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool SSHHostProfile::check_record(const hosts_key_t &key, const hosts_record_t &record)
{
   if (record.sshhostprofile == NULL)
      return 0;

   check_new_rules_ssh(key, record);
   return 1;
}

/*
 * delete_record()
 * Delete a SSH record from a main record.
 *
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool SSHHostProfile::delete_record(hosts_record_t &record)
{
   if (record.sshhostprofile == NULL) {
      return 0;
   }
   else {
      delete record.sshhostprofile;
      return 1;
   }
}

/*
 * Create/swap/destroy BloomFilters
 * Parameter "arg" is:
 *    BF_CREATE:  (constructor) create new instances of BloomFilters
 *    BF_SWAP:    Clear active BloomFilter and swap active and learning BloomFilter
 *    BF_DESTROY: (destructor) delete active and learning BloomFilter
 *
 * @param[in] arg  Type of operation
 * @param[in] size Size of BloomFilter (used only if arg is BF_CREATE)
 */
void SSHHostProfile::bloom_filter_config(sp_bf_action arg, int size)
{
   switch (arg) {
   case BF_CREATE: {
      if (ssh_bf_active != NULL || ssh_bf_learn != NULL) {
         break;
      }

      bloom_parameters ssh_bp;
      ssh_bp.projected_element_count = size;
      ssh_bp.false_positive_probability = 0.01;
      ssh_bp.compute_optimal_parameters();

      ssh_bf_active = new bloom_filter(ssh_bp);
      ssh_bf_learn = new bloom_filter(ssh_bp);
      } break;
   case BF_SWAP: {
      if (ssh_bf_active == NULL || ssh_bf_learn == NULL) {
         break;
      }

      ssh_bf_active->clear();
      bloom_filter *tmp = ssh_bf_active;
      ssh_bf_active = ssh_bf_learn;
      ssh_bf_learn = tmp;
      } break;
   case BF_DESTROY: {
      if (ssh_bf_active == NULL || ssh_bf_learn == NULL) {
         break;
      }

      delete ssh_bf_active;
      delete ssh_bf_learn;
      ssh_bf_active = NULL;
      ssh_bf_learn = NULL;
      } break;
   }
}