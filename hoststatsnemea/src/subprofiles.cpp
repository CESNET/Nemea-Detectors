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

extern int input_ifc_count;

// Macros
#define ADD(dst, src) \
   dst = safe_add(dst, src);

#define INC(value) \
   value = safe_inc(value);

/* HOW TO ADD NEW SUBPROFILE:
 * 1) In subprofiles.h create new class using SP_DEF_BEGIN_CLASS(_WITH_BF)
 *    and SP_DEF_END_CLASS(_WITH_BF) macros. Add your public class code between 
 *    this two macros. Use macros with _WITH_BF only when you need BloomFilter
 *    for your subprofile.
 * 
 * 2) In subprofile.cpp add definitions of requied subprofile functions:
 *    SP_FLOW_FILTER(name)   - flow filter
 *    SP_UPDATE_SRC_IP(name) - update subprofile of source IP
 *    SP_UPDATE_DST_IP(name) - update subprofile of destination IP
 * 
 *    Add default implementation of other requied functions(just add these lines)
 *    SP_DEF_CHECK_RECORD(name);
 *    SP_DEF_DELETE_RECORD(name);
 *    
 *    If you use macros with _WITH_BF add this two macros too.
 *    SP_DEF_BLOOM_FILTER_INIT(name);
 *    SP_DEF_BLOOM_FILTER_CONFIG(name);
 * 
 * 3) In hoststats.h add subprofile to "List of subprofiles" with new line:
 *       class SUBPROFILE_CLASS(name); 
 *    Append struct hosts_record_t with new line:
 *       SUBPROFILE_CLASS(name) *SUBPROFILE_DATA(name);
 * 
 * 4) In hoststatserv.cpp find function init_subprofiles_list() and add your
 *    subprofile to the list of available subprofiles. 
 * 
 * Note: There are two sample subprofiles (SSH and DNS) where you can inspire...
 */

/* 
 * \brief Generate function header of the flow filter
 * \param subprofile_name Name of the subprofile
 */
#define SP_FLOW_FILTER(subprofile_name) \
   bool SUBPROFILE_CLASS(subprofile_name)::flow_filter(const void *data, \
      const hs_in_ifc_spec_t &ifc)

/** \brief Flow filter
 * Use filter to filter out unwanted flow data
 */
#define SP_USE_FLOW_FILTER() \
   if (!flow_filter(data, ifc)) { \
      return 0; \
   }

/** \brief Default record creator
 * Create new record if subprofile does not exists
 * \param subprofile_name Name of the subprofile
 */
#define SP_USE_RECORD_CREATOR(subprofile_name) \
   /* Create new record if subprofile does not exists */ \
   if (main_record.SUBPROFILE_DATA(subprofile_name) == NULL) { \
      main_record.SUBPROFILE_DATA(subprofile_name) = new SUBPROFILE_CLASS(subprofile_name); \
   }

/*
 * \brief Generate update function header of source IP record
 * This macro defines a common implementation of function used by typedef 
 * ::sp_update
 * \param subprofile_name Name of the subprofile
 */
#define SP_UPDATE_SRC_IP(subprofile_name) \
   bool SUBPROFILE_CLASS(subprofile_name)::update_src_ip( \
      hosts_record_t &main_record, const void *data, const hs_in_ifc_spec_t &ifc, \
      uint8_t dir_flags, const bloom_key_t &ips) 

/*
 * \brief Generate update function header of destination IP record
 * This macro defines a common implementation of function used by typedef 
 * ::sp_update
 * \param subprofile_name Name of the subprofile
 */
#define SP_UPDATE_DST_IP(subprofile_name) \
   bool SUBPROFILE_CLASS(subprofile_name)::update_dst_ip( \
      hosts_record_t &main_record, const void *data, const hs_in_ifc_spec_t &ifc, \
      uint8_t dir_flags, const bloom_key_t &ips)

/*
 * \brief Generate default check record code
 * This macro defines a common implementation of function used by typedef 
 * ::sp_check
 * \param subprofile_name Name of the subprofile
 * \param rule_function Pointer to check record function (can by NULL)
 */
#define SP_DEF_CHECK_RECORD(subprofile_name, rule_function) \
   bool SUBPROFILE_CLASS(subprofile_name)::check_record(const hosts_key_t &key, \
      const hosts_record_t &record) \
   {\
      if (record.subprofile_name ## hostprofile == NULL || rule_function == NULL) \
         return 0; \
      \
      rule_function(key, record); \
      return 1; \
   }

/*
 * \brief Generate default delete record code
 * This macro defines a common implementation of function used by typedef 
 * ::sp_delete
 * \param subprofile_name Name of the subprofile
 */
#define SP_DEF_DELETE_RECORD(subprofile_name) \
   bool SUBPROFILE_CLASS(subprofile_name)::delete_record(hosts_record_t &record) \
   {\
      if (record.subprofile_name ## hostprofile == NULL) {\
         return 0;\
      }\
      else {\
         delete record.subprofile_name ## hostprofile;\
         return 1;\
      }\
   }

/** \brief Default initialization of BloomFilters
 * \param subprofile_name Name of the subprofiles
 */
#define SP_DEF_BLOOM_FILTER_INIT(subprofile_name) \
   /* static variables inicialization */ \
   bloom_filter* SUBPROFILE_CLASS(subprofile_name)::bf_active = NULL; \
   bloom_filter* SUBPROFILE_CLASS(subprofile_name)::bf_learn = NULL; \
   pthread_mutex_t SUBPROFILE_CLASS(subprofile_name)::bf_lock = PTHREAD_MUTEX_INITIALIZER;

/** \brief Generate default BloomFilter configuration code
 * This macro defines a common implementation of function used by typedef 
 * ::sp_bf_config .
 * \param subprofile_name Name of the subprofile
 */
#define SP_DEF_BLOOM_FILTER_CONFIG(subprofile_name) \
   void SUBPROFILE_CLASS(subprofile_name)::bloom_filter_config(sp_bf_action arg, \
   int size) \
   { \
      switch (arg) { \
      case BF_CREATE: { \
         if (bf_active != NULL || bf_learn != NULL) { \
            break; \
         } \
         \
         bloom_parameters bp; \
         bp.projected_element_count = size; \
         bp.false_positive_probability = 0.01; \
         bp.compute_optimal_parameters(); \
         \
         bf_active = new bloom_filter(bp); \
         bf_learn = new bloom_filter(bp); \
         } break; \
      case BF_SWAP: { \
         if (bf_active == NULL || bf_learn == NULL) { \
            break; \
         } \
         \
         if (input_ifc_count > 1) { \
            pthread_mutex_lock(&bf_lock); \
         } \
         bf_active->clear(); \
         bloom_filter *tmp = bf_active; \
         bf_active = bf_learn; \
         bf_learn = tmp; \
         \
         if (input_ifc_count > 1) { \
            pthread_mutex_unlock(&bf_lock); \
         } \
         \
         } break; \
      case BF_DESTROY: { \
         if (bf_active == NULL || bf_learn == NULL) { \
            break; \
         } \
         \
         delete bf_active; \
         delete bf_learn; \
         bf_active = NULL; \
         bf_learn = NULL; \
         } break; \
      } \
   }

/** \brief Generate default BloomFilter get presence code
 * Stores a key "fingerprint" and determines whether a given "fingerprint" was
 * already entered. Fingerprint is combination of SRC IP + DST IP + other
 * implementation required data
 * \n
 * Param: status[out] Result of BloomFilter presence test (bool value) - 
 *        True if "fingerprint" is known, otherwise false
 */
#define SP_GET_BF_PRESENCE(status) \
   if (input_ifc_count > 1) { \
      pthread_mutex_lock(&bf_lock); \
   } \
   \
   status = bf_active->containsinsert((const unsigned char *) &ips, \
      sizeof(bloom_key_t)); \
   bf_learn->insert((const unsigned char *) &ips, sizeof(bloom_key_t)); \
   \
   if (input_ifc_count > 1) { \
      pthread_mutex_unlock(&bf_lock); \
   }



/******************************* DNS subprofile *******************************/
#define DNS_BYTES_OVERLIMIT 1000

/* DNS flow filter */
SP_FLOW_FILTER(dns)
{
   return ((ur_get(ifc.tmpl, data, UR_PROTOCOL) == 6  || 
            ur_get(ifc.tmpl, data, UR_PROTOCOL) == 17) 
            &&
           (ur_get(ifc.tmpl, data, UR_SRC_PORT) == 53 || 
            ur_get(ifc.tmpl, data, UR_DST_PORT) == 53));
}

/* DNS SRC IP updater */
SP_UPDATE_SRC_IP(dns)
{
   /* Flow filter and record creator */
   SP_USE_FLOW_FILTER();
   SP_USE_RECORD_CREATOR(dns);
   
   /* Subprofile update */
   dns_record_t &src_host_rec = main_record.SUBPROFILE_DATA(dns)->record;
   if (dir_flags & UR_DIR_FLAG_RSP && ur_get(ifc.tmpl, data, UR_BYTES) >= DNS_BYTES_OVERLIMIT) {
      INC(src_host_rec.out_rsp_overlimit_cnt);
   }

   return 1;
}

/* DNS DST IP updater */
SP_UPDATE_DST_IP(dns)
{
   /* Flow filter and record creator */
   SP_USE_FLOW_FILTER();
   SP_USE_RECORD_CREATOR(dns);
   
   // update items
   dns_record_t &dst_host_rec = main_record.SUBPROFILE_DATA(dns)->record;
   if (dir_flags & UR_DIR_FLAG_RSP && ur_get(ifc.tmpl, data, UR_BYTES) >= DNS_BYTES_OVERLIMIT) {
      INC(dst_host_rec.in_rsp_overlimit_cnt);
   }

   return 1;
}

/* Check record and delete record default functions */
SP_DEF_CHECK_RECORD(dns, check_new_rules_dns)
SP_DEF_DELETE_RECORD(dns)

/******************************* SSH subprofile *******************************/

/* Default initialization of BloomFilter */
SP_DEF_BLOOM_FILTER_INIT(ssh)

/* SSH flow filter */
SP_FLOW_FILTER(ssh)
{
   return 
      (ur_get(ifc.tmpl, data, UR_PROTOCOL) == 6 
      &&
      (
         ur_get(ifc.tmpl, data, UR_SRC_PORT) == 22 || 
         ur_get(ifc.tmpl, data, UR_DST_PORT) == 22
      ));
}

/* SSH SRC IP updater */
SP_UPDATE_SRC_IP(ssh)
{
   /* Flow filter and record creator */
   SP_USE_FLOW_FILTER();
   SP_USE_RECORD_CREATOR(ssh);
        
   /* Find/add record in the BloomFilter */
   bool src_present = false;
   SP_GET_BF_PRESENCE(src_present);

   uint8_t tcp_flags = ur_get(ifc.tmpl, data, UR_TCP_FLAGS);

   /* Update items */
   ssh_record_t &src_host_rec = main_record.SUBPROFILE_DATA(ssh)->record;
   
   if (!src_present) INC(src_host_rec.out_all_uniqueips);
   
   if (dir_flags & UR_DIR_FLAG_REQ) {
      // request flows
      ADD(src_host_rec.out_req_packets, ur_get(ifc.tmpl, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(src_host_rec.out_req_syn_cnt);
   } else if (dir_flags & UR_DIR_FLAG_RSP) {
      // respose flows
      ADD(src_host_rec.out_rsp_packets, ur_get(ifc.tmpl, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(src_host_rec.out_rsp_syn_cnt);
   }
   return 1;
}

/* SSH DST IP updater */
SP_UPDATE_DST_IP(ssh)
{
   /* Flow filter and record creator */
   SP_USE_FLOW_FILTER();
   SP_USE_RECORD_CREATOR(ssh);
   
   /* Find/add record in the BloomFilter */
   bool dst_present = false;
   SP_GET_BF_PRESENCE(dst_present);

   uint8_t tcp_flags = ur_get(ifc.tmpl, data, UR_TCP_FLAGS);

   // update items
   ssh_record_t &dst_host_rec = main_record.SUBPROFILE_DATA(ssh)->record;
   
   if (!dst_present) INC(dst_host_rec.in_all_uniqueips);

   if (dir_flags & UR_DIR_FLAG_REQ) {
      // request flows
      ADD(dst_host_rec.in_req_packets, ur_get(ifc.tmpl, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(dst_host_rec.in_req_syn_cnt);
   } else if (dir_flags & UR_DIR_FLAG_RSP) {
      // respose flows
      ADD(dst_host_rec.in_rsp_packets, ur_get(ifc.tmpl, data, UR_PACKETS));
      if (tcp_flags & 0x2)  INC(dst_host_rec.in_rsp_syn_cnt);
   }

   return 1;
}

/* Check record, delete record and BloomFilter config default functions */
SP_DEF_CHECK_RECORD(ssh, check_new_rules_ssh)
SP_DEF_DELETE_RECORD(ssh)
SP_DEF_BLOOM_FILTER_CONFIG(ssh)

#undef ADD
#undef INC
