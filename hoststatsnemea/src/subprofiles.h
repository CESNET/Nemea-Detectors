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
/* BloomFilter from nemea-common */
#include <BloomFilter.hpp>

extern "C" {
   #include <unirec/unirec.h>
}

/** \brief Function pointer to update function of the subprofile
 * Update record with new data from TRAP. The record is updated if the new flow 
 * data belongs to a subprofile. If record does not exist, new one is created.
 * \n
 * First param: BloomFilter key (do not use if class doesn't contain BloomFilter) \n
 * Second param: Main record to update \n
 * Third param: New data from TRAP \n
 * Fourth param: Pointer to input interface template \n
 * Fifth param: Direction flag (request, response,...) \n
 * Return: True when data belongs to subprofile, false otherwise
 */
typedef bool (*sp_update)(hosts_record_t&, const void *, const hs_in_ifc_spec_t &,
   uint8_t, const bloom_key_t &);

/** \brief Function pointer to check function of the subprofile
 * Use detection rules only if subprofile exists. \n
 * First param: Key of a record \n
 * Second param: Main record with general statistics \n
 * Return: True if there was a subprofile, false otherwise
 */
typedef bool (*sp_check)(const hosts_key_t&, const hosts_record_t&);

/** \brief Function pointer to delete function of the subprofile
 * Delete a subprofile record from a main record. \n
 * Param: Main record with general statistics \n
 * Return: True if there was a subprofile, false otherwise.
 */
typedef bool (*sp_delete)(hosts_record_t&);

/** \brief Function pointers to the manipulation function of subprofile's BloomFilter
 * Create/swap/destroy BloomFilters \n
 * First param: Type of action ::sp_bf_action \n
 *   BF_CREATE - (constructor) create new instances of BloomFilters \n
 *   BF_SWAP:    Clear active BloomFilter and swap active and learning BloomFilter \n
 *   BF_DESTROY: (destructor) delete active and learning BloomFilter \n
 * Second param: Size of BloomFilter (used only if arg is BF_CREATE)
 */
typedef void (*sp_bf_config)(sp_bf_action, int);

/** \brief General stucture for subprofile pointers
 */
typedef struct sp_pointers_s {
   sp_update update_src_ptr;
   sp_update update_dst_ptr;
   sp_check check_ptr;
   sp_delete delete_ptr;
   sp_bf_config bf_config_ptr;
} sp_pointers_t;

/** \brief Structure with information about subprofile 
 */
struct subprofile_t{
   std::string name;
   sp_pointers_t pointers;
   bool rules_enabled;
   int interfaces_count;

   // Structure constructor
   /** \brief Structure constructor
	* \param name[in] Name of the subprofile
	* \param pointers[in] Pointers to subprofile functions
    */
   subprofile_t(std::string name, sp_pointers_t ptr) : name(name), pointers(ptr)
   {
       Configuration::trimString(name);
       rules_enabled = false;
       interfaces_count = 0;
   }
};

// ------------------------------ MACROS ---------------------------------------
#define SP_DEF_BASIC_FUNCTIONS() \
   /* Flow filter for update function */ \
   static bool flow_filter(const void *data, const hs_in_ifc_spec_t &ifc); \
   \
   /* Update a subprofile (source IP address) */ \
   static bool update_src_ip(hosts_record_t &main_record, const void *data, \
      const hs_in_ifc_spec_t &ifc, uint8_t dir_flags, const bloom_key_t &ips); \
   \
   /* Update a subprofile (destination IP address) */ \
   static bool update_dst_ip(hosts_record_t &main_record, const void *data, \
      const hs_in_ifc_spec_t &ifc, uint8_t dir_flags, const bloom_key_t &ips); \
   \
   /* Check rules in a subprofile */ \
   static bool check_record(const hosts_key_t &key, const hosts_record_t &record); \
   \
   /* Remove a subprofile from a main profile */ \
   static bool delete_record(hosts_record_t &record);

#define SP_DEF_BEGIN_CLASS(subprofile_name) \
   class SUBPROFILE_CLASS(subprofile_name) { \
   public: \
      SP_DEF_BASIC_FUNCTIONS();

#define SP_DEF_END_CLASS(subprofile_name) \
   }; \
   const sp_pointers_t subprofile_name##_pointers = { \
      SUBPROFILE_CLASS(subprofile_name)::update_src_ip, \
      SUBPROFILE_CLASS(subprofile_name)::update_dst_ip,\
      SUBPROFILE_CLASS(subprofile_name)::check_record,\
      SUBPROFILE_CLASS(subprofile_name)::delete_record,\
      NULL \
   };

#define SP_DEF_BEGIN_CLASS_WITH_BF(subprofile_name) \
   class SUBPROFILE_CLASS(subprofile_name) { \
   public: \
      SP_DEF_BASIC_FUNCTIONS(); \
      /* BloomFilters only for all flows */ \
      static bloom_filter *bf_active; \
      static bloom_filter *bf_learn; \
      static pthread_mutex_t bf_lock; \
      /* Create/swap/destroy BloomFilters */ \
      static void bloom_filter_config(sp_bf_action arg, int size);

#define SP_DEF_END_CLASS_WITH_BF(subprofile_name) \
   }; \
   const sp_pointers_t subprofile_name##_pointers = { \
      SUBPROFILE_CLASS(subprofile_name)::update_src_ip, \
      SUBPROFILE_CLASS(subprofile_name)::update_dst_ip,\
      SUBPROFILE_CLASS(subprofile_name)::check_record,\
      SUBPROFILE_CLASS(subprofile_name)::delete_record,\
      SUBPROFILE_CLASS(subprofile_name)::bloom_filter_config \
   };

// ----------------------------- SUBPROFILES -----------------------------------

/******************************* DNS subprofile *******************************/
// record structure
struct dns_record_t {
   uint32_t in_rsp_overlimit_cnt;
   uint32_t out_rsp_overlimit_cnt;

   dns_record_t() {
      memset(this, 0, sizeof(dns_record_t));
   }
};

// DNS subprofile class
SP_DEF_BEGIN_CLASS(dns)
   // DNS record
   dns_record_t record;
SP_DEF_END_CLASS(dns)


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
};

// SSH subprofile class
SP_DEF_BEGIN_CLASS_WITH_BF(ssh)
   // SSH record 
   ssh_record_t record;
SP_DEF_END_CLASS_WITH_BF(ssh)

#endif
