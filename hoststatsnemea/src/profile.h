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

#ifndef _PROFILE_H_
#define _PROFILE_H_

#include <string>
#include <vector>

#include "config.h"
/* BloomFilter from nemea-common */
#include <BloomFilter.hpp>
#include "hoststats.h"
// #include "database.h"
#include "detectionrules.h"
#include "subprofiles.h"

extern "C" {
   #include <cuckoo_hash_v2.h>
   #include <unirec/unirec.h>
}

// The identification of item to remove
typedef struct old_rec_item_s {
   hosts_key_t key;
   bool operator== (const old_rec_item_s& second) const
   {
      return (memcmp(&key, &second.key, sizeof(hosts_key_t)) == 0);   
   }
} old_rec_item_t;

// List of subprofiles 
typedef std::vector<subprofile_t> sp_list_v;
typedef sp_list_v::iterator sp_list_iter;

/* -------------------- MAIN PROFILE -------------------- */

class HostProfile {
private:
   stat_table_t stat_table;   // cuckoo_hash table
   stat_table_t *stat_table_ptr;

   bloom_filter *bf_active, *bf_learn; // pointer to active/learning BloomFilter
   int table_size;            // size of cuckoo_hash table
   bool detector_status;      // main profile detector active / inactive
   sp_list_v sp_list;         // list of avaiable subprofiles

   pthread_mutex_t old_rec_list_mutex;
   std::vector<old_rec_item_t> old_rec_list;
   bool old_rec_ready;

   // Get the reference of record from the table 
   hosts_record_t& get_record(const hosts_key_t& key);

   // Check changes in configuration file
   void apply_config();

public:
   int active_timeout;
   int inactive_timeout;
   int det_start_time;

   // Constructor
   HostProfile();

   // Destructor
   ~HostProfile();

   // Update the main profile and subprofiles
   void update(const void *record, const ur_template_t *tmplt,
      bool subprofiles = true);

   // Remove record from the main profile and subprofiles
   void remove_by_key(const hosts_key_t &key);

   // Release all stats loaded in memory
   void release();

   // Clear active BloomFilter and swap pointers
   void swap_bf();

   // Run detectors on the record (for kicked items from table)
   void check_record(const hosts_key_t &key, const hosts_record_t &record, 
      bool subprofiles = true);

   // A reference to the record at position n in cuckoo_hash table.
   inline const hosts_record_t& get_record_at_index(int n) 
      {return *(hosts_record_t*)stat_table_ptr->data[n];}

   // A reference to the key at position n in cuckoo_hash table.
   inline const hosts_key_t& get_key_at_index(int n)
      {return *(hosts_key_t*)stat_table_ptr->keys[n];}

   // Current table size      
   inline const int get_table_size() {return table_size;}

   /*
    * is_valid()
    * Check record validity by key and supposed index of the item.
    *
    * @param key Key of checked item
    * @param index Supposed index of item
    * @return 1 if item is on the given index in table, 0 otherwise.
    */
   inline bool is_valid(const hosts_key_t& key, int index)
      {return ht_is_valid_v2(this->stat_table_ptr, (char*)key.bytes, index);}

   // Inserts a record into the list to remove
   void old_rec_list_insert(const hosts_key_t &key);

   // Delete prepared old items
   void old_rec_list_clean();

   // Checks if a key exists in the list
   bool old_rec_list_present(const hosts_key_t &key);

   // Check if in the list is at least minimal amount of items
   inline bool is_old_rec_list_ready()
      {return old_rec_ready;}

   // Set old_rec_ready to true, mean that it can remove old records
   inline void set_old_rec_ready() {
      pthread_mutex_lock(&old_rec_list_mutex);
      old_rec_ready = true;
      pthread_mutex_unlock(&old_rec_list_mutex);
   }
};

#endif
