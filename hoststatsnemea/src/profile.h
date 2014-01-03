#ifndef _PROFILE_H_
#define _PROFILE_H_

#include <string>
#include <vector>

#include "config.h"
#include "BloomFilter.hpp"
#include "hoststats.h"
// #include "database.h"
#include "detectionrules.h"
#include "subprofiles.h"

extern "C" {
   #include <cuckoo_hash_v2.h>
   #include <unirec/unirec.h>
}


// List of subprofiles 
typedef std::vector<subprofile_t> sp_list_v;
typedef sp_list_v::iterator sp_list_iter;

/* -------------------- MAIN PROFILE -------------------- */

class HostProfile {
private:
   stat_table_t stat_table;
   stat_table_t *stat_table_ptr;
   bloom_filter *bf_active, *bf_learn;
   int table_size;
   bool detector_status;   // main profile detector active / inactive

   // Get the reference of record from the table 
   hosts_record_t& get_record(const hosts_key_t& key);

   // Check changes in configuration file
   void apply_config();

public:
   int active_timeout;
   int inactive_timeout;
   int det_start_time;
   sp_list_v sp_list;

   // Constructor
   HostProfile();

   // Destructor
   ~HostProfile();

   // Do what is needed after configuration is reloaded
   int reload_config();

   // Update the main profile and subprofiles
   void update(const void *record, const ur_template_t *tmplt,
      bool subprofiles = true);

   // Remove record from the main profile and subprofiles
   void remove_by_key(const hosts_key_t &key);

   // Release all stats loaded in memory
   void release();

   // Clear active BloomFilter and swap pointers
   void swap_bf();

   // Run detectors on the record specified by the key
   void check_record(const hosts_key_t &key, bool subprofiles = true);

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

};

///////////////////////////////////////////////////////////////////////////////
// Templates definition

/**
 * safe_inc()
 *
 * Safely increase the value by one. In case of overflow, return value is set to
 * the maximum possible value.
 *
 * @param value Value to increase
 * @return Increased value
 */
template <typename T>
inline T safe_inc (const T &value) 
{
   if (value < std::numeric_limits<T>::max()) {
      return value + 1;
   }
}

/**
 * safe_add()
 *
 * Safely add two unsigned values of different types. In case of overflow, 
 * return value is set to the maximum possible value of destination variable.
 *
 * @param dst Destination variable
 * @param src Source variable
 * @return Sum of values or max value of destination type
 */
template <typename T1, typename T2>
inline T1 safe_add (const T1 &dst, const T2 &src) 
{
   if ((src > std::numeric_limits<T1>::max()) || 
      (dst > std::numeric_limits<T1>::max() - src)) {
      return std::numeric_limits<T1>::max();
   }
   else {
      return dst + src;
   }
}

/**
 * safe_add()
 *
 * Safely add two unsigned values of the same type. In case of overflow, 
 * return value is set to the maximum possible value of the type of parameters.
 *
 * @param dst Destination variable
 * @param src Source variable
 * @return Sum of values or max value of the type of parameters
 */
template <typename T>
inline T safe_add (const T &dst, const T &src)
{
   if (dst > std::numeric_limits<T>::max() - src) {
      return std::numeric_limits<T>::max();
   }
   else {
      return dst + src;
   }
}


#endif
