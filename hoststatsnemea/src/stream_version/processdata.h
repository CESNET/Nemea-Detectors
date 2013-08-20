#ifndef _PROCESS_DATA_H
#define _PROCESS_DATA_H

#include <string>
#include "hoststats.h"
#include "../BloomFilter.hpp"
#include "../../../../unirec/unirec.h"
#include "../../../../common/cuckoo_hash_v2/cuckoo_hash.h"
#include "../config.h"
#include "profile.h"

//odebrat - jen pro test get_record
#include "../../../../unirec/ipaddr_cpp.h"
#include <iomanip>

void UpdateStatsRecord(Profile *profile_ptr, const flow_key_t &flow_key,
                       const flow_record_t &flow_rec);

void new_trap_data(const void *record);

void *data_reader_trap(void *mutex_map); //for thread

void *data_process_trap(void *mutex_map); //for thread

/* 
 * get_record()
 * Get the reference of the record from the table with statistics
 *
 * @param stat_table Table with statistics
 * @param key        Key of the record
 */
inline hosts_record_t& get_record(Profile *ptr, const hosts_key_t& key)
{
   int index = ht_get_index_v2(ptr->stat_table_to_check, (char*) key.bytes);

   if (index < 0) { 
      // the item doesn't exist, create new empty one 
      hosts_record_t empty;
      void *kicked_data;
      kicked_data = ht_insert_v2(ptr->stat_table_to_check, (char*) key.bytes, (void*) &empty);
      if (kicked_data != NULL) {
         // Another item was kicked out of the table

         // Check configuration and run detectors
         Configuration *conf = Configuration::getInstance();
         for (detectors_citer it = ptr->detectors.begin();
               it != ptr->detectors.end(); ++it) {
            conf->lock();
            if (conf->getValue(it->first) == "1")  {
               conf->unlock();
               it->second(*(ip_addr_t*)ptr->stat_table_to_check->key_kick, 
                  *(hosts_record_t*)ptr->stat_table_to_check->data_kick,
                  ptr->current_timeslot);
            } 
            else {
               conf->unlock();
            }
         }
      }
      index = ht_get_index_v2(ptr->stat_table_to_check, (char*) key.bytes);
   }

   return *((hosts_record_t *)ptr->stat_table_to_check->data[index]);
}


#endif
