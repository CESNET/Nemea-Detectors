#ifndef _PROFILE_H_
#define _PROFILE_H_

#include <string>
#include <vector>

#include "../BloomFilter.hpp"
#include "hoststats.h"
#include "database.h"
#include "../../../../common/cuckoo_hash_v2/cuckoo_hash.h"

typedef std::vector<std::pair<std::string, void (*)(const hosts_key_t&, 
      const hosts_record_t&, const std::string&)> > detectors_t;
typedef detectors_t::const_iterator detectors_citer;


class Profile {
   flow_filter_func_ptr flow_filter_func;
public:
   std::string name;
   std::string desc;
   Database database;
   std::string current_timeslot;
   stat_table_t stat_table;
   stat_table_t *stat_table_to_check;
   bloom_filter *bf_active, *bf_learn;
   detectors_t detectors;
   
   // Constructor
   Profile(flow_filter_func_ptr flow_filter_func, const std::string &name, const std::string &desc = "");
   
   // Destructor
   ~Profile();
   
   // Do what is needed after configuration is reloaded
   int reload_config();
   
   // Store new data to map (stat_talbe_to_check)
   int new_data(const flow_key_t &flow_key, const flow_record_t &flow_record);
   
/*   // Store currently loaded stats into database
   int store() const;
*/ 
   // Release all stats loaded in memory
   int release();

   // @timeslot - timeslot of currently loaded flows 
   void change_timeslot(const std::string &new_timeslot);

   // Clear active BloomFilter and swap pointers
   void swap_bf();
};

// Global vector of profiles available
extern std::vector<Profile*> profiles;

// Return the profile with a given name (if such profile doesn't exist, return NULL) 
Profile* getProfile(const std::string& name);

#endif
