#ifndef _PROFILE_H_
#define _PROFILE_H_

#include <string>
#include <vector>
#include "../BloomFilter.hpp"

#include "hoststats.h"
#include "database.h"

class Profile {
   flow_filter_func_ptr flow_filter_func;
public:
   std::string name;
   std::string desc;
   Database database;
   std::string current_timeslot;
   stat_map_t stat_map_1, stat_map_2;
   stat_map_t *stat_map_to_load, *stat_map_to_check;
   bloom_filter *bf;
   
   // Constructor
   Profile(flow_filter_func_ptr flow_filter_func, const std::string &name, const std::string &desc = "");
   
   // Destructor
   ~Profile();
   
   // Do what is needed after configuration is reloaded
   int reload_config();
   
   // Store new data to map (stat_map_to_load)
   int new_data(const flow_key_t &flow_key, const flow_record_t &flow_record);
   
   // Store currently loaded stats into database
   int store() const;
   
   // Release all stats loaded in memory
   int release();

   // Swap pointers to maps (for store and check)
   // @timeslot - timeslot of currently loaded flows 
   void swap_stat_maps(const std::string &timeslot);
};

// Global vector of profiles available
extern std::vector<Profile*> profiles;

// Return the profile with a given name (if such profile doesn't exist, return NULL) 
Profile* getProfile(const std::string& name);

#endif
