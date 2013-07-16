#include "profile.h"
#include "aux_func.h"
#include "config.h"
#include "processdata.h"

using namespace std;

// Global vector of profiles available
vector<Profile*> profiles;

Profile::Profile(flow_filter_func_ptr flow_filter_func, const std::string &name, const std::string &desc)
 : flow_filter_func(flow_filter_func), name(name), desc(desc), database(name)
{ 
   stat_map_to_load = &stat_map_1;
   stat_map_to_check = &stat_map_2;
}

Profile::~Profile()
{ }

int Profile::reload_config()
{
   database.reloadConfig();
}

int Profile::new_data(const flow_key_t &flow_key, const flow_record_t &flow_record)
{
   if (flow_filter_func != NULL && flow_filter_func(flow_key, flow_record) == false) {
      return 1;
   }

   UpdateStatsRecord(*stat_map_to_load, flow_key, flow_record, *bf);
   return 0;
}

int Profile::store() const
{
   if (!(*stat_map_to_check).empty()) {
      database.store(current_timeslot, (*stat_map_to_check));
      return 0;
   }
   else {
      return -1;
   }
   
}

int Profile::release()
{
   current_timeslot = "";
   (*stat_map_to_check).clear();
}

void Profile::swap_stat_maps(const string &timeslot)
{
   current_timeslot = timeslot;

   stat_map_t *tmp = stat_map_to_load;
   stat_map_to_load = stat_map_to_check;
   stat_map_to_check = tmp;
}

/////////////////////////////////////////

Profile* getProfile(const std::string& name)
{
   for (int i = 0; i < profiles.size(); i++) {
      if (profiles[i]->name == name)
         return profiles[i];
   }
   return NULL;
}

