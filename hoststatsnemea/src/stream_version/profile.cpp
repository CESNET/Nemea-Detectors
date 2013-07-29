#include "profile.h"
#include "../aux_func.h"
#include "../config.h"

#include "processdata.h"

using namespace std;

// Global vector of profiles available
vector<Profile*> profiles;

Profile::Profile(flow_filter_func_ptr flow_filter_func, const std::string &name, const std::string &desc)
 : flow_filter_func(flow_filter_func), name(name), desc(desc), database(name)
{ 
   stat_map_to_check = &stat_map;
   pthread_mutex_init(&mtx, NULL);
}

Profile::~Profile()
{ 
   pthread_mutex_destroy(&mtx);
}

int Profile::reload_config()
{
   database.reloadConfig();
}

int Profile::new_data(const flow_key_t &flow_key, const flow_record_t &flow_record)
{
   if (flow_filter_func != NULL && flow_filter_func(flow_key, flow_record) == false) {
      return 1;
   }

   pthread_mutex_lock(&mtx);
   UpdateStatsRecord(*stat_map_to_check, flow_key, flow_record, bf_active, bf_learn);
   pthread_mutex_unlock(&mtx);
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

void Profile::change_timeslot(const std::string &new_timeslot)
{
   current_timeslot = new_timeslot;
}

void Profile::swap_bf()
{
   bf_active->clear();

   bloom_filter *tmp = bf_active;
   bf_active = bf_learn;
   bf_learn = tmp;
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

