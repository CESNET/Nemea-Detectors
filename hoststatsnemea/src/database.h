#ifndef _HS_DATABASE_H
#define _HS_DATABASE_H

#include <string>
#include <vector>
#include "hoststats.h" // stat_map_t, host_key_t, host_rec_t

class Database {
   std::string profile_name;
   std::string path;
   std::string db_cleaner;
   std::string max_db_size;
   bool read_only;
public:
   Database(const std::string& profile_name);
   int connect();
   int disconnect();
   int reloadConfig();
   int store(const std::string &timeslot, const stat_map_t &stat_map) const;
   int load(const std::string &timeslot, stat_map_t &stat_map) const;
   int cleanup() const;
   int getRecord(const std::string& timeslot, const hosts_key_t &key, hosts_record_t &rec) const;
   std::vector<std::string> getTimeslots(const std::string &start = "", const std::string &end = "") const;
   int getNumOfRecords(const std::string &timeslot) const;
   
   static int storeToFile(const std::string &filename, const stat_map_t &stat_map);
};


#endif
