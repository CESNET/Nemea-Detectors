// Functions for handling requests from frontend
#include <string>
#include <sstream>
#include <arpa/inet.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <algorithm>
#include <arpa/inet.h>

#include "hoststats.h"
#include "requesthandlers.h"
#include "../aux_func.h"
#include "profile.h"
#include "../synan.h"
#include "../config.h"

#include "../../../../unirec/ipaddr_cpp.h"

using namespace std;

extern bool processing_data;
extern string last_timeslot;

///////////////////////////////////////////////////////////////////////////////

struct field_info_t {
   unsigned short offset;
   unsigned short size;
   field_info_t(unsigned short offset, unsigned short size)
    : offset(offset), size(size)
   {}
};

// Return offset and size of a hosts_record_t field given by its name
field_info_t get_field_info(const string &field_name)
{
   if (field_name.empty())
      return field_info_t(0, 0);
   
   hosts_record_t tmp;
   #define FIELD(name) \
      if (field_name == #name) \
         return field_info_t((char*)&tmp.name - (char*)&tmp, sizeof(tmp.name))
   FIELD(in_flows);
   FIELD(out_flows);
   FIELD(in_packets);
   FIELD(out_packets);
   FIELD(in_bytes);
   FIELD(out_bytes);
   FIELD(in_syn_cnt);
   FIELD(out_syn_cnt);
   FIELD(in_ack_cnt);
   FIELD(out_ack_cnt);
   FIELD(in_fin_cnt);
   FIELD(out_fin_cnt);
   FIELD(in_rst_cnt);
   FIELD(out_rst_cnt);
   FIELD(in_psh_cnt);
   FIELD(out_psh_cnt);
   FIELD(in_urg_cnt);
   FIELD(out_urg_cnt);
   FIELD(in_uniqueips);
   FIELD(out_uniqueips);
   #undef FIELD
   return field_info_t(0, 0);
}

// Functor for comparing two records by a given field
class CompareFunc {
   unsigned short offset, size;
   bool ascending;

public:   
   CompareFunc(const string &field_name, bool ascending)
    : ascending(ascending)
   {
      field_info_t os = get_field_info(field_name);
      offset = os.offset;
      size = os.size;
   }
   bool valid()
   {
      return (size == 1 ||size == 2 || size == 4 || size == 8);
   }
   bool operator()(const pair<hosts_key_t, hosts_record_t> &pair1,
                   const pair<hosts_key_t, hosts_record_t> &pair2)
   {
      const char* ptr1 = reinterpret_cast<const char*>(&pair1.second);
      const char* ptr2 = reinterpret_cast<const char*>(&pair2.second);
      ptr1 += offset;
      ptr2 += offset;
      // If reverse order is requested, swap records
      if (ascending) {
         const char *tmp = ptr1;
         ptr1 = ptr2;
         ptr2 = tmp;
      }
      switch (size) {
         case 1: return (*(uint8_t*)ptr1 > *(uint8_t*)ptr2);
         case 2: return (*(uint16_t*)ptr1 > *(uint16_t*)ptr2);
         case 4: return (*(uint32_t*)ptr1 > *(uint32_t*)ptr2);
         case 8: return (*(uint64_t*)ptr1 > *(uint64_t*)ptr2);
         default: return (IPaddr_cpp(&pair1.first) < IPaddr_cpp(&pair2.first)); // sort by IP addresses by default
      }
   }
};


///////////////////////////////////////////////////////////////////////////////
// Get status information about the plugin     // TODO predelat
string get_status(const string &params)
{
   stringstream ss;
   ss << "processing=" << (processing_data ? 1 : 0) << ';';
   ss << "timeslot=" << last_timeslot << ';';
   ss << "flows=" << 0/*flows_loaded*/ << ';';
   ss << "hosts=" << 0/*hosts_loaded*/;
   return ss.str();
}


///////////////////////////////////////////////////////////////////////////////
// Get history of host counts
string get_host_cnt_history(const string &params)
{
   // Split params
   vector<string> vec = split(params, ';');
   if (vec.size() != 3) {
      return "ERROR: GET_HOST_CNT_HISTORY: Invalid number of parameters \""+params+"\"";
   }
   string &profile_str = vec[0];
   string &start = vec[1];
   string &end = vec[2];
   
   // Find profile with a given name
   Profile *profile = getProfile(profile_str);
   if (profile == NULL) {
      return "ERROR: GET_HOST_CNT_HISTORY: Profile \""+profile_str+"\" doesn't exist.";
   }
   
   // Get all available timeslots between start and end
   vector<string> ts = profile->database.getTimeslots(start, end);
   
   // Get number of records in each timeslot
   stringstream ss;
   for (int i = 0; i < ts.size(); i++) {
      int n = profile->database.getNumOfRecords(ts[i]);
      if (n < 0)
         continue;
      ss << ts[i] << '=' << n << ';';
   }
   char tmp;
   ss >> tmp; // remove last ';'
   
   string str = ss.str();
   return str.substr(0, str.size()-1);
}

///////////////////////////////////////////////////////////////////////////////
// Get history of flow counts
// ! not implemented yet, temporarily returns zeros !
string get_flow_cnt_history(const string &params)
{
   // Split params
   vector<string> vec = split(params, ';');
   if (vec.size() != 3)
      return "ERROR: GET_FLOW_CNT_HISTORY: Invalid number of parameters \""+params+"\"";
   string &profile_str = vec[0];
   string &start = vec[1];
   string &end = vec[2];
   
   // Find profile with a given name
   Profile *profile = getProfile(profile_str);
   if (profile == NULL) {
      return "ERROR: GET_FLOW_CNT_HISTORY: Profile \""+profile_str+"\" doesn't exist.";
   }
   
   // Get all available timeslots between start and end
   vector<string> ts = profile->database.getTimeslots(start, end);
   
   // Get number of records in each timeslot
   stringstream ss;
   for (int i = 0; i < ts.size(); i++) {
      // TODO: get number of flow records
      ss << ts[i] << '=' << 0 << ';';
   }
   char tmp;
   ss >> tmp; // remove last ';'
   
   string str = ss.str();
   return str.substr(0, str.size()-1);
}



///////////////////////////////////////////////////////////////////////////////
// Get a list of profiles
string get_profiles(const string &params)
{
   stringstream ss;
   vector<Profile*>::iterator it;

   for (it = profiles.begin(); it != profiles.end(); ++it) {
      if (it != profiles.begin()) {
         ss << ";";
      }
      ss << (*it)->name;
   }
   return ss.str();
}



///////////////////////////////////////////////////////////////////////////////
// Return list of fields of a record

string get_field_list(const string &profile)
{
   return "in_flows;in_packets;in_bytes;out_flows;out_packets;out_bytes;"
          "in_syn_cnt;in_ack_cnt;in_fin_cnt;in_rst_cnt;in_psh_cnt;in_urg_cnt;"
          "out_syn_cnt;out_ack_cnt;out_fin_cnt;out_rst_cnt;out_psh_cnt;out_urg_cnt;"
          "in_uniqueips;out_uniqueips;in_linkbitfield;out_linkbitfield";
}

///////////////////////////////////////////////////////////////////////////////
// Return top N records from a given timeslot matching given filter rule

/**
 * get_timeslot()
 * Return table with data from given timeslot matching given filter.
 *
 * @param profile Profile to get data from. 
 * @param timeslot Timeslot in YYYYMMDDhhmm format.
 * @param filter Filter object, only records matching this ilter are returned.
 * @param limit Maximum number of records to be returned. 
 * @param sort_by Name of field used to sort records before apllying limit.
 * @param ascending Sort from lowest to highest numbers when set to true.
 *
 * @return
 *    On failure - String containing information about an error.
 *    On success - Table with requested data.
 */
string get_timeslot(const Profile *profile, const string &timeslot, 
                    Synan *filter, int limit,
                    const string &sort_by="", bool ascending=false)
{
   stat_map_t stat_map;
   int e_code;
   if ((e_code = profile->database.load(timeslot, stat_map)) < 0) {
      return "ERROR: Can't load data from timeslot '"+timeslot+"' (error code: "+int2str(e_code)+")";
   }
   
   vector<pair<hosts_key_t, hosts_record_t> > result_stats;
   
   // Filter statistics
   if (filter) {
      if (filter->Execute(stat_map, result_stats) != 0)
         return "ERROR: Error when executing filter.";
   }
   else {
      result_stats.insert(result_stats.end(), stat_map.begin(), stat_map.end());
   }
   
   stat_map.clear();
   
   // Sort resulting stats
   if (!sort_by.empty()) {
      CompareFunc comp(sort_by, ascending);
      if (!comp.valid()) {
         return "ERROR: Unknown field to sort by (\""+sort_by+"\")";
      }
      sort(result_stats.begin(), result_stats.end(), comp);
   }
   
   stringstream out;
   out << "address;in_flows;in_packets;in_bytes;out_flows;out_packets;out_bytes;"
          "in_syn_cnt;in_ack_cnt;in_fin_cnt;in_rst_cnt;in_psh_cnt;in_urg_cnt;"
          "out_syn_cnt;out_ack_cnt;out_fin_cnt;out_rst_cnt;out_psh_cnt;out_urg_cnt;"
          "in_uniqueips;out_uniqueips;in_linkbitfield;out_linkbitfield\n";
   
   int i = 0;
   vector<pair<hosts_key_t, hosts_record_t> >::iterator it;
   for (it = result_stats.begin(); it != result_stats.end() && (limit < 0 || i < limit); ++it, ++i) {
      out << IPaddr_cpp(&it->first).toString() << ';';
      out << it->second.in_flows << ';';
      out << it->second.in_packets << ';';
      out << it->second.in_bytes << ';';
      out << it->second.out_flows << ';';
      out << it->second.out_packets << ';';
      out << it->second.out_bytes << ';';
      out << it->second.in_syn_cnt << ';';
      out << it->second.in_ack_cnt << ';';
      out << it->second.in_fin_cnt << ';';
      out << it->second.in_rst_cnt << ';';
      out << it->second.in_psh_cnt << ';';
      out << it->second.in_urg_cnt << ';';
      out << it->second.out_syn_cnt << ';';
      out << it->second.out_ack_cnt << ';';
      out << it->second.out_fin_cnt << ';';
      out << it->second.out_rst_cnt << ';';
      out << it->second.out_psh_cnt << ';';
      out << it->second.out_urg_cnt << ';';
      out << it->second.in_uniqueips << ';';
      out << it->second.out_uniqueips << ';';
      out << it->second.in_linkbitfield << ';';
      out << it->second.out_linkbitfield;
      out << '\n';
   }
   
   return out.str();
}

// Decode params from string format pass from frontend and call get_timeslot(...)
string get_timeslot(const string &params)
{
   // Split params
   vector<string> vec = split(params, ';');
   if (vec.size() != 6)
      return "ERROR: GET_TIMESLOT_DATA: Invalid number of parameters \""+params+"\"";
   string &profile_str = vec[0];
   string &timeslot = vec[1];
   string &filter_str = vec[2];
   string &limit_str = vec[3];
   string &sort_by = vec[4];
   string &asc_str = vec[5];
   
   // Find profile with a given name
   Profile *profile = getProfile(profile_str);
   if (profile == NULL) {
      return "ERROR: GET_TIMESLOT_DATA: Profile \""+profile_str+"\" doesn't exist.";
   }
   
   // Check timeslot
   if (timeslot.size() != 12 || timeslot.find_first_not_of("0123456789") != string::npos) {
      return "ERROR: GET_TIMESLOT_DATA: Invalid timeslot \""+timeslot+"\"";
   }
   
   // Parse and check limit
   int limit = atoi(limit_str.c_str());
   if (limit_str.find_first_not_of("0123456789") != string::npos) {
      return "ERROR: GET_TIMESLOT_DATA: Invalid limit \""+limit_str+"\"";
   }
   
   // Create filter
   Synan *filter = NULL;
   if (!filter_str.empty())
      filter = new Synan(filter_str);
   
   // Check sort_by
   // TODO
   
   // Parse ascending-sort flag
   bool asc = (asc_str == "1");
   
   string ret = get_timeslot(profile, timeslot, filter, limit, sort_by, asc);
   
   if (filter)
      delete filter;
   return ret;
}



struct SimpleStats {
   uint32_t in_flows;
   uint32_t out_flows;
   uint64_t in_packets;
   uint64_t out_packets;
   uint64_t in_bytes;
   uint64_t out_bytes;
};

/**
 * get_timeslot_ipmap()
 * TODO
 *
 * @param profile Profile to get data from. 
 * @param timeslot Timeslot in YYYYMMDDhhmm format.
 *
 * @return
 *    On failure - String containing information about an error.
 *    On success - Table with requested data.
 */
string get_timeslot_ipmap(const Profile *profile, const string &timeslot,
                          uint32_t prefix, int prefix_len) 
{
   if (prefix_len < 0 || prefix_len > 16) {
      return "ERROR: Invalid prefix length (it must be between 0 and 16)";
   }
   
   stat_map_t stat_map;
   int e_code;
   if ((e_code = profile->database.load(timeslot, stat_map)) < 0) {
      return "ERROR: Can't load data from timeslot '"+timeslot+"' (error code: "+int2str(e_code)+")";
   }
   
   // Get range of IP addresses with given prefix
   uint32_t range_start = prefix & ~((1 << (32 - prefix_len)) - 1);
   uint32_t range_end = prefix | ((1 << (32 - prefix_len)) - 1);
   if (prefix_len == 0) {
      range_start = 0x00000000;
      range_end = 0xffffffff;
   }
   
   // Aggregate IP addresses by next 16 bits following the prefix
   map<uint32_t, SimpleStats> prefix_stats;
   for (stat_map_iter it = stat_map.begin(); it != stat_map.end(); ++it) {
      if (ip_is6(&it->first)) // Skip IPv6
         continue;
      
      uint32_t addr = it->first.ui32[2];
      if (addr < range_start || addr > range_end)
         continue;
      
      addr = range_start | (addr & (0x0000ffff << (16 - prefix_len)));
      
      prefix_stats[addr].in_flows += it->second.in_flows;
      prefix_stats[addr].out_flows += it->second.out_flows;
      prefix_stats[addr].in_packets += it->second.in_packets;
      prefix_stats[addr].out_packets += it->second.out_packets;
      prefix_stats[addr].in_bytes += it->second.in_bytes;
      prefix_stats[addr].out_bytes += it->second.out_bytes;
   }
   
   stringstream out;
   out << "prefix;in_flows;in_packets;in_bytes;out_flows;out_packets;out_bytes\n";
   
   int i = 0;
   for (map<uint32_t, SimpleStats>::const_iterator it = prefix_stats.begin(); it != prefix_stats.end(); ++it) {
      ip_addr_t tmp = ip_from_int(it->first);
      out << IPaddr_cpp(&tmp).toString() << ';';
      out << it->second.in_flows << ';';
      out << it->second.in_packets << ';';
      out << it->second.in_bytes << ';';
      out << it->second.out_flows << ';';
      out << it->second.out_packets << ';';
      out << it->second.out_bytes << '\n';
   }
   return out.str();
}

string get_timeslot_ipmap(const string &params)
{
   // Split params
   vector<string> vec = split(params, ';');
   if (vec.size() != 4)
      return "ERROR: GET_TIMESLOT_IPMAP: Invalid number of parameters \""+params+"\"";
   string &profile_str = vec[0];
   string &timeslot = vec[1];
   string &prefix_str = vec[2];
   string &prefix_len_str = vec[3];
   
   // Find profile with a given name
   Profile *profile = getProfile(profile_str);
   if (profile == NULL) {
      return "ERROR: GET_TIMESLOT_IPMAP: Profile \""+profile_str+"\" doesn't exist.";
   }
   
   // Check timeslot
   if (timeslot.size() != 12 || timeslot.find_first_not_of("0123456789") != string::npos) {
      return "ERROR: GET_TIMESLOT_IPMAP: Invalid timeslot \""+timeslot+"\"";
   }
   
   // Parse and check prefix length
   int prefix_len = atoi(prefix_len_str.c_str());
   if (prefix_len < 0 || prefix_len > 16 || prefix_len_str.find_first_not_of("0123456789") != string::npos) {
      return "ERROR: GET_TIMESLOT_IPMAP: Invalid prefix length \""+prefix_len_str+"\"";
   }
   
   // Parse prefix
   ip_addr_t prefix_ip;
   if (ip_from_str(prefix_str.c_str(), &prefix_ip) != 1 || ip_is6(&prefix_ip)) {
      return "ERROR: GET_TIMESLOT_IPMAP: Invalid prefix \""+prefix_str+"\"";
   }
   
   return get_timeslot_ipmap(profile, timeslot, (uint32_t)prefix_ip.ui32[2], prefix_len);
}



///////////////////////////////////////////////////////////////////////////////
// Return all records of one host in given time range

/**
 * get_host_history()
 * Return all records of one host in time range between timestart and timeend (inclusive).
 *
 * @param profile Profile to get data from. 
 * @param address Address of the host.
 * @param timestart First requested timeslot.
 * @param timeend Last requested timeslot. 
 *
 * @return
 *    On failure - String containing information about an error.
 *    On success - Table with requested data.
 */
string get_host_history(const Profile *profile, const hosts_key_t &address,
                        const string &timestart, const string &timeend)
{
   if (timeend < timestart)
      return "ERROR: End time is before start time.";
   
   // Get all available timeslots between timestart and timeend
   vector<string> ts = profile->database.getTimeslots(timestart, timeend);
   if (ts.empty())
      return "ERROR: No data available between timeslots "+timestart+" and "+timeend+".";
   
   stringstream out;
   out << "timeslot;in_flows;in_packets;in_bytes;out_flows;out_packets;out_bytes;"
          "in_syn_cnt;in_ack_cnt;in_fin_cnt;in_rst_cnt;in_psh_cnt;in_urg_cnt;"
          "out_syn_cnt;out_ack_cnt;out_fin_cnt;out_rst_cnt;out_psh_cnt;out_urg_cnt;"
          "in_uniqueips;out_uniqueips;in_linkbitfield;out_linkbitfield\n";
   
   for (vector<string>::iterator it = ts.begin(); it != ts.end(); ++it) {
      // Get record from file
      hosts_record_t rec;
      int ret = profile->database.getRecord(*it, address, rec);
      if (ret < 0) {
         out << *it << ";ERROR: Can't open file (error code: "+int2str(ret)+")\n";
         continue; // Can't find/open file or wrong format
      }
      // Print record values
      out << *it << ';';
      out << rec.in_flows << ';';
      out << rec.in_packets << ';';
      out << rec.in_bytes << ';';
      out << rec.out_flows << ';';
      out << rec.out_packets << ';';
      out << rec.out_bytes << ';';
      out << rec.in_syn_cnt << ';';
      out << rec.in_ack_cnt << ';';
      out << rec.in_fin_cnt << ';';
      out << rec.in_rst_cnt << ';';
      out << rec.in_psh_cnt << ';';
      out << rec.in_urg_cnt << ';';
      out << rec.out_syn_cnt << ';';
      out << rec.out_ack_cnt << ';';
      out << rec.out_fin_cnt << ';';
      out << rec.out_rst_cnt << ';';
      out << rec.out_psh_cnt << ';';
      out << rec.out_urg_cnt << ';';
      out << rec.in_uniqueips << ';';
      out << rec.out_uniqueips << ';';
      out << rec.in_linkbitfield << ';';
      out << rec.out_linkbitfield;
      out << '\n';
   }
   return out.str();
}

string get_host_history(const string &params)
{
   // Split params
   vector<string> vec = split(params, ';');
   if (vec.size() != 4)
      return "ERROR: GET_HOST_HISTORY: Invalid number of parameters \""+params+"\"";
   string &profile_str = vec[0];
   string &addr_str = vec[1];
   string &timestart = vec[2];
   string &timeend = vec[3];
   
   // Find profile with a given name
   Profile *profile = getProfile(profile_str);
   if (profile == NULL) {
      return "ERROR: GET_HOST_HISTORY: Profile \""+profile_str+"\" doesn't exist.";
   }
   
   // Check timeslots
   if (timestart.size() != 12 || timestart.find_first_not_of("0123456789") != string::npos) {
      return "ERROR: GET_HOST_HISTORY: Invalid start timeslot \""+timestart+"\"";
   }
   if (timeend.size() != 12 || timeend.find_first_not_of("0123456789") != string::npos) {
      return "ERROR: GET_HOST_HISTORY: Invalid end timeslot \""+timeend+"\"";
   }
   
   // Parse address
   ip_addr_t address;
   if (ip_from_str(addr_str.c_str(), &address) != 1) {
      return "ERROR: Invalid IP address \""+addr_str+"\""; 
   }
   
   return get_host_history(profile, address, timestart, timeend);
}


// no parameter, returns list of days (%y%m%d) with detection log available 
string get_detection_log_list(const string &params)
{
   vector<string> times;
    
   Configuration *config = Configuration::getInstance();
   config->lock();
   string path = config->getValue("detection-log");
   config->unlock();
   
   log(LOG_NOTICE, path.c_str());
   
   // Open directory
   DIR *dir = opendir(path.c_str());
   if (!dir) {
      log(LOG_ERR, "get_detection_log_list: Can't open directory '%s': %s\n", path.c_str(), strerror(errno));
      return "ERROR: Can't open directory '"+path+"': "+strerror(errno);
   }
   
   // Get all entries in directory
   dirent *entry;
   while (entry = readdir(dir)) {
      string name = string(entry->d_name);
      
      //log(LOG_DEBUG, "GET_DETECTION_LOG_LIST: %s", name.c_str());
      
      // Check if a name matches "%y%m%d.log"
      if (name.length() != 12 || name.substr(8,4) != ".log")
         continue;
      name = name.substr(0,8);
      if (name.find_first_not_of("0123456789") != string::npos)
         continue;
      
      times.push_back(name);
   }
   
   // Close directory
   closedir(dir);
   
   // Sort times and return them in one string
   sort(times.begin(), times.end());
   
   string str;
   for (int i = 0; i < times.size(); i++) {
      str += times[i];
      str += '\n';
   }
   log(LOG_DEBUG, "GET_DETECTION_LOG_LIST: %s", str.c_str());
   return str;
}

// parameter = day of requested log file (%y%m%d)
string get_detection_log(const string &params)
{
   char buffer[1024];
   string ret;
   
   Configuration *config = Configuration::getInstance();
   config->lock();
   string path = config->getValue("detection-log");
   config->unlock();
   
   if (path[path.size()-1] != '/')
      path += '/';
   
   ifstream file((path+params+".log").c_str());
   
   while(file.good()) {
      file.read(buffer, 1024);
      ret.append(buffer, file.gcount());
   }
   
   file.close();
   
   return ret;
}
