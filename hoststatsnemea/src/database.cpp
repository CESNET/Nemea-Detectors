#include <string>
#include <vector>
#include <fstream>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <algorithm>

#include "aux_func.h"
#include "config.h"
#include "database.h"

using namespace std;

const char *struct_spec = "address,16"
   ";in_all_flows,4;in_req_flows,2;in_rsp_flows,2;in_sf_flows,2;in_req_packets,2"
   ";in_all_packets,4;in_req_bytes,2;in_all_bytes,4;in_req_rst_cnt,2"
   ";in_all_rst_cnt,2;in_req_psh_cnt,2;in_all_psh_cnt,2;in_req_ack_cnt,2"
   ";in_all_ack_cnt,2;in_all_syn_cnt,2;in_all_fin_cnt,2;in_all_urg_cnt,2"
   ";in_req_uniqueips,2;in_all_uniqueips,2;in_linkbitfield,4"
   ";out_all_flows,4;out_req_flows,2;out_rsp_flows,2;out_sf_flows,2;out_req_packets,2"
   ";out_all_packets,4;out_req_bytes,2;out_all_bytes,4;out_req_rst_cnt,2"
   ";out_all_rst_cnt,2;out_req_psh_cnt,2;out_all_psh_cnt,2;out_req_ack_cnt,2"
   ";out_all_ack_cnt,2;out_all_syn_cnt,2;out_all_fin_cnt,2;out_all_urg_cnt,2"
   ";out_req_uniqueips,2;out_all_uniqueips,2;out_linkbitfield,4"
   ";first_rec_ts,4;last_rec_ts,4"
   "\n";

Database::Database(const std::string& profile_name)
 : profile_name(profile_name)
{
   reloadConfig();
}

int Database::connect()
{
   if (path.empty())
      return -1;
   // Create a directory for profile if it doesn't exist
   if (mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
      if (errno != EEXIST) {
         log(LOG_ERR, "Database: Can't create directory \"%s\": %s",
             path.c_str(), strerror(errno));
         return -2;
      }
   }
   // TODO: check whether we can read/write from/into path
   
   return 0; 
}

int Database::disconnect()
{
   return 0;
}


// TODO: zaridit, aby se toto zavolalo pri reloadu konfigurace
int Database::reloadConfig()
{
   // Load configuration
   Configuration *config = Configuration::getInstance();
   config->lock();
   path = config->getValue("db-path");
   string read_only_str = config->getValue("db-read-only");
   db_cleaner = config->getValue("db-cleaner");
   max_db_size = config->getValue("db-max-size");
   config->unlock();
   
   if (path.empty())
      return -1;
   
   // Make sure that path ends with '/'
   if (path[path.size()-1] != '/')
      path += '/';
   
   // Append profile_name to path
   path += profile_name + '/';
   
   // Parse read_only string
   if (read_only_str == "1" || read_only_str == "true" || read_only_str == "yes")
      read_only = true;
   else
      read_only = false;
   
   // Reconnect database
   disconnect();
   connect();
   
   return 0;
}

// Run database cleaner script, if defined
int Database::cleanup() const
{
   if (db_cleaner.empty() || max_db_size.empty())
      return -1;
      
   // Prepare command
   string command = db_cleaner + " " + path + " " + max_db_size;
   log(LOG_DEBUG, "Running database cleaner: '%s'", command.c_str());
   // Run the command and wait for result
   if (system(command.c_str()) != 0)  {
      log(LOG_ERR, "Database cleaner exited with error.");
      return -2;
   }
   return 0;
}

int Database::store(const std::string &timeslot, const stat_map_t &stat_map) const
{
   if (path.empty())
      return -1;
   if (read_only) {
      return 1;
   }
   
   // Run database cleaner script
   cleanup();
   
   // Store data into a file
   string filename = path + "hs." + timeslot;
   int ret = storeToFile(filename, stat_map);
   if (ret != 0) {
      return ret; // some error occured
   }
   
   log(LOG_DEBUG, "Statistics stored into '%s'", filename.c_str());
   return 0;
}


int Database::storeToFile(const string &filename, const stat_map_t &stat_map)
{
   // Open a file
   ofstream file(filename.c_str(), ofstream::out | ofstream::trunc | ofstream::binary);
   
   if (!file.good()) {
      file.close();
      log(LOG_ERR, "Database: Can't open file '%s' for writing.", filename.c_str());
      return -1; // Error when opening file
   }
   
   // Write file header
   uint16_t spec_len = string(struct_spec).size();
   file.write("HS\001\000", 4); // file type identification and version
   file.write((char*)(&spec_len), 2); // length of struct specification string
   file.write(struct_spec, spec_len); // specification string
   
   // Write data
   for (stat_map_t::const_iterator it = stat_map.begin(); it != stat_map.end(); ++it) {
      file.write(reinterpret_cast<const char*>(&it->first), sizeof(it->first)); // address
      file.write(reinterpret_cast<const char*>(&it->second), sizeof(it->second)); // statistics
   }
   
   if (!file.good()) {
      log(LOG_ERR, "Database: Some error has occured during writing into file '%s'.", filename.c_str());
      file.close();
      return -2;
   }
   
   // Close file
   file.close();
   return 0;
}


int Database::load(const string &timeslot, stat_map_t &stat_map) const
{
   if (path.empty())
      return -1;
   
   // Open file for reading
   string filename = path + "hs." + timeslot;
   ifstream file(filename.c_str(), ifstream::in | ifstream::binary);
   
   if (!file.good()) {
      file.close();
      log(LOG_ERR, "Database: Can't open file '%s' for reading.", filename.c_str());
      return -2; // Error when opening file
   }
   
   // Read file header
   char *buffer = new char[6];
   file.read(buffer, 6);
   
   if (!file.good() || buffer[0] != 'H' || buffer[1] != 'S') {
      file.close();
      delete[] buffer;
      return -3; // not a valid HostStats file
   }
   if (buffer[2] != '\001' || buffer[3] != '\000') {
      file.close();
      delete[] buffer;
      return -4; // unknown file version
   }
   uint16_t spec_len = *(uint16_t*)(buffer + 4);
   
   delete[] buffer;
   buffer = new char[spec_len+1];
   file.read(buffer, spec_len);
   buffer[spec_len] = '\0';
   
   if (!file.good()) {
      file.close();
      delete[] buffer;
      return -5;
   }
   
   // Read all records
   stat_map.clear();
   if (string(struct_spec) == buffer) {
      // It's in the same format as the hosts_record_t, read directly into the struct
      hosts_key_t key;
      hosts_record_t rec;
      
      while (1) { 
         file.read((char*)&key, sizeof(key));
         file.read((char*)&rec, sizeof(rec));
         if (!file.good())
            break;
         stat_map.insert(make_pair(key,rec));
      }
   }
   else {
      // format is different from hosts_record_t, read field by field
      log(LOG_ERR, "Database: Records in file '%s' have unknown format, can't read.", filename.c_str());
      // TODO
      delete[] buffer;
      file.close();
      return -10;
   }
   
   // Cleanup
   delete[] buffer;
   file.close();
   
   // Return records
   return stat_map.size();
}

// When record is found, store it into rec and return 0. Otherwise return error code.
int Database::getRecord(const string& timeslot, const hosts_key_t &key, hosts_record_t &rec) const
{
   if (path.empty())
      return -1;
   
   // Open file for reading
   string filename = path + "hs." + timeslot;
   ifstream file(filename.c_str(), ifstream::in | ifstream::binary);
   
   if (!file.good()) {
      file.close();
      return -2; // Error when opening file
   }
   
   // Read file header
   char *buffer = new char[6];
   file.read(buffer, 6);
   
   if (!file.good() || buffer[0] != 'H' || buffer[1] != 'S') {
      file.close();
      delete buffer;
      return -3; // not a valid HostStats file
   }
   if (buffer[2] != '\001' || buffer[3] != '\000') {
      file.close();
      delete buffer;
      return -4; // unknown file version
   }
   uint16_t spec_len = *(uint16_t*)(buffer + 4);
   
   delete[] buffer;
   buffer = new char[spec_len+1];
   file.read(buffer, spec_len);
   buffer[spec_len] = '\0';
   
   if (!file.good()) {
      file.close();
      delete[] buffer;
      return -5;
   }
   
   // Find record
   bool found = false;
   if (string(struct_spec) == buffer) {
      // It's in the same format as the hosts_record_t, read directly into the struct

      // Get number of records in the file
      file.seekg(0, istream::end);
      long filelen = file.tellg();
      file.seekg(0, istream::beg);
      long header_size = spec_len + 6;
      const int record_size = sizeof(hosts_key_t) + sizeof(hosts_record_t); 
      long n = (filelen - header_size) / record_size;
      
      // Find a record with given field using binary search (records are stored sorted)
      hosts_key_t my_key;
      long a = 0;
      long b = n-1;
      while (a <= b) {
         long i = (a+b)/2;
         file.seekg(header_size + i*record_size);
         file.read((char*)&my_key, sizeof(hosts_key_t));
         if (IPaddr_cpp(&key) < IPaddr_cpp(&my_key)) {
            b = i-1;
         }
         else if (IPaddr_cpp(&key) > IPaddr_cpp(&my_key)) {
            a = i+1;
         }
         else { // Found
            file.read((char*)&rec, sizeof(hosts_record_t));
            found = true;
            break;
         }
      }
      // **********
   }
   else {
      // format is different from hosts_record_t, read field by field
      
      // TODO
      log(LOG_ERR, "Database: Records in file '%s' have unknown format, can't read.", filename.c_str());
      delete[] buffer;
      file.close();
      return -10;
   }
   
   // Cleanup
   delete[] buffer;
   file.close();
   
   // If record was not found, fill rec with zeros
   if (!found) {
      memset(&rec, 0, sizeof(rec));
      return 1;
   }
   return 0;
}




// Return list of all available timeslots between given start and end (inclusive)
vector<string> Database::getTimeslots(const string &start, const string &end) const
{
   vector<string> timeslots;
   
   if (path.empty()) {
      log(LOG_ERR, "getTimeslots: Path to files with statistics is not set.");
      return timeslots;
   }
   
   // Open directory
   DIR *dir = opendir(path.c_str());
   if (!dir) {
      log(LOG_ERR, "getTimeslots: Can't open directory '%s': %s\n", path.c_str(), strerror(errno));
      return timeslots;
   }
   
   // Get all entries in directory
   dirent *entry;
   while (entry = readdir(dir)) {
      string name = string(entry->d_name);
      
      // Check if the name matches "hs.[0-9]{12}"
      if (name.length() != 15 || name.substr(0,3) != "hs.")
         continue;
      name = name.substr(3);
      if (name.find_first_not_of("0123456789") != string::npos)
         continue;
      
      // If start and end times are specified, check if name is between them
      if (!start.empty() && name < start)
         continue;
      if (!end.empty() && name > end)
         continue;
      
      // Store name in list of matching timeslots
      timeslots.push_back(name);
   }
   
   // Sort timeslots
   sort(timeslots.begin(), timeslots.end());
   
   // Close directory
   closedir(dir);
   return timeslots;
}


// Return number of records in a file.
// On error return negative value.
int Database::getNumOfRecords(const string &timeslot) const
{
   if (path.empty()) {
      log(LOG_ERR, "getNumOfRecords: Path to files with statistics is not set.");
      return -1;
   }
   
   // Get number of records in the file
   struct stat st;
   string filename = path + "hs." + timeslot;
   if (stat(filename.c_str(), &st) != 0) {
      log(LOG_ERR, "getNumOfRecords: Can't stat file \"%s\": %s", filename.c_str(), strerror(errno));
      return -2;
   }
   long filelen = st.st_size;
   int spec_len = string(struct_spec).size();
   long header_size = spec_len + 6;
   const int record_size = sizeof(hosts_key_t) + sizeof(hosts_record_t); 
   return ((filelen - header_size) / record_size);
}



