#ifndef _SUBPROFILES_H_
#define _SUBPROFILES_H_

#include <string>
#include <stdint.h>

#include "config.h"
#include "hoststats.h"
#include "detectionrules.h"

extern "C" {
   #include <unirec/unirec.h>
}

// Direction flag for subprofile update functions
#define DIR_OUT 0x0
#define DIR_IN  0x1


// Function pointer to subprofile update function
typedef bool (*sp_update)(hosts_record_t&, const void *, const ur_template_t *, char);

// Function pointer to check record function of a subprofile
typedef bool (*sp_check)(const hosts_key_t&, const hosts_record_t&);

// Function pointer to delete subprofile function
typedef bool (*sp_delete)(hosts_record_t&);


// Structure with information about subprofile 
struct subprofile_t{
   std::string name;
   bool sp_status;    // active (1) or inactive (0)
   std::string detector_name;
   bool detector_status;   // active (1) or inactive (0)
   sp_update update_ptr;
   sp_check check_ptr;
   sp_delete delete_ptr;

   // Structure constructor
   subprofile_t(std::string name, std::string detector_name, sp_update update_ptr,
      sp_check check_ptr, sp_delete delete_ptr)
      :  name(name), detector_name(detector_name), update_ptr(update_ptr), 
         check_ptr(check_ptr), delete_ptr(delete_ptr)
   {
   }

   // Load status information from configuration file
   void check_config() {
      Configuration *conf = Configuration::getInstance();
      conf->lock();
      sp_status =       (conf->getValue(name) == "1");
      detector_status = (conf->getValue(detector_name) == "1"); 
      conf->unlock();
   }

   // Operator overloading for sort function
   bool operator<(const subprofile_t &b) const {
      return (sp_status && !b.sp_status) || 
               (sp_status == b.sp_status && detector_status && !b.detector_status);
   }
};

/******************************* DNS subprofile *******************************/
// record structure
struct dns_record_t {
   uint32_t in_dns_flows;
   uint32_t out_dns_flows;

   dns_record_t() {
      memset(this, 0, sizeof(dns_record_t));
   }
} __attribute((packed));

// class
class DNSHostProfile {
private:
   dns_record_t record;

   // Flow filter for update function
   static bool flow_filter(const void *data, const ur_template_t *tmplt);

public:
   // Update a DNS subprofile
   static bool update(hosts_record_t &record, const void *data, 
      const ur_template_t *tmplt, char dir_flag);

   // Check rules in a DNS subprofile
   static bool check_record(const hosts_key_t &key, const hosts_record_t &record);

   // Remove a subprofile from a main profile
   static bool delete_record(hosts_record_t &record);
};

/******************************* SSH subprofile *******************************/
// record structure
struct ssh_record_t {
   uint32_t in_ssh_flows;
   uint32_t out_ssh_flows;

   ssh_record_t() {
      memset(this, 0, sizeof(ssh_record_t));
   }
} __attribute((packed));

// class
class SSHHostProfile {
private:
   ssh_record_t record;

   // Flow filter for update function
   static bool flow_filter(const void *data, const ur_template_t *tmplt);

public:
   // Update a SSH subprofile
   static bool update(hosts_record_t &record, const void *data, 
      const ur_template_t *tmplt, char dir_flag);

   // Check rules in a SSH subprofile
   static bool check_record(const hosts_key_t &key, const hosts_record_t &record);

   // Remove a subprofile from a main profile
   static bool delete_record(hosts_record_t &record);
};

#endif