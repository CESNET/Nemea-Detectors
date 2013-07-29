#ifndef _HOSTSTATS_H_
#define _HOSTSTATS_H_

#include <stdint.h>
#include <string.h>
#include <map>
#include <vector>
#include <pthread.h>

#include "../../../../unirec/ipaddr_cpp.h"
#include "../../../../unirec/ipaddr.h"

/////////////////////////////////////////////////////////////////
// Global struct and type definitions

// Flow record
struct flow_record_t {
   uint64_t packets;
   uint64_t bytes;
   uint8_t tcp_flags;
   uint64_t linkbitfield; // each bit denotes the link a flow record has been seen
   uint8_t dirbitfield; // 0x10 means incoming from abroad, 0x01 means outgoing

   flow_record_t() {
      packets = 0;
      bytes = 0;
      tcp_flags = 0;
      linkbitfield = 0x0;
      dirbitfield = 0x0;
   }
};

// Flow key
struct flow_key_t{
   ip_addr_t sad;
   ip_addr_t dad;
   uint16_t sport;
   uint16_t dport;
   uint8_t proto;

   flow_key_t() { // Constructor sets all values to zeros.
      memset(this, 0, sizeof(flow_key_t));
   }

   bool operator<(const flow_key_t &key2) const {
      return (IPaddr_cpp(&sad) < IPaddr_cpp(&key2.sad) || (IPaddr_cpp(&sad) == IPaddr_cpp(&key2.sad) && 
                (IPaddr_cpp(&dad) < IPaddr_cpp(&key2.dad) || (IPaddr_cpp(&dad) == IPaddr_cpp(&key2.dad) &&
                   (sport < key2.sport || (sport == key2.sport &&
                      (dport < key2.dport || (dport == key2.dport &&
                         (proto < key2.proto) )))))))); 
    }
};

// flow-key -> flow_record map
typedef std::map<flow_key_t, flow_record_t> flow_map_t;
typedef flow_map_t::iterator flow_map_iter;

// vector of flow maps
typedef std::vector<flow_map_t> flow_map_vector_t;
typedef flow_map_vector_t::iterator flow_map_vector_iter;

///////////////////////

// Record with statistics about a host
// ** If you change this struct, you MUST also change struct_spec in 
//    database.cpp and get_field_offset in requesthandlers.cpp! **
struct hosts_record_t {
   uint32_t in_flows;
   uint32_t out_flows;
   uint64_t in_packets;
   uint64_t out_packets;
   uint64_t in_bytes;
   uint64_t out_bytes;
   uint32_t in_syn_cnt;
   uint32_t out_syn_cnt;
   uint32_t in_ack_cnt;
   uint32_t out_ack_cnt;
   uint32_t in_fin_cnt;
   uint32_t out_fin_cnt;
   uint32_t in_rst_cnt;
   uint32_t out_rst_cnt;
   uint32_t in_psh_cnt;
   uint32_t out_psh_cnt;
   uint32_t in_urg_cnt;
   uint32_t out_urg_cnt;
   uint32_t in_uniqueips;
   uint32_t out_uniqueips;
   uint64_t in_linkbitfield;
   uint64_t out_linkbitfield;

   hosts_record_t() { // Constructor sets all values to zeros.
      memset(this, 0, sizeof(hosts_record_t));
   }
} __attribute__((packed));

typedef ip_addr_t hosts_key_t;

struct class_comp {
   bool operator() (const ip_addr_t& first, const ip_addr_t& second) const
   {
         return IPaddr_cpp(&first) < IPaddr_cpp(&second);   
   }
};

// key->record map
typedef std::map<hosts_key_t, hosts_record_t, class_comp> stat_map_t;
typedef stat_map_t::iterator stat_map_iter;
typedef stat_map_t::const_iterator stat_map_citer;

// Function for flow filtering (used by profiles)
typedef bool (*flow_filter_func_ptr)(const flow_key_t&, const flow_record_t&);

// Pthread mutex
typedef struct stat_map_mutex{
   pthread_mutex_t swap_mutex; 
   pthread_mutex_t start_processing;

   stat_map_mutex() { // Constructor init all mutexes
      pthread_mutex_init(&swap_mutex, NULL);
      pthread_mutex_init(&start_processing, NULL);
      pthread_mutex_lock(&start_processing);
   }

   ~stat_map_mutex() { // Destructor
      pthread_mutex_destroy(&swap_mutex);
      pthread_mutex_unlock(&start_processing);
      pthread_mutex_destroy(&start_processing);
   }

} stat_map_mutex_t;

////////////////////////////////////
// Declaration of global variables

extern stat_map_t stat_map; // Main host statictics

// Status information
extern bool processing_data;
extern bool data_available;
extern unsigned int flows_loaded;
extern unsigned int hosts_loaded;
extern std::string timeslot;

#endif
