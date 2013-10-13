#ifndef _HOSTSTATS_H_
#define _HOSTSTATS_H_

#include <stdint.h>
#include <string.h>
#include <map>
#include <vector>
#include <pthread.h>

#include "../../../../unirec/ipaddr_cpp.h"

extern "C" {
   #include "../../../../unirec/ipaddr.h"
   #include "../../../../common/cuckoo_hash_v2/cuckoo_hash.h"
}

/////////////////////////////////////////////////////////////////
// List of subprofiles
class DNSHostProfile;
class SSHHostProfile;

// Record with statistics about a host
// TODO: update this comment !!! 
struct hosts_record_t {
   uint32_t in_all_flows;
   uint16_t in_req_flows;
   uint16_t in_rsp_flows;
   uint16_t in_sf_flows;
   uint16_t in_req_packets;
   uint32_t in_all_packets;
   uint16_t in_req_bytes;
   uint32_t in_all_bytes;
   uint16_t in_req_rst_cnt;
   uint16_t in_all_rst_cnt;
   uint16_t in_req_psh_cnt;
   uint16_t in_all_psh_cnt;
   uint16_t in_req_ack_cnt;
   uint16_t in_all_ack_cnt;
   uint16_t in_all_syn_cnt;
   uint16_t in_all_fin_cnt;
   uint16_t in_all_urg_cnt;
   uint16_t in_req_uniqueips;
   uint16_t in_all_uniqueips;
   uint32_t in_linkbitfield;

   uint32_t out_all_flows;
   uint16_t out_req_flows;
   uint16_t out_rsp_flows;
   uint16_t out_sf_flows;
   uint16_t out_req_packets;
   uint32_t out_all_packets;
   uint16_t out_req_bytes;
   uint32_t out_all_bytes;
   uint16_t out_req_rst_cnt;
   uint16_t out_all_rst_cnt;
   uint16_t out_req_psh_cnt;
   uint16_t out_all_psh_cnt;
   uint16_t out_req_ack_cnt;
   uint16_t out_all_ack_cnt;
   uint16_t out_all_syn_cnt;
   uint16_t out_all_fin_cnt;
   uint16_t out_all_urg_cnt;
   uint16_t out_req_uniqueips;
   uint16_t out_all_uniqueips;
   uint32_t out_linkbitfield;

   uint32_t first_rec_ts; // timestamp of first flow
   uint32_t last_rec_ts;  // timestamp of last flow

   DNSHostProfile *dnshostprofile;
   SSHHostProfile *sshhostprofile;


   hosts_record_t() { // Constructor sets all values to zeros.
      memset(this, 0, sizeof(hosts_record_t));
   }
} __attribute__((packed));


typedef ip_addr_t hosts_key_t;

// hash table
typedef cc_hash_table_v2_t stat_table_t;

// struct class_comp {
//    bool operator() (const ip_addr_t& first, const ip_addr_t& second) const
//    {
//       return IPaddr_cpp(&first) < IPaddr_cpp(&second);   
//    }
// };

// INFO: stat_map_t was replaced by stat_table_t, but stat_map_t can be used
//       in another functions (database, request_handler) 
// typedef std::map<hosts_key_t, hosts_record_t, class_comp> stat_map_t;
// typedef stat_map_t::iterator stat_map_iter;
// typedef stat_map_t::const_iterator stat_map_citer;


// The identification of item to remove from stat_table
typedef struct remove_item_s {
   hosts_key_t key;

   bool operator== (const remove_item_s& second) const
   {
      return (memcmp(&key, &second.key, sizeof(hosts_key_t)) == 0);   
   }
} remove_item_t;

// Shared structure for TRAP reader and process threads
typedef struct thread_share_s {
   pthread_t data_reader_thread;
   pthread_t data_process_thread;
   pthread_mutex_t det_processing;
   pthread_mutex_t remove_mutex;                // to protect remove_vector
   std::vector<remove_item_t> remove_vector;    // items to remove from stat_map
   bool remove_ready;                           // info about remove_vector 

   thread_share_s() { // Constructor
      pthread_mutex_init(&det_processing, NULL);
      pthread_mutex_init(&remove_mutex, NULL);
      remove_vector.reserve(1024);
      remove_ready = false;
   }

   ~thread_share_s() { // Destructor
      pthread_mutex_destroy(&det_processing);
      pthread_mutex_destroy(&remove_mutex);
   }
} thread_share_t;

////////////////////////////////////

// Status information
//TODO: check if this still exists
extern bool processing_data;

#endif
