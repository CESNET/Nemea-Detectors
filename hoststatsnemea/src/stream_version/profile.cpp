#include "profile.h"
#include "../aux_func.h"

#include "processdata.h"

using namespace std;

#define DEF_SIZE (1000000)

extern uint32_t hs_time;

// DEFAULT VALUES OF THE MAIN PROFILE (in seconds)
#define D_ACTIVE_TIMEOUT   300   // default value (in seconds)
#define D_INACTIVE_TIMEOUT 30    // default value (in seconds)
#define D_DET_START_PAUSE  5     // default time between starts of detector (in seconds)

// Direction flag for subprofile update functions
#define DIR_OUT 0x0
#define DIR_IN  0x1


/* -------------------- MAIN PROFILE -------------------- */

HostProfile::HostProfile()
{
   // Fill vector of subprofiles 
   subprofile_t sp_dns("dns", "rules-dns", DNSHostProfile::update,
      DNSHostProfile::check_record, DNSHostProfile::delete_record);
   sp_list.push_back(sp_dns);

   subprofile_t sp_ssh("ssh", "rules-ssh", SSHHostProfile::update,
      SSHHostProfile::check_record, SSHHostProfile::delete_record);
   sp_list.push_back(sp_ssh);

   // Load configuration
   apply_config();

   // Initialization of cuckoo hash (v2) table
   int rc;
   rc = ht_init_v2(&stat_table, table_size, sizeof(hosts_record_t), sizeof(hosts_key_t));
   if (rc != 0) {
      // TODO: ukončení programu
      return;
   }

   stat_table_ptr = &stat_table;

   // Create BloomFilters
   bloom_parameters bp;
   bp.projected_element_count = 5000000;
   bp.false_positive_probability = 0.01;
   bp.compute_optimal_parameters();
   //log(LOG_INFO, "process_data: Creating Bloom Filter, table size: %d, hashes: %d",
   //    bp.optimal_parameters.table_size, bp.optimal_parameters.number_of_hashes);
   bf_active = new bloom_filter(bp);
   bf_learn = new bloom_filter(bp);
}

HostProfile::~HostProfile()
{
   // Remove all subprofiles
   for (unsigned int i = 0; i < table_size; ++i) 
   {
      if (stat_table_ptr->ind[i].valid != 1) {
         continue;
      }

      int index = stat_table_ptr->ind[i].index;
      hosts_record_t &temp = *((hosts_record_t *)stat_table_ptr->data[index]);

      for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
         it->delete_ptr(temp);
      }
   }

   // Delete cuckoo hash table (v2)
   ht_destroy_v2(stat_table_ptr);

   // Delete BloomFilters
   delete bf_active;
   delete bf_learn;
}

int HostProfile::reload_config()
{
   // FIXME: pozastavit všechna ostatní vlákna během vykonávání této funkce,
   //       dostat je do neutrálního stavu... hrozí zvětšování tabulky,
   //       a změna jiných kritických parametrů vedoucích až k pádu...

   apply_config();

   if (table_size != stat_table_ptr->table_size) {
      return rehash_v2(stat_table_ptr);
   }

   return 0;
}

/*
 * apply_config()
 * Load configuration data and update profile (and subprofiles) variables 
 */
void HostProfile::apply_config()
{
   Configuration *conf = Configuration::getInstance();
   conf->lock();
   table_size =       atoi(conf->getValue("table-size").c_str());
   active_timeout =   atoi(conf->getValue("timeout-active").c_str());
   inactive_timeout = atoi(conf->getValue("timeout-inactive").c_str());
   det_start_time =   atoi(conf->getValue("det_start_time").c_str());
   detector_status =  (conf->getValue("rules-generic") == "1"); 
   conf->unlock();

   if (table_size <= 0)       table_size       = DEF_SIZE;
   if (det_start_time <= 0)   det_start_time   = D_DET_START_PAUSE;
   if (active_timeout <= 0)   active_timeout   = D_ACTIVE_TIMEOUT;
   if (inactive_timeout <= 0) inactive_timeout = D_INACTIVE_TIMEOUT;

   // update subprofile configuration
   for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
      it->check_config();
   }

   // Sort vector - active subprofiles go to the forefront of sp_list
   std::sort(sp_list.begin(), sp_list.end());
}

/*
 * update()
 * Update records in the stat_table by data from TRAP input interface
 *
 * Find two host records according to source and destination address of the 
 * flow and update these records (and subprofiles).
 * Note: uses global variable hs_time with current system time 
 *
 * @param record Pointer to the data from the TRAP
 * @param tmpl_in Pointer to the TRAP input interface
 * @param subprofiles When True update active subprofiles
 */
void HostProfile::update(const void *record, const ur_template_t *tmpl_in,
      bool subprofiles)
{
   // find/add record in bloom filter
   ip_addr_t bkey[2] = {ur_get(tmpl_in, record, UR_SRC_IP),
                        ur_get(tmpl_in, record, UR_DST_IP)};
   bool present = false;
   present = bf_active->containsinsert((const unsigned char *) bkey, 32);
   bf_learn->insert((const unsigned char *) bkey, 32);

   // get flows records
   hosts_record_t& src_host_rec = get_record(bkey[0]);
   hosts_record_t& dst_host_rec = get_record(bkey[1]);

   uint8_t tcp_flags = ur_get(tmpl_in, record, UR_TCP_FLAGS);
   uint8_t dir_flags = ur_get(tmpl_in, record, UR_DIRECTION_FLAGS);

   // Macros
   #define ADD(dst, src) \
      dst = safe_add(dst, src);

   #define INC(value) \
      value = safe_inc(value);

   // source --------------------------------------------------------
   if (!src_host_rec.in_all_flows && !src_host_rec.out_all_flows)
      src_host_rec.first_rec_ts = hs_time;

   src_host_rec.last_rec_ts = hs_time;

   // all flows
   ADD(src_host_rec.out_all_bytes, ur_get(tmpl_in, record, UR_BYTES));
   ADD(src_host_rec.out_all_packets, ur_get(tmpl_in, record, UR_PACKETS));
   if (!present) INC(src_host_rec.out_all_uniqueips);
   INC(src_host_rec.out_all_flows);

   if (tcp_flags & 0x1)  INC(src_host_rec.out_all_fin_cnt);
   if (tcp_flags & 0x2)  INC(src_host_rec.out_all_syn_cnt);
   if (tcp_flags & 0x4)  INC(src_host_rec.out_all_rst_cnt);
   if (tcp_flags & 0x8)  INC(src_host_rec.out_all_psh_cnt);
   if (tcp_flags & 0x10) INC(src_host_rec.out_all_ack_cnt);
   if (tcp_flags & 0x20) INC(src_host_rec.out_all_urg_cnt);

   src_host_rec.out_linkbitfield |= ur_get(tmpl_in, record, UR_LINK_BIT_FIELD);

   // request flows
   if (dir_flags & 0x8) {
      ADD(src_host_rec.out_req_bytes, ur_get(tmpl_in, record, UR_BYTES));
      ADD(src_host_rec.out_req_packets, ur_get(tmpl_in, record, UR_PACKETS));
      if (!present) INC(src_host_rec.out_req_uniqueips);
      INC(src_host_rec.out_req_flows);

      if (tcp_flags & 0x4)  INC(src_host_rec.out_req_rst_cnt);
      if (tcp_flags & 0x8)  INC(src_host_rec.out_req_psh_cnt);
      if (tcp_flags & 0x10) INC(src_host_rec.out_req_ack_cnt);
   }

   //response flows
   if (dir_flags & 0x4) {
      INC(src_host_rec.out_rsp_flows);
   }

   // signle flows
   if (dir_flags & 0x2) {
      INC(src_host_rec.out_sf_flows);
   }

   // destination ---------------------------------------------------
   if (!dst_host_rec.in_all_flows && !dst_host_rec.out_all_flows)
      dst_host_rec.first_rec_ts = hs_time;

   dst_host_rec.last_rec_ts = hs_time;

   // all flows
   ADD(dst_host_rec.in_all_bytes, ur_get(tmpl_in, record, UR_BYTES));
   ADD(dst_host_rec.in_all_packets, ur_get(tmpl_in, record, UR_PACKETS));
   if (!present) INC(dst_host_rec.in_all_uniqueips);
   INC(dst_host_rec.in_all_flows);

   if (tcp_flags & 0x1)  INC(dst_host_rec.in_all_fin_cnt);
   if (tcp_flags & 0x2)  INC(dst_host_rec.in_all_syn_cnt);
   if (tcp_flags & 0x4)  INC(dst_host_rec.in_all_rst_cnt);
   if (tcp_flags & 0x8)  INC(dst_host_rec.in_all_psh_cnt);
   if (tcp_flags & 0x10) INC(dst_host_rec.in_all_ack_cnt);
   if (tcp_flags & 0x20) INC(dst_host_rec.in_all_urg_cnt);

   dst_host_rec.in_linkbitfield |= ur_get(tmpl_in, record, UR_LINK_BIT_FIELD);

   // request flows
   if (dir_flags & 0x8) {
      ADD(dst_host_rec.in_req_bytes, ur_get(tmpl_in, record, UR_BYTES));
      ADD(dst_host_rec.in_req_packets, ur_get(tmpl_in, record, UR_PACKETS));
      if (!present) INC(dst_host_rec.in_req_uniqueips);
      INC(dst_host_rec.in_req_flows);

      if (tcp_flags & 0x4)  INC(dst_host_rec.in_req_rst_cnt);
      if (tcp_flags & 0x8)  INC(dst_host_rec.in_req_psh_cnt);
      if (tcp_flags & 0x10) INC(dst_host_rec.in_req_ack_cnt);
   }

   // response flows
   if (dir_flags & 0x4) {
      INC(dst_host_rec.in_rsp_flows);
   }

   // signle flows
   if (dir_flags & 0x2) {
      INC(dst_host_rec.in_sf_flows);
   }

   if (!subprofiles)
      return;

   // update subprofiles
   for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
      if (!it->sp_status)
         break;

      it->update_ptr(src_host_rec, record, tmpl_in, DIR_OUT);
      it->update_ptr(dst_host_rec, record, tmpl_in, DIR_IN);
   }
}

/*
 * remove_by_key()
 * Remove the record from cuckoo_hash table. 
 * 
 * @param key Key to remove from the table
 */
void HostProfile::remove_by_key(const hosts_key_t &key)
{
   hosts_record_t &rec = get_record(key);
   for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
      it->delete_ptr(rec);
   }

   ht_remove_by_key_v2(stat_table_ptr, (char *) key.bytes);
}

/*
 * release()
 * Remove subprofiles and clean cuckoo_hash table
 */
void HostProfile::release()
{
   // Remove all subprofiles
   for (unsigned int i = 0; i < table_size; ++i) 
   {
      if (stat_table_ptr->ind[i].valid != 1) {
         return;
      }

      int index = stat_table_ptr->ind[i].index;
      hosts_record_t &temp = *((hosts_record_t *)stat_table_ptr->data[index]);

      for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
         it->delete_ptr(temp);
      }
   }

   ht_clear_v2(stat_table_ptr);
}

/*
 * swap_bf()
 * Clear active BloomFilter and swap active and learning BloomFilter
 */
void HostProfile::swap_bf()
{
   bf_active->clear();

   bloom_filter *tmp = bf_active;
   bf_active = bf_learn;
   bf_learn = tmp;
}

/*
 * check_record()
 * Check whether there are any incidents in the record that belongs to key
 *
 * @param key Key of the record
 * @param subprofiles When True check active subprofiles with active detector
 */
void HostProfile::check_record(const hosts_key_t &key, bool subprofiles)
{
   const hosts_record_t &record = get_record(key);
   check_record(key, record, subprofiles);
}

/*
 * check_record()
 * Check whether there are any incidents in the record
 *
 * @param key Key of the record
 * @param record Record to check
 * @param subprofiles When True check active subprofiles with active detector
 */
void HostProfile::check_record(const hosts_key_t &key, const hosts_record_t &record, 
   bool subprofiles)
{
   // detector
   if (detector_status) {
      check_rules(key, record);
   }

   if (!subprofiles) {
      return;
   }

   // call detector of subprofiles
   for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
      if (!it->detector_status || !it->sp_status) {
         break;
      }

      it->check_ptr(key, record);
   }
}

/*
 * get_record()
 * Get a reference to a record from the table
 * 
 * Find the record in the table. If the record does not exist, create new empty
 * one. Sometime when the empty record is saved, another record is kicked off
 * and sent to the detector. (move info in cuckoo_hash files)
 *
 * @params key Key of the record
 * @return Referece to the record
 */
hosts_record_t& HostProfile::get_record(const hosts_key_t& key)
{
   int index = ht_get_index_v2(stat_table_ptr, (char*) key.bytes);

   if (index < 0) { 
      // the item doesn't exist, create new empty one 
      hosts_record_t empty;
      void *kicked_data;
      kicked_data = ht_insert_v2(stat_table_ptr, (char*) key.bytes, (void*) &empty);
      if (kicked_data != NULL) {
         // Another item was kicked out of the table
         check_record(*(ip_addr_t *)stat_table_ptr->key_kick, 
            *(hosts_record_t *)stat_table_ptr->data_kick);

         // Delete subprofiles in the kicked item
         for(sp_list_iter it = sp_list.begin(); it != sp_list.end(); ++it) {
            it->delete_ptr(*(hosts_record_t *)stat_table_ptr->data_kick);
         }
      }
      index = ht_get_index_v2(stat_table_ptr, (char*) key.bytes);
   }

   return *((hosts_record_t *)stat_table_ptr->data[index]);
}


