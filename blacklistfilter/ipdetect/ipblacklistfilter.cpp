/**
 * \file ipblacklistfilter.cpp
 * \brief Module for detecting blacklisted IP addresses.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 * \date 2014
 * \date 2015
 */

/*
 * Copyright (C) 2013, 2014, 2015 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */
	
#include <string>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <map>
#include <vector>
#include <stdint.h>
#include <signal.h>
#include <getopt.h>
#include <dirent.h>
#include <unistd.h>
#include "../blacklist_downloader/blacklist_downloader.h"
#include <nemea-common.h>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include "ipblacklistfilter.h"



using namespace std;

trap_module_info_t module_info = {
    (char *)"IP blacklist detection module", // Module name
    // Module description
    (char *)"Module receives the UniRec record and checks if the source address\n"
    "or destination address is present in any blacklist that are available.\n"
    "If any of the addresses is blacklisted the record is changed by adding \n"
    "a identification number of the list which blacklisted the address for both IP addresses and\n"
    "a number specifying intensity of the communication between those addresses. Unirec records\n"
    "are aggregated by source,destination address and protocol for a given time. After this time\n"
    "aggregated UniRec is sent by output interface.\n"
    "Usage:\n"
    "\t./ipblacklistfilter -i <trap_interface> -f <file> [-D <blacklists>] [-n] [-I secs] [-A secs] [-s size]\n"
    "Module specific parameters:\n"
    "	-f file		Specify file with blacklisted IP addresses/subnets.\n"
    "	-D blacklists	Switch to dynamic mode and specify which blacklists to use.\n"
    "	-n              Do not send terminating Unirec when exiting program.\n"
    "	-A secs         Specify active timeout in seconds. [Default: 300]\n"
    "	-I secs         Specify inactive timeout in seconds. [Default: 30]\n"
    "	-s size         Size of aggregation hash table. [Default: 500000]\n"
    "Interfaces:\n"
    "   Inputs: 1 (unirec record)\n"
    "   Outputs: 1 (unirec record)\n",
    1, // Number of input interfaces
    1, // Number of output interfaces
};


// Global variable used for storing actual timestamps received from input UniRec records
uint32_t TIMESTAMP = 0; 

// Global variable used for storing aggregated records
fht_table_t *AGGR_TABLE; 

// Global variables for storing periods of timeouts
uint32_t TIMEOUT_ACTIVE = DEFAULT_TIMEOUT_ACTIVE;
uint32_t TIMEOUT_INACTIVE = DEFAULT_TIMEOUT_INACTIVE;

// Global variable for signaling the program to stop execution
static int stop = 0; 

// Global variable for signaling the program to update blacklists
static int update = 0; 

/**
 * \brief Function for handling signals SIGTERM and SIGINT.
 * \param signal Number of received signal.
 */
void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      if (stop) {
         printf("Another terminating signal caught!\nTerminating without clean up!!!.\n");
         exit(EXIT_FAILURE);
      }
      stop = 1;
      printf("Terminating signal caught...\nPlease wait for clean up.\n");
   } else {
      update = 1;
   }
}

/**
 * \brief Function for checking if blacklists are ready to load.
 */
void check_update()
{
   bld_lock_sync();
   update = BLD_SYNC_FLAG;
   bld_unlock_sync();
}

/**
 * \brief Function for updating internal timestamp.
 * \param new_time New timestamp in seconds.
 */
void update_timestamp(uint32_t new_time)
{
   if (new_time > TIMESTAMP) {
      TIMESTAMP = new_time;
   }
}

/**
 * \brief Function computes nearest upper value of power of 2.
 * \param size Actual size.
 * \return Lowest power of 2 bigger or equal than actual size.
 */
uint32_t update_hash_table_size_to_pow2(uint32_t size)
{
   size--;
   size |= size >> 1;
   size |= size >> 2;
   size |= size >> 4;
   size |= size >> 8;
   size |= size >> 16;
   return ++size;
}

/**
 * \brief Function for creating new or finding old record in aggregation hash table.
 * \param key  Key of inserting data.
 * \param data New data to insert.
 * \param lock Reference for locked data.
 * \param kicked Data kicked from table due to insertion of new data.
 * \param kicked_flag Flag gaining values 0 (data was not kicked) or 1 (data was kicked).
 * \return NULL if insert was successfull or pointer to old data with same key as
 *         new data if data was already present in table.
 */
aggr_data_t *create_new_aggr(aggr_data_key_t *key, aggr_data_t *data, int8_t **lock, aggr_data_t *kicked, uint8_t *kicked_flag)
{
   int fht_ret;
   aggr_data_t *data_ret = NULL;

   fht_ret = fht_insert(AGGR_TABLE, key, data, NULL, kicked);



   switch (fht_ret) {
      case FHT_INSERT_OK: data_ret = NULL;
                          *kicked_flag = 0;
                          *lock = NULL;
                          break;
      case FHT_INSERT_LOST: data_ret = NULL;
                            *kicked_flag = 1;
                            *lock = NULL;
                            break;
      case FHT_INSERT_FAILED: data_ret = (aggr_data_t*) fht_get_data_locked(AGGR_TABLE, key, lock);
                              *kicked_flag = 0;
                              break;
   }

   return data_ret;
}

/**
 * \brief Function update aggregation count and last seen timestamp of data.
 * \param tmplt Unirec template for stored data.
 * \param data  Pointer to stored data.
 * \return 0 if Active timeout has expired, 0 otherwise.
 */
uint8_t update_aggr(ur_template_t *tmplt, aggr_data_t *data)
{
   uint8_t ret = 1;

   // Update aggregation count
   ur_set(tmplt, data->data, UR_EVENT_SCALE, ur_get(tmplt, data->data, UR_EVENT_SCALE) +1);
   data->time_last = TIMESTAMP;

   // Check Active timeout
   if ((data->time_last - data->time_first) >= TIMEOUT_ACTIVE) {
      // Active timeout has ran out
      ret = 0;
   }

   return ret;
}


/**
 * Function for swapping bits in byte.
 * /param in Input byte.
 * /return Byte with reversed bits.
 */
inline uint8_t bit_endian_swap(uint8_t in) {
   in = (in & 0xF0) >> 4 | (in & 0x0F) << 4;
   in = (in & 0xCC) >> 2 | (in & 0x33) << 2;
   in = (in & 0xAA) >> 1 | (in & 0x55) << 1;
   return in;
}


/**
 * \brief Function for creating masks for IPv4 addresses. It fills the given
 * array with every possible netmask for IPv4 address.
 * \param m Array to be filled.
 */
void create_v4_mask_map(ipv4_mask_map_t& m)
{
   // Explicitly inserted or else it will be 0xFFFFFFFF
   m[0] = 0x00000000;

   for (int i = 1; i <= 32; i++) {
      m[i] = (0xFFFFFFFF >> (32 - i));

      // Swap bits in each byte for compatibility with ip_addr_t structure
      m[i] = (bit_endian_swap((m[i] & 0x000000FF)>>  0) <<  0) |
             (bit_endian_swap((m[i] & 0x0000FF00)>>  8) <<  8) |
             (bit_endian_swap((m[i] & 0x00FF0000)>> 16) << 16) |
             (bit_endian_swap((m[i] & 0xFF000000)>> 24) << 24);
   }
}

/**
 * \brief Function for creating masks for IPv6 addresses. It fills the given
 * array with every possible netmask for IPv6 address.
 * \param m Array to be filled.
 */
void create_v6_mask_map(ipv6_mask_map_t& m)
{
   // Explicitly inserted or else it will be 0xFF in every byte
   m[0][0] = m[0][1] = 0;

   for (int i = 1; i <= 128; i++) {
      if (i < 64) {
         m[i][0] = 0xFFFFFFFFFFFFFFFF >> (64 - i);
         m[i][1] = 0x0;
      } else {
         m[i][0] = 0xFFFFFFFFFFFFFFFF;
         m[i][1] = 0xFFFFFFFFFFFFFFFF >> (64 - i);
      }
   }
}

/**
 * \brief Function for loading updates. It parses file with blacklisted IP
 * addresses (created by blacklist downloader thread). Records are sorted
 * into two lists based on operation (update list and remove list). These lists
 * are used for both IPv4 and IPv6 addresses. Function also checks validity
 * of line on which the IP address was found. Invalid of bad formated lines
 * are ignored.
 * \param update_list_a Vector with entries that will be added or updated.
 * \param update_list_rm Vector with entries that will be removed.
 * \param file File with updates.
 * \return ALL_OK if everything goes well, BLIST_FILE_ERROR if file cannot be accessed.
 */
int load_update(black_list_t& update_list_a, black_list_t& update_list_rm, string& file)
{
   ifstream input; // data input
   string line, ip, bl_flag_str;
   size_t str_pos;
   uint64_t bl_flag;
   int line_num = 0;
   ip_blist_t bl_entry; // black list entry associated with ip address
   bool add_rem = false; // add/remove flag

   // Open file with blacklists
   input.open(file.c_str(), ifstream::in);
   if (!input.is_open()) {
      cerr << "Cannot open file with updates!" << endl;
      return BLIST_FILE_ERROR;
   }

   // Read file line by line
   while (!input.eof()) {
      getline(input, line);
      line_num++;

      // Trim all white spaces (if any)
      line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

      // Transform all letters to lowercase (if any)
      transform(line.begin(), line.end(), line.begin(), ::tolower);

      // Encountered a remove line?
      if (line == "#remove") {
         add_rem = true; // switch to remove mode
         continue;
      }

      // Skip empty lines
      if (!line.length()) {
         continue;
      }

      // Find IP-blacklist separator
      str_pos = line.find_first_of(',');
      if (str_pos == string::npos) {
         // Blacklist index delimeter not found (bad format?), skip it
         cerr << "WARNING: File '" << file << "' has bad formated line number '" << line_num << "'" << endl;
         continue;
      }

      // Parse blacklist ID
      bl_flag = strtoull((line.substr(str_pos + 1, string::npos)).c_str(), NULL, 10);

      // Parse IP
      ip = line.substr(0, str_pos);
      // Are we loading prefix?
      str_pos = ip.find_first_of('/');
      if (str_pos == string::npos) {
         // IP only
         if (!ip_from_str(ip.c_str(), &bl_entry.ip)) {
            continue;
         }
         if (ip_is4(&bl_entry.ip)) {
            bl_entry.pref_length = PREFIX_V4_DEFAULT;
         } else {
            bl_entry.pref_length = PREFIX_V6_DEFAULT;
         }
      } else {
         // IP prefix
         if (!ip_from_str((ip.substr(0, str_pos)).c_str(), &bl_entry.ip)) {
            continue;
         }
         ip.erase(0, str_pos + 1);
         if (str_pos != string::npos) {
            bl_entry.pref_length = strtoul(ip.c_str(), NULL, 0);
         } else {
            continue;
         }
      }

      // Determine blacklist
      bl_entry.in_blacklist = bl_flag;

      // Put entry into its respective update list
      if (!add_rem) {
         update_list_a.push_back(bl_entry);
      } else {
         update_list_rm.push_back(bl_entry);
      }
   }
   input.close();

   return ALL_OK;
}

/**
 * \brief Function for binary searching in prefix lists. It uses binary search
 * algorithm to determine whehter the given ip address fits any of the prefix in the list.
 * \param searched IP address that we are checking.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param black_list List of prefixes to be compared with.
 * \return IP_NOT_FOUND if the ip address doesn't fit any prefix. Index of the prefix otherwise.
 */
int ip_binary_search(ip_addr_t* searched, ipv4_mask_map_t& v4mm, ipv6_mask_map_t& v6mm, black_list_t& black_list)
{
   int begin, end, mid;
   int mask_result = 1;
   ip_addr_t masked;
   begin = 0;
   end = black_list.size() - 1;

   // Binary search
   while (begin <= end) {
      mid = (begin + end) >> 1;

      if (ip_is4(searched)) {
         masked.ui32[2] = searched->ui32[2] & v4mm[black_list[mid].pref_length];
         mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);
      } else {
         if (black_list[mid].pref_length <= 64) {
            masked.ui64[0] = searched->ui64[0] & v6mm[black_list[mid].pref_length][0];
            mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
         } else {
            masked.ui64[1] = searched->ui64[1] & v6mm[black_list[mid].pref_length][1];
            mask_result = memcmp(&(black_list[mid].ip.ui8), &(masked.ui8), 16);
         }
      }

      if (mask_result < 0) {
         begin = mid + 1;
      } else if (mask_result > 0) {
         end = mid - 1;
      } else {
         break;
      }
   }

   // Check result
   if (mask_result == 0) {
      // Found an address, return black list number
      return mid;
   }
   return IP_NOT_FOUND;
}

/**
 * \brief Function for checking IPv4 addresses. It extracts both source and
 * destination addresses from the UniRec record and tries to match them to either
 * address or prefix. If the match is positive the field in detection record is filled
 * with the respective blacklist number.
 * \param ur_tmp Template of input UniRec record.
 * \param ur_det Template of detection UniRec record.
 * \param record Record being analyzed.
 * \param detected Detection record used if any address matches the blacklist.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param net_bl List of prefixes to be compared with.
 * \return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v4_blacklist_check(ur_template_t* ur_tmp,
                       ur_template_t* ur_det,
                       const void *record,
                       void *detected,
                       ipv4_mask_map_t& v4mm,
                       ipv6_mask_map_t& v6mm,
                       black_list_t& net_bl)
{
   bool marked = false;
   // index of the prefix the source ip fits in (return value of binary/hash search)
   int search_result;

   // Check source IP
   ip_addr_t ip = ur_get(ur_tmp, record, UR_SRC_IP);
   if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, UR_SRC_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
      ur_set(ur_det, detected, UR_SRC_BLACKLIST, net_bl[search_result].in_blacklist);
      marked = true;
   } else {
      ur_set(ur_det, detected, UR_SRC_BLACKLIST, 0x0);
   }

   // Check destination IP
   ip = ur_get(ur_tmp, record, UR_DST_IP);
   if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, UR_DST_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
      ur_set(ur_det, detected, UR_DST_BLACKLIST, net_bl[search_result].in_blacklist);
      marked = true;
   } else {
      ur_set(ur_det, detected, UR_DST_BLACKLIST, 0x0);
   }

   // Check result
   if (marked) {
      // IP was found
      return BLACKLISTED;
   }
   return ADDR_CLEAR;
}

/**
 * \brief Function for checking IPv6 addresses. It extracts both source and
 * destination addresses from the UniRec record and tries to match them to
 * either an address or prefix. If the match is positive the field in detection
 * record is filled with the respective blacklist number.
 * \param ur_tmp Template of input UniRec record.
 * \param ur_det Template of detection UniRec record.
 * \param record Record being analyzed.
 * \param detected Detection record used if any address matches the blacklist.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param net_bl List of prefixes to be compared with.
 * \return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v6_blacklist_check(ur_template_t* ur_tmp,
                       ur_template_t* ur_det,
                       const void *record,
                       void *detected,
                       ipv4_mask_map_t& v4mm,
                       ipv6_mask_map_t& v6mm,
                       black_list_t& net_bl)
{
   bool marked = false;
   // index of the prefix the source ip fits in (return value of binary search)
   int search_result;

   // Check source IP
   ip_addr_t ip = ur_get(ur_tmp, record, UR_SRC_IP);
   if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, UR_SRC_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
      ur_set(ur_det, detected, UR_SRC_BLACKLIST, net_bl[search_result].in_blacklist);
      marked = true;
   } else {
      ur_set(ur_det, detected, UR_SRC_BLACKLIST, 0x0);
   }

   // Check destination IP
   ip = ur_get(ur_tmp, record, UR_DST_IP);
   if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, UR_DST_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
      ur_set(ur_det, detected, UR_DST_BLACKLIST, net_bl[search_result].in_blacklist);
      marked = true;
   } else {
      ur_set(ur_det, detected, UR_DST_BLACKLIST, 0x0);
   }

   // Check result
   if (marked) {
      // IP was found
      return BLACKLISTED;
   }
   return ADDR_CLEAR;
}


/**
 * \brief Function for updating prefix lists (add operation). It performs binary search
 * similar to matching operation but instead of returning the index of the matching
 * ip it either updates the entry or returns the index where the new item should
 * be inserted. This operation keeps the list sorted for binary search without sorting
 * the vectors explicitely.
 * \param updated Item containing the update.
 * \param v4mm Array with v4 masks used for prefix search.
 * \param v6mm Array with v6 masks used for prefix search.
 * \param black_list Blacklist to be updated.
 * \return BL_ENTRY_UPDATED if only update operation was performed otherwise index for insertion.
 */
int ip_binary_update(ip_blist_t* updated, ipv4_mask_map_t& v4mm, ipv6_mask_map_t& v6mm, black_list_t& black_list)
{
   int begin, end, mid;
   int mask_result = 1; // need to be anything other than 0 to pass the first run
   ip_addr_t masked;
   begin = 0;
   end = black_list.size() - 1;

   // Binary search
   while (begin <= end) {
      mid = (begin + end) >> 1;

      if (ip_is4(&(updated->ip))) {
         // Process IPv4
         masked.ui32[2] = updated->ip.ui32[2];
         mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);
      } else {
         // Process IPv6
         if (black_list[mid].pref_length <= 64) {
            masked.ui64[0] = updated->ip.ui64[0];
            mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
         } else {
            masked.ui64[1] = updated->ip.ui64[1];
            mask_result = memcmp(&(black_list[mid].ip.ui8), &(masked.ui8), 16);
         }
      }

      if (mask_result < 0) {
         begin = mid + 1;
      } else if (mask_result > 0) {
         end = mid - 1;
      } else {
         break;
      }
   }

   // Check results
   if (mask_result == 0) {
      // Found an address --> update the entry
      black_list[mid].pref_length = updated->pref_length;
      black_list[mid].in_blacklist = updated->in_blacklist;
      return BL_ENTRY_UPDATED;
   } else {
      // No address found, return index where to put new item
      return begin;
   }
}

/**
 * \brief Function for updating blacklists (add operation). It performs update
 * operations borth for prefixes and addresses.
 * \param bl_v4 Vector with blacklisted v4 prefixes.
 * \param bl_v6 Vector with blacklisted v6 prefixes.
 * \param add_upd Vector with updates (new items).
 * \param m4 Array with v4 masks used for prefix search.
 * \param m6 Array with v6 masks used for prefix search.
 */
void update_add(black_list_t& bl_v4,
               black_list_t& bl_v6,
               black_list_t& add_upd,
               ipv4_mask_map_t& m4,
               ipv6_mask_map_t& m6)
{
   int insert_index; // position for item insertion

   // Cycle through all updates
   for (unsigned int i = 0; i < add_upd.size(); i++) {
      if (ip_is4(&(add_upd[i].ip))) {
         insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v4);
         if (insert_index != BL_ENTRY_UPDATED) {
            bl_v4.insert(bl_v4.begin() + insert_index, add_upd[i]);
         }
      } else {
         // IPv6 processing
         insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v6);
         if (insert_index != BL_ENTRY_UPDATED) {
            bl_v6.insert(bl_v6.begin() + insert_index, add_upd[i]);
         }
      }
   }
}

/**
 * \brief Function for updating blacklists (remove). It performs update
 * operations borth for prefixes and addresses.
 * \param bl_v4 Vector with blacklisted v4 prefixes.
 * \param bl_v6 Vector with blacklisted v6 prefixes.
 * \param rm_upd Vector with updates (removed items).
 * \param m4 Array with v4 masks used for prefix search.
 * \param m6 Array with v6 masks used for prefix search.
 */
void update_remove(black_list_t& bl_v4,
                   black_list_t& bl_v6,
                   black_list_t& rm_upd,
                   ipv4_mask_map_t& m4,
                   ipv6_mask_map_t& m6)
{
   int remove_index; // position of deleted item

   // Cycle through all updates
   for (unsigned int i = 0; i < rm_upd.size(); i++) {
      if (ip_is4(&(rm_upd[i].ip))) {
         // IPv4 Processing
         remove_index = ip_binary_search(&(rm_upd[i].ip), m4, m6, bl_v4);
         if (remove_index == IP_NOT_FOUND) { // nothing to remove --> move on
            continue;
         } else {
           // Remove from vector
            bl_v4.erase(bl_v4.begin() + remove_index);
         }
      } else {
         // IPv6 processing
         remove_index = ip_binary_search(&(rm_upd[i].ip), m4, m6, bl_v6);
         if (remove_index == IP_NOT_FOUND) {
            continue;
         } else {
            bl_v6.erase(bl_v6.begin() + remove_index);
         }
      }
   }
}



/**
 * \brief Function for thread checking if Inactive timeout of stored flows
 * has expired.
 * \param tmplt Unirec template of stored data.
 */
void *inactive_timeout_thread_func(void *tmplt)
{
   while (!stop) {
      // Sleep for inactive timeout
      sleep(TIMEOUT_INACTIVE);

      // Send all flows still in table as SF (single flow)
      fht_iter_t *iter = fht_init_iter(AGGR_TABLE);
      while (fht_get_next_iter(iter) == FHT_ITER_RET_OK) {
         // Check flow last seen timestamp
         if (TIMESTAMP - ((aggr_data_t*)iter->data_ptr)->time_last >= TIMEOUT_INACTIVE) {
            // Inactive timeout expired, send data to output
            trap_send_data(0, ((aggr_data_t*)iter->data_ptr)->data, ur_rec_static_size((ur_template_t*)tmplt), TRAP_HALFWAIT);
            fht_remove_iter(iter);
         }
      }
   }

   // The program is terminating, empty stored flows
   fht_iter_t *iter = fht_init_iter(AGGR_TABLE);
   while (fht_get_next_iter(iter) == FHT_ITER_RET_OK) {
      trap_send_data(0, ((aggr_data_t*)iter->data_ptr)->data, ur_rec_static_size((ur_template_t*)tmplt), TRAP_HALFWAIT);
         fht_remove_iter(iter);
   }

   return NULL;
}

/**
 * \brief Setup arguments structure for Blacklist Downloader.
 * \param args Pointer to arguments structure.
 * \param file File to which blacklist IP addresses will be written.
 * \param b_str Names of blacklists to use delimeted by comma.
 */
void setup_downloader(bl_down_args_t *args, const char *file, char *b_str)
{
   uint64_t sites;
   uint8_t num = bl_translate_to_id(b_str, &sites);
   args->use_regex = (uint8_t*)malloc(sizeof(uint8_t) * num);
   args->reg_pattern = (char**)malloc(sizeof(char *) * num);

   for (int i = 0; i < num; i++) {
      args->use_regex[i] = 1;
      args->reg_pattern[i] = strdup(BLACKLIST_REG_PATTERN);
   }

   args->sites      = sites;
   args->file       = (char*)file;
   args->comment_ar = BLACKLIST_COMMENT_AR;
   args->num        = num;
   args->delay      = BLACKLIST_UPDATE_DELAY_TIME;
   args->update_mode     = BLACKLIST_UPDATE_MODE;
   args->line_max_length = BLACKLIST_LINE_MAX_LENGTH;
   args->el_max_length   = BLACKLIST_EL_MAX_LENGTH;
   args->el_max_count    = BLACKLIST_EL_MAX_COUNT;
}



/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{
   int retval = 0; // return value
   int send_terminating_unirec = 1;
   bl_down_args_t bl_args;
   uint32_t hash_table_size = DEFAULT_HASH_TABLE_SIZE;
   uint32_t hash_table_stash_size = 0;
   int8_t *fht_lock = NULL;

   // UniRec templates for recieving data and reporting blacklisted IPs
   ur_template_t *templ = ur_create_template("<COLLECTOR_FLOW>");
   ur_template_t *tmpl_det = ur_create_template("<COLLECTOR_FLOW>,SRC_BLACKLIST,DST_BLACKLIST,EVENT_SCALE");

   // Create detection record
   void *detection = NULL;
   detection = ur_create(tmpl_det, 0);
   if (detection == NULL) {
       cerr << "ERROR: No memory available for detection report. Unable to continue." << endl;
       ur_free_template(templ);
       ur_free_template(tmpl_det);
       return EXIT_FAILURE;
   }

   // Buffers for aggregated records
   aggr_data_t *new_data = (aggr_data_t*) malloc(sizeof(aggr_data_t) + ur_rec_static_size(tmpl_det));
   aggr_data_t *kicked_data = (aggr_data_t*) malloc(sizeof(aggr_data_t) + ur_rec_static_size(tmpl_det));

   // For use with prefixes
   black_list_t v4_list;
   black_list_t v6_list;

   // Update lists
   black_list_t add_update;
   black_list_t rm_update;

   // Mask array for prefixes
   ipv4_mask_map_t v4_masks;
   ipv6_mask_map_t v6_masks;
   create_v4_mask_map(v4_masks);
   create_v6_mask_map(v6_masks);

   // TRAP initialization
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

   // Turn off buffer on output interface
   //trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0x0);

   // Set signal handling for termination
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);
   signal(SIGUSR1, signal_handler);

   int opt;
   string file, bl_str;
   int bl_mode = BL_STATIC_MODE; // default mode

   // ********** Parse arguments **********
   while ((opt = getopt(argc, argv, "nD:f:A:I:s:")) != -1) {
      switch (opt) {
         case 'D': // Dynamic mode
                   bl_mode = BL_DYNAMIC_MODE;
                   bl_str = string(optarg);
                   break;
         case 'f': // Specify file with blacklisted IPs
                   file = string(optarg);
                   break;
         case 'n': // Do not send terminating Unirec
                   send_terminating_unirec = 0;
                   break;
         case 'A': // Active timeout
                   TIMEOUT_ACTIVE = atoi(optarg);
                   break;
         case 'I': // Inactive timeout
                   TIMEOUT_INACTIVE = atoi(optarg);
                   break;
         case 's': // FHT table size
                   hash_table_size = atoi(optarg);
                   break;
         case '?': if (optopt == 'D' || optopt == 'f' || optopt == 'I' || optopt == 'A' || optopt == 's') {
                      fprintf (stderr, "ERROR: Option -%c requires an argumet.\n", optopt);
                   } else {
                      fprintf (stderr, "ERROR: Unknown option -%c.\n", optopt);
                   }
                   ur_free_template(templ);
                   ur_free_template(tmpl_det);
                   trap_finalize();
                   return EXIT_FAILURE;
      }
   }

   // ***** Check module arguments *****
   if (file.length() == 0) {
      fprintf(stderr, "Error: Parameter -f is mandatory.\nUsage: %s -i <trap_interface> -f <file> [-D <blacklists>] [-n] [-I secs] [-A secs] [-s size]\n", argv[0]);
      ur_free_template(templ);
      ur_free_template(tmpl_det);
      trap_finalize();
      return EXIT_FAILURE;
   }
   if (bl_mode == BL_DYNAMIC_MODE && bl_str.length() == 0) {
      fprintf(stderr, "Error: Parameter -D needs argument.\nUsage: %s -i <trap_interface> -f <file> [-D <blacklists>] [-n] [-I secs] [-A secs] [-s size]\n", argv[0]);
      ur_free_template(templ);
      ur_free_template(tmpl_det);
      trap_finalize();
      return EXIT_FAILURE;
   }
   hash_table_size = update_hash_table_size_to_pow2(hash_table_size);
   if ((AGGR_TABLE = fht_init(hash_table_size, sizeof(aggr_data_key_t), sizeof(aggr_data_t) + ur_rec_static_size(tmpl_det), hash_table_stash_size)) == NULL) {
      fprintf(stderr, "Error: Could not allocate memory for hash table\n");
      ur_free_template(templ);
      ur_free_template(tmpl_det);
      trap_finalize();
      return EXIT_FAILURE;
   }

   // ***** Initialize Blacklist Downloader *****
   if (bl_mode == BL_DYNAMIC_MODE) {
      // Start Blacklist Downloader
      setup_downloader(&bl_args, file.c_str(), (char*) bl_str.c_str());
      if (bl_args.sites == 0) {
         fprintf(stderr, "Error: No blacklists were specified!\n");
         ur_free_template(templ);
         ur_free_template(tmpl_det);
         fht_destroy(AGGR_TABLE);
         trap_finalize();
         return EXIT_FAILURE;
      }
      int ret = bl_down_init(&bl_args);
      if (ret < 0) {
         fprintf(stderr, "Error: Could not initialize downloader!\n");
         ur_free_template(templ);
         ur_free_template(tmpl_det);
         fht_destroy(AGGR_TABLE);
         trap_finalize();
         return EXIT_FAILURE;
      } else {
         // Wait for initial update
         while (!update) {
            sleep(1);
            if (stop) {
               ur_free_template(templ);
               ur_free_template(tmpl_det);
               fht_destroy(AGGR_TABLE);
               trap_finalize();
               if (bl_mode == BL_DYNAMIC_MODE) {
                  fprintf(stderr, "Quiting before first update\n");
                  bld_finalize();
               }
               return EXIT_FAILURE;
            }
            check_update();
         }
         update = 0;
      }
   }

   // Load ip addresses from sources
   retval = load_update(add_update, rm_update, file);

   // If update from file could not be processed, return error
   if (retval == BLIST_FILE_ERROR) {
      fprintf(stderr, "Error: Unable to read file '%s'\n", file.c_str());
      ur_free_template(templ);
      ur_free_template(tmpl_det);
      fht_destroy(AGGR_TABLE);
      trap_finalize();
      if (bl_mode == BL_DYNAMIC_MODE) {
         bld_finalize();
      }
      return EXIT_FAILURE;
   }

   // Add update
   if (!add_update.empty()) {
      update_add(v4_list, v6_list, add_update, v4_masks, v6_masks);
   }
   add_update.clear();
   rm_update.clear();


    // Create thread for Inactive timeout checking
    pthread_t inactive_timeout_thread_id;
    if (pthread_create(&inactive_timeout_thread_id, NULL, &inactive_timeout_thread_func, tmpl_det)) {
       fprintf(stderr, "ERROR: Could not create inactive timeout flush thread.\n");
       ur_free(detection);
       ur_free_template(templ);
       ur_free_template(tmpl_det);
       fht_destroy(AGGR_TABLE);
       trap_finalize();
       return EXIT_SUCCESS;
    }


   // ***** Main processing loop *****
   while (!stop) {
      const void *data;
      uint16_t data_size;
      // Retrieve data from sender
      retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval, continue, break);

      // Check the data size
      if (data_size != ur_rec_size(templ, data)) {
         if (data_size <= 1) { // end of data
            break;
         } else { // data corrupted
            cerr << "ERROR: Corrupted data or wrong data template was specified. ";
            cerr << "Size computed from record: " << ur_rec_size(templ, data) << " ";
            cerr << "Size returned from Trap: " << data_size << endl;
            break;
         }
      }

      // Update timestamp from record
      update_timestamp(ur_get(templ, data, UR_TIME_FIRST) >> 32);

      // Try to match the IP addresses to blacklist
      if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
         // Check blacklisted IPs
         retval = v4_blacklist_check(templ, tmpl_det, data, detection, v4_masks, v6_masks, v4_list);
      } else {
         retval = v6_blacklist_check(templ, tmpl_det, data, detection, v4_masks, v6_masks, v6_list);
      }

      // If IP address was found on blacklist
      if (retval == BLACKLISTED) {
         aggr_data_t *aggr_data;
         aggr_data_key_t aggr_data_key;
         uint8_t kicked_flag;

         aggr_data_key.srcip = ur_get(templ, data, UR_SRC_IP);
         aggr_data_key.dstip = ur_get(templ, data, UR_DST_IP);
         aggr_data_key.proto = ur_get(templ, data, UR_PROTOCOL);

         new_data->time_first = TIMESTAMP;
         new_data->time_last = TIMESTAMP;
         ur_transfer_static(templ, tmpl_det, data, detection);
         ur_set(tmpl_det, detection, UR_EVENT_SCALE, 1);
         memcpy(new_data->data, detection, ur_rec_size(tmpl_det, detection));

         // Create new aggregation record or find old one already in table
         aggr_data = create_new_aggr(&aggr_data_key, new_data, &fht_lock, kicked_data, &kicked_flag);

         // If aggregation record is already present in table
         if (aggr_data) {
            // Update old record
            if (!update_aggr(tmpl_det, aggr_data)) {
               // If Active timeout has run out, send data to output
               trap_send_data(0, aggr_data->data, ur_rec_static_size(tmpl_det), TRAP_HALFWAIT);
               fht_remove_locked(AGGR_TABLE, &aggr_data_key, fht_lock);
            }
            fht_unlock_data(fht_lock);
            fht_lock = NULL;
         }

         // If data was kicked out from table, send them to output
         if (kicked_flag) {
            trap_send_data(0, kicked_data->data, ur_rec_static_size(tmpl_det), TRAP_HALFWAIT);
         }
      }

      // Critical section starts here
      bld_lock_sync();
      if (bl_mode == BL_DYNAMIC_MODE && BLD_SYNC_FLAG) {
         // Update blacklists
         string upd_path = file;
         retval = load_update(add_update, rm_update, upd_path);
         if (retval == BLIST_FILE_ERROR) {
            cerr << "ERROR: Unable to load update files. Will use the old tables instead." << endl;
            update = 0;
            continue;
         }
         if (!rm_update.empty()) {
            update_remove(v4_list, v6_list, rm_update, v4_masks, v6_masks);
         }
         if (!add_update.empty()) {
            update_add(v4_list, v6_list, add_update, v4_masks, v6_masks);
         }

         add_update.clear();
         rm_update.clear();
         BLD_SYNC_FLAG = 0;
      }
      bld_unlock_sync();
      // Critical section ends here
    }
    // Module is stopping, set appropriate flag
    stop = 1;

    // Terminate blacklist downloader thread if in dynamic mode
    if (bl_mode == BL_DYNAMIC_MODE) {
        bld_finalize();
    }

   // Wait for inactive timeout flush thread
   if (fht_lock != NULL) {
      fht_unlock_data(fht_lock);
   }
   pthread_kill(inactive_timeout_thread_id, SIGUSR1);
   pthread_join(inactive_timeout_thread_id, NULL);


   // If set, send terminating message to modules on output
   if (send_terminating_unirec) {
      trap_send_data(0, "TERMINATE", 1, TRAP_HALFWAIT);
   }

   // Clean up before termination
   if (detection != NULL) {
      ur_free(detection);
      detection = NULL;
   }
   ur_free_template(templ);
   ur_free_template(tmpl_det);
   fht_destroy(AGGR_TABLE);

   TRAP_DEFAULT_FINALIZATION();

   return EXIT_SUCCESS;
}
