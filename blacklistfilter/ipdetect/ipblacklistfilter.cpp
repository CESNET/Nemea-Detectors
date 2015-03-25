/**
 * \file ipblacklistfilter.cpp
 * \brief Main module for IPBlackLIstDetector.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 * \date 2014
 */

/*
 * Copyright (C) 2013,2014 CESNET
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



#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif

#include <unirec/unirec.h>
#include <cuckoo_hash_v2.h>
#include "ipblacklistfilter.h"
#include "../blacklist_downloader/blacklist_downloader.h"

//#define DEBUG
#define LONG_RUN

using namespace std;

trap_module_info_t module_info = {
    (char *)"IP blacklist detection module", // Module name
    // Module description
    (char *)"Module recieves the UniRec record and checks if the stored source address\n"
    "or destination address isn't present in any blacklist that are available.\n"
    "If any of the addresses is blacklisted the record is changed by adding \n"
    "a number of the list which blacklisted the address. UniRec with this \n"
    "flag is then sent to the next module.\n"
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



uint32_t TIMESTAMP = 0; // global variable used for active/inactive timeout
fht_table_t *AGGR_TABLE;

uint32_t TIMEOUT_ACTIVE = DEFAULT_TIMEOUT_ACTIVE;
uint32_t TIMEOUT_INACTIVE = DEFAULT_TIMEOUT_INACTIVE;

static int stop = 0; // global variable for stopping the program
static int update = 0; // global variable for updating blacklists

/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
void signal_handler(int signal)
{
    if (signal == SIGTERM || signal == SIGINT) {
        stop = 1;
        printf("Terminating signal caught...\nPlease wait for clean up.\n");
    }
}

/**
 * \brief Procedure for checking if blacklists are ready to load.
 */
void check_update()
{
   bld_lock_sync();
   update = BLD_SYNC_FLAG;
   bld_unlock_sync();
}

/**
 * \brief Procedure for updating internal timestamp.
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
   aggr_data_t *data_ret;

   fht_ret = fht_insert(AGGR_TABLE, key, data, NULL, kicked);



   switch (fht_ret) {
      case FHT_INSERT_OK: data_ret = NULL;
                          *kicked_flag = 0;
                          break;
      case FHT_INSERT_LOST: data_ret = NULL;
                            *kicked_flag = 1;
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
 * Procedure for swapping bits in byte.
 * @param in Input byte.
 * @return Byte with reversed bits.
 */
inline uint8_t bit_endian_swap(uint8_t in) {
   in = (in & 0xF0) >> 4 | (in & 0x0F) << 4;
   in = (in & 0xCC) >> 2 | (in & 0x33) << 2;
   in = (in & 0xAA) >> 1 | (in & 0x55) << 1;
   return in;
}


/**
 * Function for creating masks for IPv4 addresses.
 * Function fills the given array with every possible netmask for IPv4 address.
 * Size of this array is 33 items (see header file)
 *
 * @param m Array to be filled
 */
void create_v4_mask_map(ipv4_mask_map_t& m)
{
    m[0] = 0x00000000; // explicitly inserted or else it will be 0xFFFFFFFF
    for (int i = 1; i <= 32; i++) {
        m[i] = (0xFFFFFFFF >> (32 - i));

        // swap bits in each byte for compatibility with ip_addr_t structure
        m[i] = (bit_endian_swap((m[i] & 0x000000FF)>>  0) <<  0) |
               (bit_endian_swap((m[i] & 0x0000FF00)>>  8) <<  8) |
               (bit_endian_swap((m[i] & 0x00FF0000)>> 16) << 16) |
               (bit_endian_swap((m[i] & 0xFF000000)>> 24) << 24);
    }
}

/**
 * Function for creating masks for IPv6 addresses.
 * Functions fills the given array with every possible netmask for IPv6 address.
 * Size of the array is 129 items each containing 2 parts of IPv6 mask.
 *
 * @ param m Array to be filled
 */

void create_v6_mask_map(ipv6_mask_map_t& m)
{
    // explicitly inserted or else it will be 0xFF in every byte
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
 * Function for loading updates.
 * Function goes through all files in given directory and loads their content
 * (ip addresses/prefixes) for updating its classification tables. Records are 
 * sorted to two update lists based on adding/removal operation. These list are 
 * used for both V4 and V6 addresses and both for pure addresses and prefixes.
 * The function also checks whether the record in file is valid ip address 
 * or if the file contains valid data. Invalid records/files are automatically 
 * skipped.
 *
 * @param update_list_a Vector with entries that will be added or updated.
 * @param update_list_rm Vector with entries that will be removed.
 * @param file File with updates.
 * @return ALL_OK if everything goes well, BLIST_FILE_ERROR if file cannot be accessed.
 */
int load_update(black_list_t& update_list_a, black_list_t& update_list_rm, string& file)
{
    ifstream input; // data input

    string line, ip, bl_flag_str;
    size_t str_pos;

    uint64_t bl_flag;
    int line_num = 0;

    ip_addr_t key; // ip address (used as key in the map)
    ip_blist_t bl_entry; // black list entry associated with ip address

    bool add_rem = false; // add or remove from table ?

    input.open(file.c_str(), ifstream::in);

    if (!input.is_open()) {
        cerr << "Cannot open file with updates!" << endl;
        return BLIST_FILE_ERROR;
    }

    while (!input.eof()) {
        getline(input, line);
        line_num++;

        // trim all white spaces (if any)
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

        // transform all letters to lowercase (if any)
        transform(line.begin(), line.end(), line.begin(), ::tolower);

        // encountered a remove line?
        if (line == "#remove") {
            add_rem = true; // switch to remove mode
            continue;
        }

        // Skip empty lines
        if (!line.length()) {
            continue;
        }


        // find IP-blacklist separator
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
        // are we loading prefix?
        str_pos = ip.find_first_of('/');
        if (str_pos == string::npos) { // ip only
            if (!ip_from_str(ip.c_str(), &bl_entry.ip)) {
                continue;
            }
            if (ip_is4(&bl_entry.ip)) {
               bl_entry.pref_length = PREFIX_V4_DEFAULT;
            } else {
                bl_entry.pref_length = PREFIX_V6_DEFAULT;
            }                
        } else { // ip prefix
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

        // determine blacklist
        bl_entry.in_blacklist = bl_flag;           
     
       // put entry into its respective update list        
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
 * Function for binary searching in prefix lists.
 * Function uses binary search algorithm to determine whehter the given ip 
 * address fits any of the prefix in the list.
 *
 * @param searched IP address that we are checking.
 * @param v4mm Map of IPv4 masks.
 * @param v6mm Map of IPv6 masks.
 * @param black_list List of prefixes to be compared with.
 * @return IP_NOT_FOUND if the ip address doesn't fit any prefix. Index of the prefix otherwise.
 */
int ip_binary_search(ip_addr_t* searched, ipv4_mask_map_t& v4mm, ipv6_mask_map_t& v6mm, black_list_t& black_list)
{
    int begin, end, mid;
    int mask_result = 1;
    ip_addr_t masked;
    begin = 0;
    end = black_list.size() - 1;

    while (begin <= end) {
        mid = (begin + end) >> 1;

        if (ip_is4(searched)) {
            masked.ui32[2] = searched->ui32[2] & v4mm[black_list[mid].pref_length];
            mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);
        } else {
            if (black_list[mid].pref_length <= 64) { 
                /*
                 * we mask only the "upper part of the address and use
                 * it for comparison (we don't need to compare the whole
                 * address)
                 */
                masked.ui64[0] = searched->ui64[0] & v6mm[black_list[mid].pref_length][0];
                mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
            } else { 
                /*
                 * we mask only the lower part of the address and use 
                 * the whole address for comparison
                 */
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

    if (mask_result == 0) { // we found an address --> return black list number
        return mid;
    }
    return IP_NOT_FOUND;
}

/**
 * Function for checking IPv4 addresses.
 * Function extracts both source and destination addresses from the UniRec record 
 * and tries to match them to either an address or prefix. If the match is positive 
 * the field in detection record is filled with the respective blacklist number. 
 * This record is later sent to the modlue that for further analysis.
 *
 * @param ur_tmp Template of input UniRec record.
 * @param ur_det Template of detection UniRec record.
 * @param record Record being analyzed.
 * @param detected Detection record used if any address matches the blacklist.
 * @param ip_bl Hash table with addresses.
 * @param v4mm Map of IPv4 masks.
 * @param v6mm Map of IPv6 masks.
 * @param net_bl List of prefixes to be compared with.
 * @return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v4_blacklist_check(ur_template_t* ur_tmp,
                       ur_template_t* ur_det,
                       const void *record,
                       void *detected,
                       cc_hash_table_t& ip_bl,
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

    if (marked) {
        return BLACKLISTED;
    }
    return ADDR_CLEAR;
}

/**
 * Function for checking IPv6 addresses.
 * Function extracts both source and destination addresses from the UniRec record 
 * and tries to match them to either an address or prefix. If the match is positive 
 * the field in detection record is filled with the respective blacklist number. 
 * This record is later sent to the modlue that for further analysis.
 *
 * @param ur_tmp Template of input UniRec record.
 * @param ur_det Template of detection UniRec record.
 * @param record Record being analyzed.
 * @param detected Detection record used if any address matches the blacklist.
 * @param ip_bl Hash table with addresses.
 * @param v4mm Map of IPv4 masks.
 * @param v6mm Map of IPv6 masks.
 * @param net_bl List of prefixes to be compared with.
 * @return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v6_blacklist_check(ur_template_t* ur_tmp,
                       ur_template_t* ur_det,
                       const void *record,
                       void *detected,
                       cc_hash_table_t& ip_bl,
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
 
    if (marked) {
        return BLACKLISTED;
    }
    return ADDR_CLEAR;
}


/**
 * Function for updating prefix lists (adding operation).
 * Function performs binary search similar to matching operation but 
 * instead of returning the index of the matching ip it either updates 
 * the entry or returns the index where the new item should be inserted.
 * This operation keeps the list sorted for binary search without sorting 
 * the vectors explicitely.
 *
 * @param updated Item containing the update.
 * @param v4mm Array with v4 masks used for prefix search.
 * @param v6mm Array with v6 masks used for prefix search.
 * @param black_list Blacklist to be updated.
 * @return BL_ENTRY_UPDATED if only update operation was performed otherwise index for insertion.
 */
int ip_binary_update(ip_blist_t* updated, ipv4_mask_map_t& v4mm, ipv6_mask_map_t& v6mm, black_list_t& black_list)
{
    int begin, end, mid;
    int mask_result = 1; // Need to be anything other than 0 to pass the first run
    ip_addr_t masked;
    begin = 0;
    end = black_list.size() - 1;

    while (begin <= end) {
        mid = (begin + end) >> 1;

        if (ip_is4(&(updated->ip))) {
            masked.ui32[2] = updated->ip.ui32[2];// & v4mm[black_list[mid].pref_length];
            mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);
        } else {
            if (black_list[mid].pref_length <= 64) { 
                /*
                 * we mask only the "upper part of the address and use
                 * it for comparison (we don't need to compare the whole
                 * address)
                 */
                masked.ui64[0] = updated->ip.ui64[0];// & v6mm[black_list[mid].pref_length][0];
                mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
            } else { 
                /*
                 * we mask only the lower part of the address and use 
                 * the whole address for comparison
                 */
                masked.ui64[1] = updated->ip.ui64[1];// & v6mm[black_list[mid].pref_length][1];
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

    if (mask_result == 0) { // we found an address --> update the entry
        black_list[mid].pref_length = updated->pref_length;
        black_list[mid].in_blacklist = updated->in_blacklist;
        return BL_ENTRY_UPDATED;
    } else {// position is shifted for safety reasons
        return begin;
    }
}

/**
 * Procedure for updating blacklists (add or update).
 * Procedure performs update operations borth for prefixes and addresses.
 *
 * @param bl_hash Hash table with blacklisted addresses.
 * @param bl_v4 Vector with blacklisted v4 prefixes.
 * @param bl_v6 Vector with blacklisted v6 prefixes.
 * @param add_upd Vector with updates (new items).
 * @param m4 Array with v4 masks used for prefix search.
 * @param m6 Array with v6 masks used for prefix search.
 * @return 0 if everything goes otherwise REHASH_FAILURE or INSERT_FAILURE if update fails 
 * (mainly with hash table).
 */ 
int update_add(cc_hash_table_t& bl_hash, black_list_t& bl_v4, black_list_t& bl_v6, black_list_t& add_upd, ipv4_mask_map_t& m4, ipv6_mask_map_t& m6)
{
    int insert_index; // position for item insertion
    int ins_retval; // return value of insertion operation

    for (int i = 0; i < add_upd.size(); i++) { // go through updates

        if (ip_is4(&(add_upd[i].ip))) {
                insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v4);
                if (insert_index == BL_ENTRY_UPDATED) { // item was already in table
                } else { // item is new --> add it
                    bl_v4.insert(bl_v4.begin() + insert_index, add_upd[i]);
                }
                //bl_v4.push_back(add_upd[i]);
        } else { // same for v6
               insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v6);
                if (insert_index == BL_ENTRY_UPDATED) {
                    continue;
                } else {
                    bl_v6.insert(bl_v6.begin() + insert_index, add_upd[i]);
                }
        }
    }
    return 0;
}

/**
 * Procedure for updating blacklists (remove).
 * Procedure performs update operations borth for prefixes and addresses.
 *
 * @param bl_hash Hash table with blacklisted addresses.
 * @param bl_v4 Vector with blacklisted v4 prefixes.
 * @param bl_v6 Vector with blacklisted v6 prefixes.
 * @param rm_upd Vector with updates (removed items).
 * @param m4 Array with v4 masks used for prefix search.
 * @param m6 Array with v6 masks used for prefix search.
 */ 
void update_remove(cc_hash_table_t& bl_hash, black_list_t& bl_v4, black_list_t& bl_v6, black_list_t& rm_upd, ipv4_mask_map_t& m4, ipv6_mask_map_t& m6)
{
    int remove_index; // position of deleted item

    for (int i = 0; i < rm_upd.size(); i++) { // go through updates   
        if (ip_is4(&(rm_upd[i].ip))) {
           remove_index = ip_binary_search(&(rm_upd[i].ip), m4, m6, bl_v4);
           if (remove_index == IP_NOT_FOUND) { // nothing to remove --> move on
              continue;
           } else { // remove from vector
              bl_v4.erase(bl_v4.begin() + remove_index);
           }
        } else { // same for v6
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
 * \brief Thread checking if Inactive timeout of stored flows has expired.
 * \brief tmplt Unirec template of stored data.
 * \return void.
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
}





/**
 * \brief Setup arguments structure for Blacklist Downloader.
 * \param args Pointer to arguments structure.
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
   args->delay      = 300;
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

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

    // UniRec templates for recieving data and reporting blacklisted IPs
    ur_template_t *templ = ur_create_template("<COLLECTOR_FLOW>");
    ur_template_t *tmpl_det = ur_create_template("<COLLECTOR_FLOW>,SRC_BLACKLIST,DST_BLACKLIST,EVENT_SCALE");

    aggr_data_t *new_data = (aggr_data_t*) malloc(sizeof(aggr_data_t) + ur_rec_static_size(tmpl_det));
    aggr_data_t *kicked_data = (aggr_data_t*) malloc(sizeof(aggr_data_t) + ur_rec_static_size(tmpl_det));

    // for use with prefixes (not implemented now)
    black_list_t v4_list; 
    black_list_t v6_list;

    // update lists
    black_list_t add_update;
    black_list_t rm_update;

    // mask array (for prefixes)
    ipv4_mask_map_t v4_masks;
    ipv6_mask_map_t v6_masks;
    create_v4_mask_map(v4_masks);
    create_v6_mask_map(v6_masks);

    // can be used for both v4 and v6
    cc_hash_table_t hash_blacklist;

    void *detection = NULL;
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        if (retval == TRAP_E_HELP) {
            trap_print_help(&module_info);
            return EXIT_SUCCESS;
        }
        cerr << "ERROR: Cannot parse input parameters: " << trap_last_error_msg << endl;
        return retval;
    }

    // Initialize TRAP library (create and init all interfaces)     
    retval = trap_init(&module_info, ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP couldn't be initialized: " << trap_last_error_msg << endl;
        return retval;
    }

    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0x0);

    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    ht_init(&hash_blacklist, BL_HASH_SIZE, sizeof(ip_blist_t), sizeof(ip_addr_t), REHASH_ENABLE);

    const void *data;
    uint16_t data_size;

#ifdef DEBUG
    int count = 0, bl_count = 0;
#endif

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
                      ht_destroy(&hash_blacklist);
                      trap_finalize();
                      return EXIT_FAILURE;
        }
    }

    // ***** Check module arguments *****
    if (file.length() == 0) {
        fprintf(stderr, "Error: Parameter -f is mandatory.\nUsage: %s -i <trap_interface> -f <file> [-D <blacklists>] [-n] [-I secs] [-A secs] [-s size] ", argv[0]);
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        ht_destroy(&hash_blacklist);
        trap_finalize();
        return EXIT_FAILURE;
    }
    if (bl_mode == BL_DYNAMIC_MODE && bl_str.length() == 0) {
        fprintf(stderr, "Error: Parameter -D needs argument.\nUsage: %s -i <trap_interface> -f <file> [-D <blacklists>] [-n] [-I secs] [-A secs] [-s size]\n", argv[0]);
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        ht_destroy(&hash_blacklist);
        trap_finalize();
        return EXIT_FAILURE;
    }
    hash_table_size = update_hash_table_size_to_pow2(hash_table_size);
    if ((AGGR_TABLE = fht_init(hash_table_size, sizeof(aggr_data_key_t), sizeof(aggr_data_t) + ur_rec_static_size(tmpl_det), hash_table_stash_size)) == NULL) {
        fprintf(stderr, "Error: Could not allocate memory for hash table\n");
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        ht_destroy(&hash_blacklist);
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
           ht_destroy(&hash_blacklist);
           fht_destroy(AGGR_TABLE);
           trap_finalize();
           return EXIT_FAILURE;
        }
        int ret = bl_down_init(&bl_args);
        if (ret < 0) {
           fprintf(stderr, "Error: Could not initialize downloader!\n");
           ur_free_template(templ);
           ur_free_template(tmpl_det);
           ht_destroy(&hash_blacklist);
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
                   ht_destroy(&hash_blacklist);
                   fht_destroy(AGGR_TABLE);
                   trap_finalize();
                   if (bl_mode == BL_DYNAMIC_MODE) {
                      fprintf(stderr, "Quiting before first update\n");
                      bld_finalize();
                   }
                   return EXIT_FAILURE;
                }
#ifdef DEBUG
                cout << "Waiting for initial update.\n";
#endif
                check_update();
            }
            update = 0;
        }
    }

    // load ip addresses from sources
    retval = load_update(add_update, rm_update, file);

    // something went wrong during loading operation -- terminate with error
    if (retval == BLIST_FILE_ERROR) {
        fprintf(stderr, "Error: Unable to read file '%s'\n", file.c_str());
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        ht_destroy(&hash_blacklist);
        fht_destroy(AGGR_TABLE);
        trap_finalize();
        if (bl_mode == BL_DYNAMIC_MODE) {
            bld_finalize();
        }
        return EXIT_FAILURE;
    }

    // Add update
    if (!add_update.empty()) {
        if (update_add(hash_blacklist, v4_list, v6_list, add_update, v4_masks, v6_masks)) {
            ur_free_template(templ);
            ur_free_template(tmpl_det);
            fht_destroy(AGGR_TABLE);
            ht_destroy(&hash_blacklist);
            trap_finalize();
            fprintf(stderr, "Update failed\n");
            if (bl_mode == BL_DYNAMIC_MODE) {
                bld_finalize();
            }
            return EXIT_FAILURE;
        }
    }
    add_update.clear();
    rm_update.clear();

    unsigned int conn_try = 10;
    char ip_tab[INET6_ADDRSTRLEN];

    // create detection record
    detection = ur_create(tmpl_det,0);
    if (detection == NULL) {
        cerr << "ERROR: No memory available for detection report. Unable to continue." << endl;
        stop = 1;
    }
#ifdef DEBUG
    ofstream out;
    out.open("./detect", ofstream::out);
#endif


    // Create thread for Inactive timeout checking
    pthread_t inactive_timeout_thread_id;
    if (pthread_create(&inactive_timeout_thread_id, NULL, &inactive_timeout_thread_func, tmpl_det)) {
       fprintf(stderr, "ERROR: Could not create inactive timeout flush thread.\n");
       ur_free(detection);
       ur_free_template(templ);
       ur_free_template(tmpl_det);
       fht_destroy(AGGR_TABLE);
       ht_destroy(&hash_blacklist);
       trap_finalize();
       return EXIT_SUCCESS;
    }


    // ***** Main processing loop *****
    while (!stop) {
               
        // retrieve data from server
        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) { // trap is terminated
                break;
            } else if (retval == TRAP_E_TIMEOUT) {
                conn_try--;
                if (!conn_try) {
                    break;
                }
                continue;
            } else { // recieve error
                cerr << "ERROR: Unable to get data. Return value ";
                cerr << dec << retval;
                cerr << " (" << trap_last_error_msg << ")." <<  endl;
                break;
            }
        }

        // check the data size 
        if (data_size != ur_rec_static_size(templ)) {
            if (data_size <= 1) { // end of data
                break;
            } else { // data corrupted
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_static_size(templ) << " ";
                cerr << "Recieved: " << data_size << endl;
                break;
            }
        }

        
        update_timestamp(ur_get(templ, data, UR_TIME_FIRST) >> 32);

        ip_addr_t tmp_ip = ur_get(templ, data, UR_SRC_IP);
        if (tmp_ip.bytes[8] == 147 && tmp_ip.bytes[9] == 229) {
            retval++;
            retval--;
        }

        
        // try to match the ip addresses to blacklist
        if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
            // Check blacklisted IPs (subnet mask /32)
            retval = v4_blacklist_check(templ, tmpl_det, data, detection, hash_blacklist, v4_masks, v6_masks, v4_list);
        } else {
            retval = v6_blacklist_check(templ, tmpl_det, data, detection, hash_blacklist, v4_masks, v6_masks, v6_list);
        }
        
        if (retval == BLACKLISTED) {
#ifdef DEBUG
            cout << "Sending report ..." << endl;
#endif
            aggr_data_t *aggr_data;
            aggr_data_key_t aggr_data_key;
            uint8_t kicked_flag;
            int8_t *data_lock;

            aggr_data_key.srcip = ur_get(templ, data, UR_SRC_IP);
            aggr_data_key.dstip = ur_get(templ, data, UR_DST_IP);
            aggr_data_key.proto = ur_get(templ, data, UR_PROTOCOL);

            new_data->time_first = TIMESTAMP;
            new_data->time_last = TIMESTAMP;
            ur_transfer_static(templ, tmpl_det, data, detection);
            ur_set(tmpl_det, detection, UR_EVENT_SCALE, 1);
            memcpy(new_data->data, detection, ur_rec_size(tmpl_det, detection));

            // Create new aggregation record or find old one already in table
            aggr_data = create_new_aggr(&aggr_data_key, new_data, &data_lock, kicked_data, &kicked_flag);

            // If aggregation record is already present in table
            if (aggr_data) {
                // Update old record 
                if (!update_aggr(tmpl_det, aggr_data)) {
                   // If Active timeout has run out, send data to output
                   trap_send_data(0, aggr_data->data, ur_rec_static_size(tmpl_det), TRAP_HALFWAIT);
                   fht_remove_locked(AGGR_TABLE, &aggr_data_key, data_lock);
                }
                fht_unlock_data(data_lock);
            }

            // If data was kicked out from table, send them to output
            if (kicked_flag) {
               trap_send_data(0, kicked_data->data, ur_rec_static_size(tmpl_det), TRAP_HALFWAIT);
            }




#ifdef DEBUG
            bl_count++;
#endif
        }
#ifdef DEBUG        
        count++;
#endif

        // Critical section starts here
        bld_lock_sync();
        if (bl_mode == BL_DYNAMIC_MODE && BLD_SYNC_FLAG) {
        //  update black_list
#ifdef DEBUG
            out << "Updating black list ..." << endl;
#endif
            string upd_path = file;
            // Update procedure.
            retval = load_update(add_update, rm_update, upd_path);
            if (retval == BLIST_FILE_ERROR) {
                cerr << "ERROR: Unable to load update files. Will use the old tables instead." << endl;
                update = 0;
                continue;
            }
#ifdef DEBUG
            out << "Updates loaded. Performing update operations (" << add_update.size() << " additions/updates and " << rm_update.size() << " removals) ..." << endl;
#endif
            if (!rm_update.empty()) {
#ifdef DEBUG
            out << "Removing invalid entries..." << endl;
#endif
                update_remove(hash_blacklist, v4_list, v6_list, rm_update, v4_masks, v6_masks);
            }
            if (!add_update.empty()) {
#ifdef DEBUG
            out << "Adding new entries and updating persistent entries... " << endl;
#endif
                if (update_add(hash_blacklist, v4_list, v6_list, add_update, v4_masks, v6_masks)) {
                    cerr << "ERROR: Unable to update due the insufficent memory. Unable to continue." << endl;
                    stop = 1;
                    break;
                }
            }

#ifdef DEBUG
            out << "Cleaning update lists ...  " << endl;
#endif

            add_update.clear();
            rm_update.clear();
#ifdef DEBUG
            cout << "Blacklist succesfully updated." << endl;
#endif
           BLD_SYNC_FLAG = 0;
        }
        bld_unlock_sync();
        // Critical section ends here

    }

    // Terminate child process if in dynamic mode
    if (bl_mode == BL_DYNAMIC_MODE) {
#ifdef DEBUG
        fprintf(stderr, "Terminating\n");
#endif
        bld_finalize();
    }

   // Wait for inactive timeout flush thread
   pthread_kill(inactive_timeout_thread_id, SIGUSR1);
   pthread_join(inactive_timeout_thread_id, NULL);


// we don't want cascading shutdown of following modules
   if (send_terminating_unirec) {
      trap_send_data(0, data, 1, TRAP_NO_WAIT);
   }

#ifdef DEBUG
    out << count << " flows went through." << endl;
    out << bl_count << " were marked." << endl;
    out.close();
#endif
    // clean up before termination
    if (detection != NULL) {
        ur_free(detection);
        detection = NULL;
    }
    ur_free_template(templ);
    ur_free_template(tmpl_det);
    ht_destroy(&hash_blacklist);
    fht_destroy(AGGR_TABLE);

    TRAP_DEFAULT_FINALIZATION();

    return EXIT_SUCCESS;
}
