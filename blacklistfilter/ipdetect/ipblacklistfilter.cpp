/**
 * \file ipblacklistfilter.cpp
 * \brief Main module for IPBlackLIstDetector.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

/*
 * Copyright (C) 2013 CESNET
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
#include "../../../unirec/unirec.h"
#include "ipblacklistfilter.h"
#include "../../../common/cuckoo_hash/cuckoo_hash.h"

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
    "Running syntax:\n"
    "\t./ipblacklistfilter -i <trap_interface> <blacklist_folder>\n"
    "The module should be controlled by python script \"detector.py\".\n"
    "Interfaces:\n"
    "   Inputs: 1 (unirec record)\n"
    "   Outputs: 1 (unirec record)\n", 
    1, // Number of input interfaces
    1, // Number of output interfaces
};

static int stop = 0; // global variable for stopping the program
static int update = 0; // global variable for updating blacklists

/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
void signal_handler(int signal)
{
    if (signal == SIGTERM || signal == SIGINT) {
        stop = 1;
        trap_terminate();
    } else if (signal == SIGUSR1) {
        // set update variable
        update = 1;
    }
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

/*
 * Comparison functions for sorting the vector of loaded prefixes
 */
bool sort_by_ip_v4 (const ip_addr_t& addr1, const ip_addr_t& addr2)
{
    return (memcmp(&(addr1.ui32[2]), &(addr2.ui32[2]), 4) < 0) ? true : false;
}

bool sort_by_ip_v6 (const ip_addr_t& addr1, const ip_addr_t& addr2)
{
    return (memcmp(&addr1.ui8, &addr2.ui8, 16) < 0) ? true : false;
}

/**
 * Function for loading source files.
 * Function goes through all files in given directory and loads their content
 * (ip addresses/prefixes) to module's tables/vectors used for IP address
 * classification. Pure addresses are then saved in one hash table (both V4 
 * and V6), prefixes are put into separate vectors for according to their 
 * IP version. Vectors are then sorted for the purpose of binary search.
 * The function also checks whether the record in file is valid ip address 
 * or if the file contains valid data. Invalid records/files are automatically 
 * skipped.
 *
 * @param ip_bl Hash table for storing the addresses.
 * @param source_dir Path to the directory with IP addresses.
 * @return ALL_OK if everything goes well, BLIST_FILE_ERROR if directory cannot be accessed.
 */
int load_ip (cc_hash_table_t& ip_bl, string& source_dir)
{
    DIR* dp; // directory pointer
    struct dirent *file; // file pointer
    ifstream input; // data input

    string line, ip;
    size_t str_pos;

    ip_addr_t key; // ip address (used as key in the map)
    ip_blist_t bl_entry; // black list entry associated with ip address
    
    dp = opendir(source_dir.c_str());

    if (dp == NULL) { // directory cannot be openned
        cerr << "ERROR: Cannot open directory " << source_dir << ". Directory doesn't exist";
        cerr << " or you don't have proper permissions. Unable to continue." << endl; 
        return BLIST_FILE_ERROR;
    }

    while (file = readdir(dp)) { // iterate over files
        if (file->d_name[0] == '.' || file->d_type == 0x4) {
            // we don't need references to direcotry itself and its parent
            continue;
        }

        input.open((source_dir + file->d_name).c_str(), ifstream::in);
        
        if (!input.is_open()) {
            cerr << "ERROR: File " << file->d_name << " cannot be opened and will be skipped." << endl;
            continue;
        }
        
        while (!(input.eof())) {
            getline(input, line);

            if (!line.length()) {
                continue;
            }

            // trim all whitespaces
            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

            str_pos = line.find_first_of('/');

            // prefix length is not specified --> will use 32
            if (str_pos == string::npos) {
                if(!ip_from_str(line.c_str(), &key)) {
                    continue;
                }
                if (ip_is4(&key)) {
                    bl_entry.pref_length = PREFIX_V4_DEFAULT;
                } else {
                    bl_entry.pref_length = PREFIX_V6_DEFAULT;
                }
           /* } else { // commented out for future use with prefixes
                ip = line.substr(0, str_pos);
    
                if(!ip_from_str(ip.c_str(), &key)) {
                    continue;
                }

                ip = line.substr(str_pos + 1);
                bl_entry.pref_length = strtoul(ip.c_str(), NULL, 0);

                if (ip_is4(&key) && (bl_entry.pref_length > 32)) {
                    continue;
                } else if (ip_is6(&key) && (bl_entry.pref_length > 128)) {
                    continue;
                }
            }*/

            } else { // prefix specified -- will drop for now
                continue;
            }
 
            memcpy(&bl_entry.ip, &key, 16); // copy the ip address to the entry

            // get source blacklist
            bl_entry.in_blacklist = strtoul(file->d_name, NULL, 0);
            
            if (bl_entry.in_blacklist == 0) {
                continue;
            }

            if (bl_entry.pref_length == 32 || bl_entry.pref_length == 128) {
                if (ht_get_index(&ip_bl, (char *) key.bytes, ip_bl.key_length) == NOT_FOUND) {
                    ht_insert(&ip_bl, (char *) key.bytes, &bl_entry, ip_bl.key_length);
                }
            }               
            // else
            //  if ip_is4
            //      pushback to v4 prefix list
            //  else
            //      pushback to v6 prefix list
            //
            // sort both vectors (for binary search)
        }
        input.close();
    }

    closedir(dp);
    return ALL_OK;
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
 * @param path Path to the directory with updates.
 * @return ALL_OK if everything goes well, BLIST_FILE_ERROR if directory cannot be accessed.
 */
int load_update(black_list_t& update_list_a, black_list_t& update_list_rm, string& path)
{
    DIR* dp; // directory pointer
    struct dirent *file; // file pointer
 
    ifstream input; // data input

    string line;
    size_t str_pos;

    ip_addr_t key; // ip address (used as key in the map)
    ip_blist_t bl_entry; // black list entry associated with ip address

    dp = opendir(path.c_str());

    bool add_rem = false; // add or remove from table ?

    if (dp == NULL) {
        cerr << "Cannot open directory with updates. Will not update." << endl;
        return BLIST_FILE_ERROR;
    }

    // go over every file with updates (one for each source)
    while (file = readdir(dp)) {
        if (file->d_name[0] == '.' || file->d_type == 0x4) {
            // we don't need references to direcotry itself and its parent or hidden files
            // and we also don't want to go recursively into another directories
            continue;
        }

        input.open((path + file->d_name).c_str(), ifstream::in);

        if (!input.is_open()) {
            cerr << "Cannot open file with updates. Will be skipped." << endl;
            continue;
        }

        while (!input.eof()) {
            getline(input, line);

            // trim all white spaces (if any)
            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

            // transform all letters to lowercase (if any)
            transform(line.begin(), line.end(), line.begin(), ::tolower);

            // encountered a remove line?
            if (line == "#remove") {
                add_rem = true; // switch to remove mode
                continue;
            }

            // are we loading prefix?
            str_pos = line.find_first_of('/');

            if (str_pos == string::npos) { // ip only
                if (!ip_from_str(line.substr(0, str_pos).c_str(), &bl_entry.ip)) {
                    continue;
                }
                if (ip_is4(&bl_entry.ip)) {
                    bl_entry.pref_length = PREFIX_V4_DEFAULT;
                } else {
                    bl_entry.pref_length = PREFIX_V6_DEFAULT;
                }                
            } else { // ip prefix
                if (!ip_from_str(line.substr(0, str_pos).c_str(), &bl_entry.ip)) {
                    continue;
                }
                line.erase(0, str_pos + 1);
                if (str_pos != string::npos) {
                    bl_entry.pref_length = strtoul(line.c_str(), NULL, 0);
                } else {
                    continue;
                }
            }

            // determine blacklist
            bl_entry.in_blacklist = strtoul(file->d_name, NULL, 0);           
            if (bl_entry.in_blacklist == 0x0) {
                cerr << "ERROR: Unable to determine the source blacklist. File " << file->d_name << " will be skipped." << endl;
                input.close();
                break;
            }

            // put entry into its respective update list        
            if (!add_rem) {
                update_list_a.push_back(bl_entry);
            } else {
                update_list_rm.push_back(bl_entry);
            }
        }
        input.close();
    }
    closedir(dp);
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
    int mask_result;
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
 * @return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v4_blacklist_check(ur_template_t* ur_tmp, ur_template_t* ur_det, const void *record, void *detected, cc_hash_table_t& ip_bl)
{
    bool marked = false;
    // index of the prefix the source ip fits in (return value of binary/hash search)
    int search_result;
    ip_addr_t ip = ur_get(ur_tmp, record, UR_SRC_IP);
    search_result = ht_get_index(&ip_bl,(char *) ip.bytes, ip_bl.key_length);
// if (search_result == NOT_FOUND)
//  try prefixes
// if (search_result != NOT_FOUND) ...
    uint8_t bl = 0x0;

    if (search_result != NOT_FOUND) {
        ur_set(ur_det, detected, UR_SRC_BLACKLIST, ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist);
        bl |= (((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist << 4);
        marked = true;
    } else {
        ur_set(ur_det, detected, UR_SRC_BLACKLIST, 0x0);
    }
    ip = ur_get(ur_tmp, record, UR_DST_IP);
    search_result = ht_get_index(&ip_bl, (char *) ip.bytes, ip_bl.key_length);
    if (search_result != NOT_FOUND) {
        ur_set(ur_det, detected, UR_DST_BLACKLIST, ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist);
        bl |= ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist;
        marked = true;
    } else {
        ur_set(ur_det, detected, UR_DST_BLACKLIST, 0x0);
    }
 
// else
//  try prefixes
// if (search_result != NOT_FOUND)
//  ur_set(det_tmp, detected, UR_DST_BLACKLIST
    if (marked) {
        ur_set(ur_det, detected, UR_BLACKLIST_TYPE, bl);
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
 * @return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v6_blacklist_check(ur_template_t* ur_tmp, ur_template_t* ur_det, const void *record, void *detected, cc_hash_table_t& ip_bl)
{
    bool marked = false;
    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;

    ip_addr_t ip = ur_get(ur_tmp, record, UR_SRC_IP);
    search_result = ht_get_index(&ip_bl,(char *) ip.bytes, ip_bl.key_length);
// if (search_result == NOT_FOUND)
//  try prefixes
// if (search_result != NOT_FOUND) ...

    uint8_t bl = 0x0;

    if (search_result != NOT_FOUND) {
        ur_set(ur_det, detected, UR_SRC_BLACKLIST, ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist);
        bl |= (((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist) << 4;
        marked = true;
    } else {
        ur_set(ur_det, detected, UR_SRC_BLACKLIST, 0x0);
    }
    ip = ur_get(ur_tmp, record, UR_DST_IP);
    search_result = ht_get_index(&ip_bl, (char *) ip.bytes, ip_bl.key_length);
// if (search_result == NOT_FOUND)
//  try prefixes
// if (search_result != NOT_FOUND) ...
    if (search_result != NOT_FOUND) {
        ur_set(ur_det, detected, UR_DST_BLACKLIST, ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist);
        bl |= ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist;
        marked = true;
    } else {
        ur_set(ur_det, detected, UR_DST_BLACKLIST, 0x0);
    }
 
    if (marked) {
        ur_set(ur_det, detected, UR_BLACKLIST_TYPE, bl);
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
    int mask_result;
    ip_addr_t masked;
    begin = 0;
    end = black_list.size() - 1;

    while (begin <= end) {
        mid = (begin + end) >> 1;

        if (ip_is4(&(updated->ip))) {
            masked.ui32[2] = updated->ip.ui32[2] & v4mm[black_list[mid].pref_length];
            mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);
        } else {
            if (black_list[mid].pref_length <= 64) { 
                /*
                 * we mask only the "upper part of the address and use
                 * it for comparison (we don't need to compare the whole
                 * address)
                 */
                masked.ui64[0] = updated->ip.ui64[0] & v6mm[black_list[mid].pref_length][0];
                mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
            } else { 
                /*
                 * we mask only the lower part of the address and use 
                 * the whole address for comparison
                 */
                masked.ui64[1] = updated->ip.ui64[1] & v6mm[black_list[mid].pref_length][1];
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
            if (add_upd[i].pref_length == PREFIX_V4_DEFAULT) { // ip only
                insert_index = ht_get_index(&bl_hash, (char *) add_upd[i].ip.bytes, bl_hash.key_length);

                if (insert_index == NOT_FOUND) { // item is not in table --> insert
                    ins_retval = ht_insert(&bl_hash, (char *) add_upd[i].ip.bytes, &add_upd[i], bl_hash.key_length);
                    if (ins_retval != 0) {
                        return ins_retval;
                    }
                } else { // item is in the table --> overwrite
                    ((ip_blist_t *)(bl_hash.table[insert_index].data))->pref_length = add_upd[i].pref_length;
                    ((ip_blist_t *)(bl_hash.table[insert_index].data))->in_blacklist = add_upd[i].in_blacklist;
                }
            } else { // prefix --> use binary search method
                insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v4);
                if (insert_index == BL_ENTRY_UPDATED) { // item was already in table
                    continue;
                } else { // item is new --> add it
                    bl_v4.insert(bl_v4.begin() + insert_index, add_upd[i]);
                }
            }
        } else { // same for v6
            if (add_upd[i].pref_length == PREFIX_V6_DEFAULT) { // ip only
                insert_index = ht_get_index(&bl_hash, (char *) add_upd[i].ip.bytes, bl_hash.key_length);

                if (insert_index == NOT_FOUND) { // item is not in table --> insert
                    ins_retval = ht_insert(&bl_hash, (char *) add_upd[i].ip.bytes, &add_upd[i], bl_hash.key_length);
                    if (ins_retval != 0) {
                        return ins_retval;
                    }
                } else { // item is in the table --> overwrite
                    ((ip_blist_t *)(bl_hash.table[insert_index].data))->pref_length = add_upd[i].pref_length;
                    ((ip_blist_t *)(bl_hash.table[insert_index].data))->in_blacklist = add_upd[i].in_blacklist;
                }
            } else {
                insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v6);
                if (insert_index == BL_ENTRY_UPDATED) {
                    continue;
                } else {
                    bl_v6.insert(bl_v6.begin() + insert_index, add_upd[i]);
                }
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
            if (rm_upd[i].pref_length == PREFIX_V4_DEFAULT) { // ip only
                remove_index = ht_get_index(&bl_hash, (char *) rm_upd[i].ip.bytes, bl_hash.key_length);
                if (remove_index != NOT_FOUND) { // remove from table
                    ht_remove_by_index(&bl_hash, remove_index);
                }
            } else {
                remove_index = ip_binary_search(&(rm_upd[i].ip), m4, m6, bl_v4);
                if (remove_index == IP_NOT_FOUND) { // nothing to remove --> move on
                    continue;
                } else { // remove from vector
                    bl_v4.erase(bl_v4.begin() + remove_index);
                }
            }
        } else { // same for v6
            if (rm_upd[i].pref_length == PREFIX_V6_DEFAULT) { // ip only
                remove_index = ht_get_index(&bl_hash, (char *) rm_upd[i].ip.bytes, bl_hash.key_length);
                if (remove_index != NOT_FOUND) {
                    ht_remove_by_index(&bl_hash, remove_index);
                }
            } else {
                remove_index = ip_binary_search(&(rm_upd[i].ip), m4, m6, bl_v6);
                if (remove_index == IP_NOT_FOUND) {
                    continue;
                } else {
                    bl_v6.erase(bl_v6.begin() + remove_index);
                }
            }
        }
    }
}

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

    // UniRec templates for recieving data and reporting blacklisted IPs
    ur_template_t *templ = ur_create_template("<COLLECTOR_FLOW>");
    ur_template_t *tmpl_det = ur_create_template("<BASIC_FLOW>,DIR_BIT_FIELD,SRC_BLACKLIST,DST_BLACKLIST,BLACKLIST_TYPE");

    // for use with prefixes (not implemented now)
    black_list_t v4_list; 
    black_list_t v6_list;

    // update lists
    black_list_t add_update;
    black_list_t rm_update;

    // mask array (for prefixes)
    ipv4_mask_map_t v4_masks;
    ipv6_mask_map_t v6_masks;

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
    // is directory with sources specified ? (should be in control script)
    if (argc != 2) {
        cerr << "ERROR: Directory with blacklists is not specified. Unable to continue." << endl;
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        trap_finalize();
        return EXIT_FAILURE;
    }

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

    string dir = string(argv[1]);

    // load ip addresses from sources
    retval = load_ip(hash_blacklist, dir);
    
    // something went wrong during loading operation -- terminate with error
    if (retval == BLIST_FILE_ERROR) {
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        ht_destroy(&hash_blacklist);
        trap_finalize();
        return EXIT_FAILURE;
    }

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
        
        retval = v4_blacklist_check(templ, tmpl_det, data, detection, hash_blacklist);
        // try to match the ip addresses to blacklist
        if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
        //      retval = v4_blacklist_check(templ, data, black_list, v4_masks);
            retval = v4_blacklist_check(templ, tmpl_det, data, detection, hash_blacklist);
        } else {
        //      retval = v6_blacklist_check(templ, data, black_list, v6_masks);
            retval = v6_blacklist_check(templ, tmpl_det, data, detection, hash_blacklist);
        }
        
        if (retval == BLACKLISTED) {
#ifdef DEBUG
            cout << "Sending report ..." << endl;
#endif
            ur_transfer_static(templ, tmpl_det, data, detection);
            trap_send_data(0, detection, ur_rec_size(tmpl_det, detection), TRAP_HALFWAIT);
#ifdef DEBUG
            bl_count++;
#endif
        }
#ifdef DEBUG        
        count++;
#endif

        if (update) {
        //  update black_list
#ifdef DEBUG
            out << "Updating black list ..." << endl;
#endif
            string upd_path = dir;
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
            out << "Blacklist succesfully updated." << endl;
#endif
            update = 0;
            continue;
        }

    }

// we don't want cascading shutdown of following modules
#ifndef LONG_RUN
    trap_send_data(0, data, 1, TRAP_HALFWAIT);
#endif

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
    trap_finalize();

    return EXIT_SUCCESS;
}
