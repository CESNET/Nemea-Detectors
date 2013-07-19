/**
 * \file spoofing.cpp
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

#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif
#include "../../unirec/unirec.h"
#include "../ipaddr.h"
#include "blacklistfilter.h"
#include "../cuckoo_hash/cuckoo_hash.h"

//#define DEBUG 1


using namespace std;

trap_module_info_t module_info = {
    "IP blacklist detection module", // Module name
    // Module description
    "Module recieves the UniRec record and checks if the stored source address\n"
    "or destination address isn't present in any blacklist that are available.\n"
    "If any of the addresses is blacklisted the record is changed by adding \n"
    "a number of the list which blacklisted the address. UniRec with this \n"
    "flag is then sent to the next module.\n"
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
 * Function for loading prefix file.
 * Function reads file with network prefixes and creates a vector for use
 * filters. This function should be called only once, since loading 
 * prefixes is needed only on "cold start of the detector" or if we want to 
 * teach the detector new file. (Possile changes to get signal for loading).
 *
 * @param prefix_list_v4 List of IPv4 prefixes to be filled.
 * @param prefix_list_v6 List of IPv6 prefixes to be filled.
 * @param prefix_file File with prefixes to be loaded and parsed to structures.
 * @return ALL_OK if everything goes smoothly otherwise PREFIX_FILE_ERROR.
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
    
//    map<ip_addr_t,ip_blist_t,bool(*)(const ip_addr_t&, const ip_addr_t&)> v4_dedup (sort_by_ip_v4);
//    map<ip_addr_t,ip_blist_t,bool(*)(const ip_addr_t&, const ip_addr_t&)> v6_dedup (sort_by_ip_v6);

    dp = opendir(source_dir.c_str());

    if (dp == NULL) { // directory cannot be openned
        cerr << "ERROR: Cannot open directory " << source_dir << ". Directory doesn't exist";
        cerr << " or you don't have proper permissions. Unable to continue." << endl; 
        return BLIST_FILE_ERROR;
    }

    while (file = readdir(dp)) { // iterate over files

        if (string(file->d_name) == "." || string(file->d_name) == "..") {
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

            // trim all whitespaces
            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

            str_pos = line.find_first_of('/');

            // prefix length is not specified --> will use 32
            if (str_pos == string::npos) {
#ifdef DEBUG
                cout << line << endl;
#endif
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
            ip = string(file->d_name);
            str_pos = ip.find_last_of('.');
            bl_entry.in_blacklist = strtoul(ip.substr(str_pos + 1).c_str(), NULL, 0);
            
            if (bl_entry.in_blacklist == 0) {
                continue;
            }

            if (bl_entry.pref_length == 32) {
                if (ht_get_index(&ip_bl, (char *) key.bytes) == NOT_FOUND) {
                    ht_insert(&ip_bl, (char *) key.bytes, &bl_entry);
                }
            }

        }
        input.close();
    }

/* commented out for future use with prefixes
 *
    // we prepare vectors with ip addresses (maps are used only to prevent 
    // duplicate values)

    black_list_v4.reserve(v4_dedup.size());
    black_list_v6.reserve(v6_dedup.size());

    map<ip_addr_t,ip_blist_t,bool(*)(const ip_addr_t&, const ip_addr_t&)>::iterator v4_dedup_it;
    map<ip_addr_t,ip_blist_t,bool(*)(const ip_addr_t&, const ip_addr_t&)>::iterator v6_dedup_it;

    // copy maps into the respective vectors
    for (v4_dedup_it = v4_dedup.begin(); v4_dedup_it != v4_dedup.end(); ++v4_dedup_it) {
        v4_dedup_it->second.ip = v4_dedup_it->first;
        black_list_v4.push_back(v4_dedup_it->second);
    }
    for (v6_dedup_it = v6_dedup.begin(); v6_dedup_it != v6_dedup.end(); ++v6_dedup_it) {
        v6_dedup_it->second.ip = v6_dedup_it->first;
        black_list_v6.push_back(v6_dedup_it->second);
    }
*/
    closedir(dp);
    return ALL_OK;
}

int load_update(black_list_t& update_list_a, black_list_t& update_list_rm, string& path)
{
/*
 * directory
 *
 * DIR* dp; // directory pointer
 * struct dirent *file; // file pointer
 */

 
    ifstream input; // data input

    string line, ip;
    size_t str_pos;

    ip_addr_t key; // ip address (used as key in the map)
    ip_blist_t bl_entry; // black list entry associated with ip address

/*
 * directory
 *
 * dp = opendir(path);
 *
 * if (dp == NULL) {
 *     cerr << "Cannot open directory with updates. Will not update." << endl;
 *     return BLIST_FILE_ERROR;
 * }
 *
 * while (file = readdir(dp)) {
 *      input.open((path + file->d_name).c_str(), ifstream::in);
 */

    input.open(path.c_str(), ifstream::in);

    if (!input.is_open()) {
        cerr << "Cannot open file with updates. Will be skipped." << endl; // or terminate update
//        continue;
        return BLIST_FILE_ERROR;
    }

    while (!input.eof()) {
        getline(input, line);

        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

        str_pos = line.find_first_of('/');

        if (str_pos == string::npos) {
            str_pos == line.find_first_of(';');
            if (str_pos != string::npos) {
                if (!ip_from_str(line.substr(0, str_pos).c_str(), &bl_entry.ip)) {
                    continue;
                }
            } else {
                continue;
            }
        } else {
            if (!ip_from_str(line.substr(0, str_pos).c_str(), &bl_entry.ip)) {
                continue;
            }
            line.erase(0, str_pos + 1);
            str_pos = line.find_first_of(';');
            if (str_pos != string::npos) {
                bl_entry.pref_length = strtoul(line.substr(0, str_pos).c_str(), NULL, 0);
            } else {
                continue;
            }
        }

        line.erase(0, str_pos + 1);

        line.find_first_of(';');
        bl_entry.in_blacklist = strtoul(line.substr(0, str_pos).c_str(), NULL, 0);
        
        line.erase(0, str_pos + 1);

        if (line.at(0) == 'A') {
            update_list_a.push_back(bl_entry);
        } else if (line.at(0) == 'R') {
            update_list_rm.push_back(bl_entry);
        }
    }
            
}
 
/**
 * Function for binary searching in prefix lists.
 * Function uses binary search algorithm to determine whehter the given ip 
 * address fits any of the prefix in the list.
 *
 * @param searched IP address that we are checking.
 * @param v4mm Map of IPv4 masks.
 * @param v6mm Map of IPv6 masks.
 * @param prefix_list List of prefixes to be compared with.
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
 * BLACKLIST COMPARATOR
 */
int v4_blacklist_check(ur_template_t* ur_tmp, const void *record, cc_hash_table_t& ip_bl)
{

#ifdef DEBUG
    char dst[INET6_ADDRSTRLEN];
    char src[INET6_ADDRSTRLEN];
    ip_to_str(&ur_get(ur_tmp, record, UR_SRC_IP), src);
    ip_to_str(&ur_get(ur_tmp, record, UR_DST_IP), dst);
    
    cerr << src << " and " << dst << endl;
#endif

    bool marked = false;
    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;
    ip_addr_t ip = ur_get(ur_tmp, record, UR_SRC_IP);
//    char *ip_key = (char *) ur_get(ur_tmp, record, UR_SRC_IP).bytes;
    search_result = ht_get_index(&ip_bl,(char *) ip.bytes);

    if (search_result != NOT_FOUND) {
//        ur_set(ur_tmp, record, UR_SRC_BLACKLIST, ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist);
        marked = true;
    }
    ip = ur_get(ur_tmp, record, UR_DST_IP);
    search_result = ht_get_index(&ip_bl, (char *) ip.bytes);
    if (search_result != NOT_FOUND) {
//        ur_set(ur_tmp, record, UR_DST_BLACKLIST, ((ip_blist_t*) ip_bl.table[search_result].data)->in_blacklist);
        marked = true;
    }
 
    if (marked) {
        return BLACKLISTED;
    }
    return ADDR_CLEAR;
}


///////////////
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
/* For future use with prefixes
 * 
void update_add(black_list_t& bl_v4, black_list_t& bl_v6, black_list_t& add_upd, ipv4_mask_map_t& m4, ipv6_mask_map_t& m6)
{
    int insert_index; // position for item insertion

    for (int i = 0; i < add_upd.size(); i++) { // go through updates

        if (ip_is4(&(add_upd[i].ip))) {
            insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v4);
            if (insert_index == BL_ENTRY_UPDATED) {
                continue;
            } else {
                bl_v4.insert(bl_v4.begin() + insert_index, add_upd[i]);
            }
        } else {
            insert_index = ip_binary_update(&(add_upd[i]), m4, m6, bl_v6);
            if (insert_index == BL_ENTRY_UPDATED) {
                continue;
            } else {
                bl_v4.insert(bl_v6.begin() + insert_index, add_upd[i]);
            }
        }
    }
}

void update_remove(black_list_t& bl_v4, black_list_t& bl_v6, black_list_t& rm_upd, ipv4_mask_map_t& m4, ipv6_mask_map_t& m6)
{
    int remove_index; // position of deleted item

    for (int i = 0; i < rm_upd.size(); i++) { // go through updates

        if (ip_is4(&(rm_upd[i].ip))) {
            remove_index = ip_binary_search(&(rm_upd[i].ip), m4, m6, bl_v4);
            if (remove_index == IP_NOT_FOUND) {
                continue;
            } else {
                bl_v4.erase(bl_v4.begin() + remove_index);
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
*/

void ht_update_add(black_list_t& add_upd, cc_hash_table_t& ht)
{
    int insert_index; // position for item insertion

    for (int i = 0; i < add_upd.size(); i++) { // go through updates
        insert_index = ht_get_index(&ht, (char *) add_upd[i].ip.bytes);
        if (insert_index == NOT_FOUND) { // item is not in table --> insert
            ht_insert(&ht, (char *) add_upd[i].ip.bytes, &add_upd[i]);
        } else { // item is in the table --> overwrite
           ((ip_blist_t *)(ht.table[insert_index].data))->pref_length = add_upd[i].pref_length;
           ((ip_blist_t *)(ht.table[insert_index].data))->in_blacklist = add_upd[i].in_blacklist;
        }
    }
}

void ht_update_remove(black_list_t& rm_upd, cc_hash_table_t& ht)
{
    int remove_index; // position of deleted item

    for (int i = 0; i < rm_upd.size(); i++) { // go through updates
        remove_index = ht_get_index(&ht, (char *) rm_upd[i].ip.bytes);
        if (remove_index != NOT_FOUND) {
            ht_remove_by_index(&ht, remove_index);
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

    ur_template_t *templ = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS");
//    ur_template_t *templ = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD");
//    ur_template_t *templ = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS,SRC_BLACKLIST,DST_BLACKLIST");


      // for use with prefixes (not implemented now)
//    black_list_t v4_list; 
//    black_list_t v6_list;

      // update lists
//    black_list_t add_update;
//    black_list_t rm_update;

    // can be used for both v4 and v6
    cc_hash_table_t hash_blacklist;

    // Initialize TRAP library (create and init all interfaces)
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        if (retval == TRAP_E_HELP) {
            trap_print_help(&module_info);
            return EXIT_SUCCESS;
        }
        cerr << "ERROR: Cannot parse input parameters: " << trap_last_error_msg << endl;
        return retval;
    }
     
    retval = trap_init(&module_info, ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP couldn't be initialized: " << trap_last_error_msg << endl;
        return retval;
    }

    if (argc != 2) {
        cerr << "ERROR: Directory with blacklists is not specified. Unable to continue." << endl;
        return EXIT_FAILURE;
    }
    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    ht_init(&hash_blacklist, BL_HASH_SIZE, sizeof(ip_blist_t), 16);

    const void *data;
    uint16_t data_size;

    ///////////////////
    int count = 0, bl_count = 0;

    string dir = string(argv[1]);

    load_ip(hash_blacklist, dir);

    char ip_tab[INET6_ADDRSTRLEN];

    // ***** Main processing loop *****
    while (!stop) {
                
        // retrieve data from server
        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) { // trap is terminated
                break;
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
        
        retval = v4_blacklist_check(templ, data, hash_blacklist);
        // try to match the ip addresses to blacklist
        // if (ip_is4(&(ur_get(templ, data, UR_SRC_IP) {
        //      retval = v4_blacklist_check(templ, data, black_list, v4_masks);
        // } else {
        //      retval = v6_blacklist_check(templ, data, black_list, v6_masks);
        // }
        
        if (retval == BLACKLISTED) {
            bl_count++;
        }
        
        count++;

        if (update) {
        //  update black_list
#ifdef DEBUG
            cout << "Updating black list ..." << endl;
#endif

            // Update procedure. NOT WORKING YET.
//          load_update(add_update, rm_update, upd_filename);
//          ht_update_remove(rm_update, hash_blacklist);
//          ht_update_add(add_update, hash_blacklist);
//          add_update.clear();
//          rm_update.clear();
#ifdef DEBUG
            cout << "Blacklist succesfully updated." << endl;
#endif
            continue;
        }

    }


    trap_send_data(0, data, 1, TRAP_WAIT);

    // clean up before termination
//    cout << count << " flows went through." << endl;
  //  cout << bl_count << " were marked." << endl;
    ur_free_template(templ);
    ht_destroy(&hash_blacklist);
    trap_finalize();

    return retval;
}
