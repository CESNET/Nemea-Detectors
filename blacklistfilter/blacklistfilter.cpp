/**
 * \file spoofing.cpp
 * \brief IP spoofing detector for Nemea
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <map>
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

#define DEBUG 1


using namespace std;

trap_module_info_t module_info = {
    "IP spoofing detection module", // Module name
    // Module description
    "Interfaces:\n"
    "   Inputs: 1 (unirec record)\n"
    "   Outputs: 1 (unirec record)\n", 
    1, // Number of input interfaces
    1, // Number of output interfaces
};

static int stop = 0;
static int update = 0;

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
int load_ip (cc_hash_table_t& ip_bl, black_list_t& pref_list_v4, black_list_t& pref_list_v6, const char *source_dir)
{
    DIR* dp; // directory pointer
    struct dirent *file; // file pointer
    ifstream input; // data input

    string line, ip;
    size_t str_pos;

    ip_addr_t key; // ip address (used as key in the map)
    ip_blist_t bl_entry; // black list entry associated with ip address
    
    map<ip_addr_t,ip_blist_t,bool(*)(const ip_addr_t&, const ip_addr_t&)> v4_dedup (sort_by_ip_v4);
    map<ip_addr_t,ip_blist_t,bool(*)(const ip_addr_t&, const ip_addr_t&)> v6_dedup (sort_by_ip_v6);

    dp = opendir(source_dir);

    if (dp == NULL) { // directory cannot be openned
        cerr << "ERROR: Cannot open directory " << source_dir << ". Directory doesn't exist";
        cerr << " or you don't have proper permissions. Unable to continue." << endl; 
        return BLIST_FILE_ERROR;
    }

    while (file = readdir(dp)) { // iterate over files
        input.open(file->d_name, ifstream::in);
        
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
            } else {
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
            }
            
            memcpy(&bl_entry.ip, &key, 16); // copy the ip address to the entry

            // get source blacklist
            ip = string(file->d_name);
            str_pos = ip.find_last_of('.');
            bl_entry.in_blacklist = strtoul(ip.substr(str_pos).c_str(), NULL, 0);
            
            if (bl_entry.in_blacklist == 0) {
                continue;
            }

            if (bl_entry.pref_length == 32) {
                ht_insert(ip_bl, key, &bl_entry);
            }

            if (ip_is4(&key) && (v4_dedup.count(key) == 0)) {
                v4_dedup.insert(pair<ip_addr_t, ip_blist_t>(key, bl_entry));
            } else if (ip_is6(&key) && (v6_dedup.count(key) == 0)) {
                v6_dedup.insert(pair<ip_addr_t, ip_blist_t>(key, bl_entry));
            }
        }
        input.close();
    }

    if (v4_dedup.empty() && v6_dedup.empty()) {
        cerr << "ERROR: No addresses were loaded. Unable to continue." << endl;
        return BLIST_FILE_ERROR;
    }

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
 */
int v4_blacklist_check(ur_template_t* ur_tmp, const void *record, black_list_t& black_list, ipv4_mask_map_t& v4mm)
{

    ipv6_mask_map_t dummy; // dummy structure for the binary search parameter
    bool marked = false;
    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;

    search_result = ip_binary_search(&(ur_get(ur_tmp, record, UR_SRC_IP)), v4mm, dummy, black_list);
    if (search_result != IP_NOT_FOUND) {
        // ur_set(ur_tmp, record, UR_SRC_BLACKLIST, black_list[search_result].in_blacklist);
        marked = true;
    }
    search_result = ip_binary_search(&(ur_get(ur_tmp, record, UR_DST_IP)), v4mm, dummy, black_list);
    if (search_result != IP_NOT_FOUND) {
        // ur_set(ur_tmp, record, UR_DST_BLACKLIST, black_list[search_result].in_blacklist);
        marked = true;
    }
 
    if (marked) {
        return BLACKLISTED;
    }
    return ADDR_CLEAR;
}

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
        black_list[mid].ip = updated->ip;
        black_list[mid].pref_length = updated->pref_length;
        black_list[mid].in_blacklist = updated->in_blacklist;
        return BL_ENTRY_UPDATED;
    } else {// position is shifted for safety reasons
        return begin;
    }
}

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

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

    ur_template_t *templ = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS");
//    ur_template_t *templ = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD");

    black_list_t v4_list; 
    black_list_t v6_list; 


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
    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    const void *data;
    uint16_t data_size;

    ///////////////////
    int a = 0, b = 1, tmp;
    int count = 0;

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

        // try to match the ip addresses to blacklist
        // if (ip_is4(&(ur_get(templ, data, UR_SRC_IP) {
        //      retval = v4_blacklist_check(templ, data, black_list, v4_masks);
        // } else {
        //      retval = v6_blacklist_check(templ, data, black_list, v6_masks);
        // }
        // if (retval = BLACKLISTED) {
        //  send UniRec with blacklist marks
        // }
        
        count++;

        if (update) {
        //  update black_list
            cout << "Updating black list ..." << endl;
            for (int i = 0; i < 2000000000; i++) {
                tmp = a;
                a = b;
                b = tmp;
            }
            update = 0;
            continue;
        }

    }


    trap_send_data(0, data, 1, TRAP_WAIT);

    // clean up before termination
    cout << count << " flows went through." << endl;
    ur_free_template(templ);
    trap_finalize();

    return retval;
}
