/**
 * \file spoofing.cpp
 * \brief IP spoofing detector for Nemea
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

#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif
#include "../../unirec/unirec.h"
#include "spoofing.h"
#include <libtrap/trap.h>

#define DEBUG 1


using namespace std;

trap_module_info_t module_info = {
    "IP spoofing detection module", // Module name
    // Module description
    "This module checks ip addresses in data flows for possible IP spoofing.\n"
    "It uses four conditions to determine this:\n"
    "1. Testing for bogon prefixes\n"
    "2. Checking symetric routes\n"
    "3. Checking asymetric routes\n"
    "4. Counting new flows\n"
    "Interfaces:\n"
    "   Inputs: 1 (unirec record)\n"
    "   Outputs: 1 (unirec record)\n" 
    "Additional parameters:\n"
    "   -b <filename>    File with list of bogon prefixes. This parameter is \n"
    "                    mandatory.\n"
    "   -c <filename>    File with other specific prefixes.\n"
    "   -s <sec>         Time before updating records for symetric routing \n"
    "                    filter. Default value is 45 seconds.\n"
    "   -t <num>         Threshold for reporting spoofed addresses from new \n"
    "                    filter. Default value is 1000 flows.\n",
    1, // Number of input interfaces
    1, // Number of output interfaces
};

static int stop = 0;

// *****    Bloom filter handling    *****

static int bf_active = 0; // index of currently used bloom filter
static int bf_learning = 1; // index of inactive bloom filter

/**
 * Procedure for swapping the active filters
 */
inline void swap_filters() 
{
    int tmp;
    tmp = bf_learning;
    bf_learning = bf_active;
    bf_active = tmp;
}

/**
 * Procedure for creating the sets of bloom filters for new flow counter.
 * @param length Length of the vector with prefixes. Filters are on the same indexes as their respective prefixes.
 * @param filters Set of Bloom filters to be created.
 */
void create_nflow_filters(int length, flow_filter_t* filters)
{
    for (int i = 0; i < length; i++) {
        bloom_parameters bp;
        bp.projected_element_count = 1000000;
        bp.false_positive_probability = 0.01;
        bp.compute_optimal_parameters();

        flow_count_t fca;
        flow_count_t fcl;

        fca.sources = new bloom_filter(bp);
        fcl.sources = new bloom_filter(bp);

        fca.count = fcl.count = 0;
       
        filters[bf_active].flows.push_back(fca);
        filters[bf_learning].flows.push_back(fcl);
    }
    filters[bf_active].timestamp = 0x0;
    filters[bf_learning].timestamp = 0x0;
}

/**
 * Procedure for erasing the content of bloom filter that is being
 * set inactive.
 *
 * @param filter_set Set of filters that is being cleared.
 */
void clear_filters(flow_filter_t& filter_set)
{
    for (int i = 0;i < filter_set.flows.size(); i++) {
        filter_set.flows[i].sources->clear();
        filter_set.flows[i].count = 0;
    }
}

/**
 * Procedure for destroying all filters for module termination
 *
 * @param filters Bloom filters to be freed from memory.
 */
void destroy_filters(flow_filter_t* filters)
{
    for (int i = 0; i < filters[bf_active].flows.size(); i++) {
        delete filters[bf_active].flows[i].sources;
        delete filters[bf_learning].flows[i].sources;
    }
    filters[bf_active].flows.clear();
    filters[bf_active].flows.clear();
}

/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
void signal_handler(int signal)
{
    if (signal == SIGTERM || signal == SIGINT) {
        stop = 1;
        trap_terminate();
    }
}

// **********   BOGON PREFIX FILTER   **********
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
bool sort_by_prefix_v4 (const ip_prefix_t& addr1, const ip_prefix_t& addr2)
{
    return (memcmp(&(addr1.ip.ui32[2]), &(addr2.ip.ui32[2]), 4) < 0) ? true : false;
}

bool sort_by_prefix_v6 (const ip_prefix_t& addr1, const ip_prefix_t& addr2)
{
    return (memcmp(&addr1.ip.ui8, &addr2.ip.ui8, 16) < 0) ? true : false;
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
int load_pref (pref_list_t& prefix_list_v4, pref_list_t& prefix_list_v6, const char *prefix_file)
{
    int error_cnt = 0;
    ip_prefix_t pref;
    ifstream pref_file;
    
    // open file with prefixes
    pref_file.open(prefix_file);

    // unable to open prefix file
    if (!pref_file.is_open()) {
        cerr << "ERROR: File with network prefixes couldn't be opened. Unable to continue." << endl;
        return PREFIX_FILE_ERROR;
    }

    // loading the prefixes to memory
    while (!(pref_file.eof())) {

        string line;
        string raw_ip;
        size_t pos;
        getline(pref_file, line);

        // trim whitespaces from the input
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

        pos = line.find_first_of('/');
        if (pos == string::npos) {
            // prefix length is missing from the line
            continue;
        }
        raw_ip = line.substr(0, pos);

        /*
         * Convert input to ip address for use in program
         * If it fails (invalid ip address) free the memory and continue 
         * to next line.
         */
        if (!ip_from_str(raw_ip.c_str(), &(pref.ip))) {
            continue;
        }
        // load prefix length (+1 for skipping the '/' character
        raw_ip = line.substr(pos + 1);

        // convert to number
        pref.pref_length = strtoul(raw_ip.c_str(), NULL, 0);

        // length of the prefix is out of bounds (32 for IPv4, 128 for IPv6)
        if (ip_is4(&(pref.ip)) &&  (pref.pref_length > 32)) {
            continue;
        } else if (ip_is6(&(pref.ip)) && (pref.pref_length > 128)) {
            continue;
        }

        if (ip_is4(&(pref.ip))) {
            prefix_list_v4.push_back(pref);
        } else {
            prefix_list_v6.push_back(pref);
        }

    }

    // nothing was loaded from the given file
    if (prefix_list_v4.empty() && prefix_list_v6.empty()) {
        cerr << "ERROR: No networks were loaded. File is probably in wrong format. Unable to continue." << endl;
        return PREFIX_FILE_ERROR;
    }

    // sort lists for binary search used in filters
    sort(prefix_list_v4.begin(), prefix_list_v4.end(), sort_by_prefix_v4);
    sort(prefix_list_v6.begin(), prefix_list_v6.end(), sort_by_prefix_v6);

    pref_file.close();
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
int ip_binary_search(ip_addr_t* searched, ipv4_mask_map_t& v4mm, ipv6_mask_map_t& v6mm, pref_list_t& prefix_list)
{
    int begin, end, mid;
    int mask_result;
    ip_addr_t masked;
    begin = 0;
    end = prefix_list.size() - 1;

    while (begin <= end) {
        mid = (begin + end) >> 1;

        if (ip_is4(searched)) {
            masked.ui32[2] = searched->ui32[2] & v4mm[prefix_list[mid].pref_length];
            mask_result = memcmp(&(prefix_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);
        } else {
            if (prefix_list[mid].pref_length <= 64) { 
                /* 
                 * we mask only the "upper part of the address and use
                 * it for comparison (we don't need to compare the whole
                 * address)
                 */
                masked.ui64[0] = searched->ui64[0] & v6mm[prefix_list[mid].pref_length][0];
                mask_result = memcmp(&(prefix_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
            } else { 
                /*
                 * we mask only the lower part of the address and use 
                 * the whole address for comparison
                 */
                masked.ui64[1] = searched->ui64[1] & v6mm[prefix_list[mid].pref_length][1];
                mask_result = memcmp(&(prefix_list[mid].ip.ui8), &(masked.ui8), 16);
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

    if (mask_result == 0) { // we found an address --> return index for it
        return mid;
    }
    return IP_NOT_FOUND;
}

/**
 * Filter for checking ipv4 for bogon prefixes.
 * This function checks the given ip address  whether it matches 
 * any of the bogon prefixes in list. If it does filter returns 
 * positive spoofing constant and spoofing counter is increased.
 * 
 * @param ur_tmp Template used for UniRec record.
 * @param checked Record being checked.
 * @param prefix_list List of bogon prefixes used for checking.
 * @param v4mm Array of every possible netmasks for protocol.
 * @return SPOOF_POSITIVE if address fits the bogon prefix otherwise SPOOF_NEGATIVE.
 */
int v4_bogon_filter(ur_template_t* ur_tmp, const void *checked, pref_list_t& prefix_list, ipv4_mask_map_t& v4mm)
{
    //check source address of the record with each prefix

    ipv6_mask_map_t dummy; // dummy structure for the binary search parameter

    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;

    search_result = ip_binary_search(&(ur_get(ur_tmp, checked, UR_SRC_IP)), v4mm, dummy, prefix_list);

#ifdef DEBUG
        char debug_ip_src[INET6_ADDRSTRLEN];
        char debug_ip_pref[INET6_ADDRSTRLEN];
        ip_to_str(&(ur_get(ur_tmp, checked, UR_SRC_IP)), debug_ip_src);
        ip_to_str(&(prefix_list[search_result].ip), debug_ip_pref);
#endif

    if (search_result == IP_NOT_FOUND) {
        return SPOOF_NEGATIVE;
    } else {
        // address fits any of the prefix from the given list
#ifdef DEBUG
            cout << "Possible spoofing found: ";
            cout << debug_ip_src;
            cout << " fits prefix ";
            cout << debug_ip_pref;
            cout <<"/";
            short a;
            cout << dec <<  (a = prefix_list[search_result].pref_length) << endl;
#endif
            return SPOOF_POSITIVE;
    }
    return SPOOF_NEGATIVE;
}

/**
 * Filter for checking ipv6 for bogon prefixes.
 * This function checks the given ip address  whether it matches 
 * any of the bogon prefixes in list. If it does filter returns 
 * positive spoofing constant and spoofing counter is increased.
 * 
 * @param ur_tmp Template used for UniRec record.
 * @param checked Record being checked.
 * @param prefix_list List of bogon prefixes used for checking
 * @param v6mm Array of every possible netmasks for protocol
 * @return SPOOF_POSITIVE if address fits the bogon prefix otherwise SPOOF_NEGATIVE
 */
int v6_bogon_filter(ur_template_t* ur_tmp, const void *checked, pref_list_t& prefix_list, ipv6_mask_map_t& v6mm)
{

    ipv4_mask_map_t dummy; // dummy structure for the binary search parameter

    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;

    search_result = ip_binary_search(&(ur_get(ur_tmp, checked, UR_SRC_IP)), dummy, v6mm, prefix_list);

#ifdef DEBUG
        char debug_ip_src[INET6_ADDRSTRLEN];
        char debug_ip_pref[INET6_ADDRSTRLEN];
        ip_to_str(&(ur_get(ur_tmp, checked, UR_SRC_IP)), debug_ip_src);
        ip_to_str(&(prefix_list[search_result].ip), debug_ip_pref);
#endif

    if (search_result == IP_NOT_FOUND) {
        return SPOOF_NEGATIVE;
    } else {

#ifdef DEBUG
       cout << "Possible spoofing found: ";
       cout << debug_ip_src;
       cout << " fits bogon prefix ";
       cout << debug_ip_pref;
       cout <<"/";
       short a;
       cout << dec <<  (a = prefix_list[search_result].pref_length) << endl;
#endif

        return SPOOF_POSITIVE;
    }
    return SPOOF_NEGATIVE;   
}

// **********   SYMETRIC ROUTING FILTER   **********

/**
 * Function for checking routing symetry for IPv4.
 * Function takes the direction flag from the record and based on its value 
 * it decides whether to associate the link with its source IP or to check 
 * the link used by the communication. Checking of the communication is 
 * done based on the map of links their respective source IP address. The map 
 * is filled from outgoing communication by the destination address. If the 
 * communication flow is incomming then the source address is used as a key 
 * to the map to get the link used by this communiation. If the link fits 
 * the bitmask stored on this location then the communication is considered 
 * legit (the route is symetric). If the result of masking  AND operation is
 * 0x0 then there is no valid link for this communication and the source IP is 
 * flagged as spoofed.
 *
 * @param ur_tmp Template used for UniRec record.
 * @param record Record (UniRec format) that is being analyzed.
 * @param src Map with link masks associated to their respective sources.
 * @param rw_time Time before updating (rewriting) the link record in the map.
 * @return SPOOF_NEGATIVE if the route is symetric otherwise SPOOF_POSITIVE.
 */

int check_symetry_v4(ur_template_t *ur_tmp, const void *record, v4_sym_sources_t& src, unsigned rw_time)
{

#ifdef DEBUG
    char debug_ip_src[INET6_ADDRSTRLEN];
    char debug_ip_dst[INET6_ADDRSTRLEN];
    ip_to_str(&(ur_get(ur_tmp, record, UR_SRC_IP)), debug_ip_src);
    ip_to_str(&(ur_get(ur_tmp, record, UR_DST_IP)), debug_ip_dst);
#endif
    unsigned v4_numeric;

    // check incomming/outgoing traffic
    if (ur_get(ur_tmp, record, UR_DIR_BIT_FIELD) == 0x0) {// outgoing trafic
        // mask with 24-bit long prefix
        v4_numeric = ip_get_v4_as_int(&(ur_get(ur_tmp, record, UR_DST_IP))) & 0x00FFFFFF;

        if (src.count(v4_numeric)
            && (((ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL) - src[v4_numeric].timestamp) < rw_time)) {
            src[v4_numeric].link |= ur_get(ur_tmp, record, UR_LINK_BIT_FIELD);
            src[v4_numeric].timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
        } else {
            sym_src_t src_rec;
            src_rec.link = ur_get(ur_tmp, record, UR_LINK_BIT_FIELD);
            src_rec.timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
            src.insert(pair<int, sym_src_t>(v4_numeric, src_rec));
        }

    } else { // incomming traffic --> check for validity
        // mask with 24-bit long prefix
        v4_numeric = ip_get_v4_as_int(&(ur_get(ur_tmp, record, UR_SRC_IP))) & 0x00FFFFFF;

        if (src.count(v4_numeric)) {
            int valid = (src[v4_numeric].link) & ur_get(ur_tmp, record, UR_LINK_BIT_FIELD);
            if (valid == 0x0) {
                //no valid link found => possible spoofing
#ifdef  DEBUG
                cout << debug_ip_src << " ---> " << debug_ip_dst << endl;
                cout << "Flow goes through " << (long long) ur_get(ur_tmp, record, UR_LINK_BIT_FIELD); 
                cout << " while stored is " << (long long) src[v4_numeric].link  << endl;
                cout << "Possible spoofing found: tested route is asymetric." << endl;
#endif
                return SPOOF_POSITIVE;
            } else {
                // trafic went through the valid link
                return SPOOF_NEGATIVE;
            }
        } else { // no bit record found -- can't decide
            return SPOOF_NEGATIVE;
        }
    }
    return SPOOF_NEGATIVE;
}

/**
 * Function for checking routing symetry for IPv6.
 * Function takes the direction flag from the record and based on its value 
 * it decides whether to associate the link with its source IP or to check 
 * the link used by the communication. Checking of the communication is 
 * done based on the map of links their respective source IP address. The map 
 * is filled from outgoing communication by the destination address. If the 
 * communication flow is incomming then the source address is used as a key 
 * to the map to get the link used by this communiation. If the link fits 
 * the bitmask stored on this location then the communication is considered 
 * legit (the route is symetric). If the result of masking  AND operation is
 * 0x0 then there is no valid link for this communication and the source IP is 
 * flagged as spoofed.
 *
 * @param ur_tmp Template used for UniRec record.
 * @param record Record (UniRec format) that is being analyzed.
 * @param src Map with link masks associated to their respective sources.
 * @param rw_time Time before updating (rewriting) the link record in the map.
 * @return SPOOF_NEGATIVE if the route is symetric otherwise SPOOF_POSITIVE.
 */


int check_symetry_v6(ur_template_t *ur_tmp, const void *record, v6_sym_sources_t& src, unsigned rw_time)
{

#ifdef DEBUG
    char debug_ip_src[INET6_ADDRSTRLEN];
    char debug_ip_dst[INET6_ADDRSTRLEN];
    ip_to_str(&(ur_get(ur_tmp, record, UR_SRC_IP)), debug_ip_src);
    ip_to_str(&(ur_get(ur_tmp, record, UR_DST_IP)), debug_ip_dst);
#endif

    // check incomming/outgoing traffic
    if (ur_get(ur_tmp, record, UR_DIR_BIT_FIELD) == 0x0) {// outgoing traffic
        // for future use with /48 prefix length
        // record->dst_addr.ui64[0] &= 0xFFFFFFFFFFFF0000ULL;

        if (src.count(ur_get(ur_tmp, record, UR_SRC_IP).ui64[0])
            && ((ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL)
                 - src[ur_get(ur_tmp, record, UR_DST_IP).ui64[0]].timestamp) < rw_time) {
            src[ur_get(ur_tmp, record, UR_DST_IP).ui64[0]].link |= ur_get(ur_tmp, record, UR_LINK_BIT_FIELD);
            src[ur_get(ur_tmp, record, UR_DST_IP).ui64[0]].timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
        } else {
            sym_src_t src_rec;
            src_rec.link = ur_get(ur_tmp, record, UR_LINK_BIT_FIELD);
            src_rec.timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
            src.insert(pair<uint64_t, sym_src_t>(ur_get(ur_tmp, record, UR_DST_IP).ui64[0], src_rec));
        }

    } else { // incomming traffic --> check for validity
        // for future use with /48 prefix length
        //record->src_addr.ui64[0] &= 0xFFFFFFFFFFFF0000ULL;

        if (src.count(ur_get(ur_tmp, record, UR_SRC_IP).ui64[0])) {
            int valid = src[ur_get(ur_tmp, record, UR_SRC_IP).ui64[0]].link & ur_get(ur_tmp, record, UR_LINK_BIT_FIELD);
            if (valid == 0x0) {
                //no valid link found => possible spoofing
#ifdef  DEBUG
                cout << debug_ip_src << " ---> " << debug_ip_dst << endl;
                cout << "Flow goes through " << (long long) ur_get(ur_tmp, record, UR_LINK_BIT_FIELD); 
                cout << " while stored is " << (long long) src[ur_get(ur_tmp, record, UR_SRC_IP).ui64[0]].link  << endl;
                cout << "Possible spoofing found: tested route is asymetric." << endl;
#endif
                return SPOOF_POSITIVE;
            } else {
                return SPOOF_NEGATIVE;
            }
        } else { // no bit record found
            return SPOOF_NEGATIVE;
        }
    }
    return SPOOF_NEGATIVE;
}

// **********   TTL CONSISTENCY CHECK   **********
/*
 *
 * This part of the filter will be implemented when it's possible to 
 * extract TTL data from the flow record.
 * 
 */ 

// Learning process of HCF
// 
// check hop count in incomming traffic
// if hop_count == 0
//     insert new hop_count
// else
//     check timestamp
//     if timestamp_from_record - timestamp_in table > update_time
//         update hop_count item
//     else
//         keep item as is

//int check_TTL_diff_v4 (/* unirec */ *record, v4_sym_sources_t& src)
//int check_TTL_diff_v6 (/* unirec */ *record, v6_sym_sources_t& src)
//{
//     // for IPv4 only
//     v4_numeric = ip_get_v4_as_int(record->src_addr) & 0xFFFFFF00;
//     
//     // the record is present in model and the ttl is different
//     if (src.count(v4_numeric /* record->src_addr.ui64[0] */) 
//         && (src[v4_numeric /* record->src_addr.ui64[0]].ttl - record->ttl != 0)) {
//#ifdef DEBUG
//             cout << "Possible spoofing found: Data flow TTL (" << record->ttl << ")";
//             cout << " doesn't match the stored value (" << src[v4_numeric /*record->src_addr.ui64[0]].ttl << << ")." << endl;
//#endif
//             return SPOOF_POSITIVE;
//         }
//     return SPOOF_NEGATIVE;
//}

// **********   NEW FLOW COUNT FILTER   **********

/**
 * Function for cheking new flows for given source (IPv4).
 * Function gets the record and map of used data flows. Then it tries 
 * to find the source in the map represented by Bloom filters. If the 
 * source is already present nothing happens. If not the source is added 
 * to the filter and its respective counter is increased. If the counter 
 * value exceeds the given threshold then every new flow is flagged as 
 * possibly spoofed.
 *
 * @param ur_tmp Template used for UniRec record.
 * @param record Record that is being analyzed.
 * @param threshold Maximum limit for flows per source.
 * @param filter Set of Bloom filters.
 * @param mm Map with mask prefixes (IPv4)
 * @param prefix_list List of watched networks (prefixes)
 * @return SPOOF_POSITIVE if the flow count exceeds the threshold.
 */
int check_new_flows_v4(ur_template_t *ur_tmp, const void *record, unsigned threshold, flow_filter_t* filter, ipv4_mask_map_t& mm, pref_list_t& prefix_list)
{

#ifdef DEBUG
    char debug_ip_dst[INET6_ADDRSTRLEN];
#endif

    // check the timestamp of filters and record
    long long tf, tr, td;
    tf = ur_get(ur_tmp, record, UR_TIME_FIRST) >> 32;
    tr = filter[bf_active].timestamp >> 32;
    td = tr - tf;

    /*
     * If the time stamp is older than BF_SWAP_TIME constant
     * the filters will be swwapped
     */
    if (td > 0 && td > BF_SWAP_TIME) {
        swap_filters();
        clear_filters(filter[bf_learning]);
        filter[bf_active].timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
        filter[bf_learning].timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
    }

    char ip_key[INET6_ADDRSTRLEN];
    bool is_present = false;

    // test for other specified prefixes
    ipv6_mask_map_t dummy;    
    int search_result;
    ip_addr_t flow_source;
    search_result = ip_binary_search(&(ur_get(ur_tmp, record, UR_DST_IP)), mm, dummy, prefix_list);

    // Source address doesn't fit the watched networks --> ignored
    if (search_result == IP_NOT_FOUND) {
        return SPOOF_NEGATIVE;
    }

    flow_source = ur_get(ur_tmp, record, UR_SRC_IP);
    flow_source.ui32[2] &= mm[24]; // mask with 24-bit prefix for aggregation

    // convert address to string key for bloom filter
    ip_to_str(&(flow_source), ip_key);

    // test if the flow is present in bloom filter
    is_present = filter[bf_active].flows[search_result].sources->contains((unsigned char *) ip_key, INET6_ADDRSTRLEN);

    if (is_present) { // the flow is already in filter --> will be ignored
        return SPOOF_NEGATIVE;
    } else {
        // insert to both filters and increase their respective counts
        filter[bf_active].flows[search_result].sources->insert(ip_key, INET6_ADDRSTRLEN);
        filter[bf_learning].flows[search_result].sources->insert(ip_key, INET6_ADDRSTRLEN);
        filter[bf_active].flows[search_result].count++;
        filter[bf_learning].flows[search_result].count++;

        if (filter[bf_active].flows[search_result].count > threshold) {
        // flow limit exceeded
#ifdef DEBUG
            ip_to_str(&(prefix_list[search_result].ip), debug_ip_dst);
            cout << "Possible spoofing found: ";
            cout << debug_ip_dst << " recieving too many flows (" << filter[bf_active].flows[search_result].count << ")." << endl;
#endif
            return SPOOF_POSITIVE;
        }
    }
    return SPOOF_NEGATIVE;
}

/**
 * Function for cheking new flows for given source (IPv6).
 * Function gets the record and map of used data flows. Then it tries 
 * to find the source in the map represented by Bloom filters. If the 
 * source is already present nothing happens. If not the source is added 
 * to the filter and its respective counter is increased. If the counter 
 * value exceeds the given threshold then every new flow is flagged as 
 * possibly spoofed.
 *
 * @param ur_tmp Template used for UniRec record.
 * @param record Record that is being analyzed.
 * @param threshold Maximum limit for flows per source.
 * @param filter Set of Bloom filters.
 * @param mm Map with mask prefixes (IPv6)
 * @param prefix_list List of watched networks (prefixes)
 * @return SPOOF_POSITIVE if the flow count exceeds the threshold.
 */
int check_new_flows_v6(ur_template_t *ur_tmp, const void *record, unsigned threshold, flow_filter_t* filter, ipv6_mask_map_t& mm, pref_list_t& prefix_list)
{

#ifdef DEBUG
    char debug_ip_src[INET6_ADDRSTRLEN];
    char debug_ip_dst[INET6_ADDRSTRLEN];
#endif

    // check the timestamp of filters and the record
    long long tf, tr, td;
    tf = ur_get(ur_tmp, record, UR_TIME_FIRST) >> 32;
    tr = filter[bf_active].timestamp >> 32;
    td = tr - tf;

    /*
     * If the time stamp is older than BF_SWAP_TIME constant
     * the filters will be swwapped
     */   
    if (td > 0 && td > BF_SWAP_TIME) {
        swap_filters();
        clear_filters(filter[bf_learning]);
        filter[bf_active].timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST);
        filter[bf_learning].timestamp = ur_get(ur_tmp, record, UR_TIME_FIRST);
    }

    char ip_key[INET6_ADDRSTRLEN];
    bool is_present = false;

    // test for specified prefixes
    
    ipv4_mask_map_t dummy;    
    int search_result;
    ip_addr_t flow_source;
    search_result = ip_binary_search(&(ur_get(ur_tmp, record, UR_DST_IP)), dummy, mm, prefix_list);

    // Source address doesn't fit the watched networks --> ignore
    if (search_result == IP_NOT_FOUND) {
        return SPOOF_NEGATIVE;
    }

    flow_source = ur_get(ur_tmp, record, UR_SRC_IP);
    flow_source.ui64[0] &= mm[64][0]; // mask with 64-bit prefix for aggregation
    flow_source.ui64[1] &= 0x0;

    // convert address to string key for bloom filter
    ip_to_str(&(flow_source), ip_key);

    // test if the flow is present in bloom filter
    is_present = filter[bf_active].flows[search_result].sources->contains((unsigned char *) ip_key, INET6_ADDRSTRLEN);

    if (is_present) { // the flow is already in filter --> will be ignored
        return SPOOF_NEGATIVE;
    } else {
        // insert to both filters and increase their respective counts
        filter[bf_active].flows[search_result].sources->insert(ip_key, INET6_ADDRSTRLEN);
        filter[bf_learning].flows[search_result].sources->insert(ip_key, INET6_ADDRSTRLEN);
        filter[bf_active].flows[search_result].count++;
        filter[bf_learning].flows[search_result].count++;

        if (filter[bf_active].flows[search_result].count > threshold) {
        // flow limit exceeded
#ifdef DEBUG
            ip_to_str(&(prefix_list[search_result].ip), debug_ip_dst);
            cout << "Possible spoofing found: ";
            cout << debug_ip_dst << " recieving too many flows (" << filter[bf_active].flows[search_result].count << ")." << endl;
#endif
            return SPOOF_POSITIVE;
        }
    }
    return SPOOF_NEGATIVE;
}

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

//    ur_template_t *templ = ur_create_template("<BASIC_FLOW>,DIR_BIT_FIELD");
    ur_template_t *templ = ur_create_template("<COLLECTOR_FLOW>");

    // lists of bogon prefixes
    pref_list_t bogon_list_v4; 
    pref_list_t bogon_list_v6;
    pref_list_t spec_list_v4;
    pref_list_t spec_list_v6;

    ipv4_mask_map_t v4_masks; // all possible IPv4 masks
    ipv6_mask_map_t v6_masks; // all possible IPv6 masks

    v4_sym_sources_t v4_route_sym; // map of sources for symetric routes (IPv4)
    v6_sym_sources_t v6_route_sym; // map of sources for symetric routes (IPv6)

    flow_filter_t v4_flows[2]; // Bloom filter structures for new flow filter (IPv4)
    flow_filter_t v6_flows[2]; // Bloom filter structures for new flow filter (IPv6)

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
     
    // getopt loop for additional parameters not parsed by TRAP
    int argret = 0;
    unsigned sym_rw_time = 0;
    unsigned nf_threshold = 0;
    bool b_flag = false;
    bool c_flag = false;
    string bog_filename;
    string cnet_filename;

    while ((argret = getopt(argc, argv, "b:c:s:t:")) != -1) {
        switch (argret) {
            case 'b': // file with bogon prefixes (mandatory)
                bog_filename = string(optarg);
                b_flag = true;
                break;
            
            case 'c': // file with other prefixes (mandatory)
                c_flag = true;
                cnet_filename = string(optarg);
                break;

            case 's': // symetric filter update time (optional)
                sym_rw_time = atoi(optarg);
                break;

            case 't': // maximum of new flows per source allowed (optional)
                nf_threshold = atoi(optarg);
                break;
            
            case '?':
                if (optopt == 'b' || optopt == 'c' || optopt == 's' || optopt == 't') {
                    cerr << "ERROR: Option -" << (char) optopt << " requires an argumet." << endl;
                    return EXIT_FAILURE;
                } else {
                    cerr << "ERROR: Unknown parameter -" << (char) optopt << " given." << endl;
                    return EXIT_FAILURE;
                }

                break;
        }
    }

    // check whether files with prefixes were specified
    if (! b_flag) {
        cerr << "ERROR: Bogon file not specified. Unable to continue." << endl;
        return EXIT_FAILURE;
    }
#ifdef DEBUG
    if (!c_flag) {
        cout << "No other file with prefixes has been specified." << endl;
    }
#endif

#ifdef DEBUG
    if (sym_rw_time == 0) {
        cout << "Symetric filter update time not specified. Default time (" << SYM_RW_DEFAULT << " seconds) will be used instead." << endl;    
    }
    if (nf_threshold == 0) {
        cout << "New flow threshold not specified. Default (" << NEW_FLOW_DEFAULT << ") will be used instead." << endl;
    }
#endif

    // set the default rw_time
    if (sym_rw_time == 0) {
        sym_rw_time = SYM_RW_DEFAULT;
    }
    if (nf_threshold == 0) {
        nf_threshold = NEW_FLOW_DEFAULT;
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

    // fill the netmask masks
    create_v4_mask_map(v4_masks);    
    create_v6_mask_map(v6_masks);

#ifdef DEBUG
    unsigned v4 = 0;
    unsigned v6 = 0;
    unsigned spoof_count = 0;
    unsigned bogons = 0;
    unsigned syms = 0;
    unsigned nflows = 0;
#endif

    // we don't have list of bogon prefixes loaded (usually first run)
    retval = load_pref(bogon_list_v4, bogon_list_v6, bog_filename.c_str());

    if (c_flag)
        retval = load_pref(spec_list_v4, spec_list_v6, cnet_filename.c_str());

    if (retval == PREFIX_FILE_ERROR) {
        return retval;
    }

    // create Bloom filters
    create_nflow_filters(spec_list_v4.size(), v4_flows);
    create_nflow_filters(spec_list_v6.size(), v6_flows);

#ifdef DEBUG
    cout << "Bloom filters created. " << endl;
#endif

    const void *data;
    uint16_t data_size;
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

#ifdef DEBUG
        if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
            ++v4;
        } else {
            ++v6;
        }
#endif
        // go through all filters
        // initialize the timestamp of bloom filters
        if (v4_flows[bf_active].timestamp == 0x0 
            && v4_flows[bf_learning].timestamp == 0x0) {
            v4_flows[bf_active].timestamp = v4_flows[bf_learning].timestamp = ur_get(templ, data, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
        }
        if (v6_flows[bf_active].timestamp == 0x0 
            && v6_flows[bf_learning].timestamp == 0x0) {
            v6_flows[bf_active].timestamp = v6_flows[bf_learning].timestamp = ur_get(templ, data, UR_TIME_FIRST) & 0xFFFFFFFF00000000ULL;
        }
        

        // ***** 1. bogon and specific prefix filter *****
        if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
            retval = v4_bogon_filter(templ, data, bogon_list_v4, v4_masks);
            if (retval == SPOOF_NEGATIVE && ur_get(templ, data, UR_DIR_BIT_FIELD) == 0x01 && c_flag) {
                retval = v4_bogon_filter(templ, data, spec_list_v4, v4_masks);
            }
        } else {
            retval = v6_bogon_filter(templ, data, bogon_list_v6, v6_masks);
            if (retval == SPOOF_NEGATIVE && ur_get(templ, data, UR_DIR_BIT_FIELD) == 0x01 && c_flag) {
                retval = v6_bogon_filter(templ, data, spec_list_v6, v6_masks);
            }
        }
       
        // we caught a spoofed address by bogon prefix
        if (retval == SPOOF_POSITIVE) {
#ifdef DEBUG
            ++spoof_count;
            ++bogons;
#endif
            //for future use
            trap_send_data(1, data, ur_rec_static_size(templ), TRAP_HALFWAIT);
            retval = ALL_OK; // reset return value
            continue;
        }

        // ***** 2. symetric routing filter *****
        if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
            retval = check_symetry_v4(templ, data, v4_route_sym, sym_rw_time);
        } else {
            retval = check_symetry_v6(templ, data, v6_route_sym, sym_rw_time);
        }
        
        // we caught a spoofed address by not keeping to symteric routing
        if (retval == SPOOF_POSITIVE) {
#ifdef DEBUG
            ++spoof_count;
            ++syms;
#endif
            //for future use
            trap_send_data(1, data, ur_rec_static_size(templ), TRAP_WAIT);
            retval = ALL_OK;
            continue;
        }
        
        // 3. asymetric routing filter (will be implemented later)

        // ***** 4. new flow count check *****

        if (ip_is4(&(ur_get(templ, data, UR_SRC_IP)))) {
            retval = check_new_flows_v4(templ, data, nf_threshold, v4_flows, v4_masks, spec_list_v4); 
        } else {
            retval = check_new_flows_v6(templ, data, nf_threshold, v6_flows, v6_masks, spec_list_v6);
        }
    
        if (retval == SPOOF_POSITIVE) {
#ifdef DEBUG
            ++spoof_count;
            ++nflows;
#endif
            //for future use
            trap_send_data(1, data, ur_rec_static_size(templ), TRAP_WAIT);
            retval = ALL_OK;
            continue;
        }
    }

#ifdef DEBUG
    cout << "IPv4: " << v4 << endl;
    cout << "IPv6: " << v6 << endl;
    cout << "No. of possibly spoofed addresses: " << spoof_count << endl;
    cout << "Caught by bogon filter: " << bogons << endl;
    cout << "Caught by symetric routing filter: " << syms << endl;
    cout << "Caught by using too many new flows: " << nflows << endl;
#endif

    trap_send_data(0, data, 1, TRAP_WAIT);

    // clean up before termination
    destroy_filters(v4_flows);
    destroy_filters(v6_flows);
    ur_free_template(templ);
    trap_finalize();

    return retval;
}
