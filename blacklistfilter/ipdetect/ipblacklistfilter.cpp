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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <nemea-common/nemea-common.h>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include "ipblacklistfilter.h"
#include "patternstrings.h"
#include "fields.h"

using namespace std;

UR_FIELDS(
//BASIC_FLOW
        ipaddr SRC_IP,      //Source address of a flow
        ipaddr DST_IP,      //Destination address of a flow
        uint16 SRC_PORT,    //Source transport-layer port
        uint16 DST_PORT,    //Destination transport-layer port
        uint8 PROTOCOL,     //L4 protocol (TCP, UDP, ICMP, etc.)
        uint32 PACKETS,     //Number of packets in a flow or in an interval
        uint64 BYTES,       //Number of bytes in a flow or in an interval
        time TIME_FIRST,    //Timestamp of the first packet of a flow
        time TIME_LAST,     //Timestamp of the last packet of a flow
        uint8 TCP_FLAGS,    //TCP flags of a flow (logical OR over TCP flags field of all packets)
//COLLECTOR_FLOW
        uint64 LINK_BIT_FIELD,  //Bit field where each bit marks whether a flow was captured on corresponding link
        uint8 DIR_BIT_FIELD,    //Bit field used for detemining incomming/outgoing flow
        uint8 TOS,              //IP type of service
        uint8 TTL,              //IP time to live
//Blacklist items
        uint64 SRC_BLACKLIST,   //Bit field of blacklists IDs which contains the source address of the flow
        uint64 DST_BLACKLIST,   //Bit field of blacklists IDs which contains the destination address of the flow
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("ipblacklistfilter", "Module receives the UniRec record and checks if the source address " \
    "or destination address is present in any blacklist that are available. " \
    "If any of the addresses is blacklisted the record is changed by adding " \
    "a identification number of the list which blacklisted the address for both IP addresses and " \
    "a number specifying intensity of the communication between those addresses. Unirec records " \
    "are aggregated by source,destination address and protocol for a given time. After this time " \
    "aggregated UniRec is sent by output interface. " \
    "This module uses configurator tool. To specify file with blacklist IP addresses or public " \
    "blacklists, use XML configuration file for IPBlacklistFilter (userConfigurationFile.xml). " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bld_userConfigurationFile.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "", "Specify user configuration file for IPBlacklistFilter. [Default: " SYSCONFDIR "/ipblacklistfilter/userConfigurationFile.xml]", required_argument, "string") \
  PARAM('U', "", "Specify user configuration file for blacklist downloader. [Default: " SYSCONFDIR "/ipblacklistfilter/bld_userConfigurationFile.xml]", required_argument, "string") \
  PARAM('D', "", "Switch to dynamic mode. Use blacklists specified in configuration file.", no_argument, "none") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none") \
  PARAM('A', "", "Specify active timeout in seconds. [Default: 300]", required_argument, "uint32") \
  PARAM('I', "", "Specify inactive timeout in seconds. [Default: 30]", required_argument, "uint32") \
  PARAM('s', "", "Size of aggregation hash table. [Default: 500000]", required_argument, "uint32")


// Global variable for signaling the program to stop execution
static int stop = 0;

// Global variable for signaling the program to update blacklists
static int update = 0;

// Reconfiguration flag, set if signal SIGUSR2 received
static int RECONF_FLAG = 0;

/**
 * \brief Function for handling signals SIGTERM and SIGINT.
 * \param signal Number of received signal.
 */
void signal_handler(int signal)
{
    switch (signal) {
        case SIGTERM:
        case SIGINT:
            if (stop) {
                printf("Another terminating signal caught!\nTerminating without clean up!!!.\n");
                exit(EXIT_FAILURE);
            }
            stop = 1;
            printf("Terminating signal caught...\nPlease wait for clean up.\n");
            break;
        case SIGUSR1:
            update = 1;
            break;
        case SIGUSR2:
            RECONF_FLAG = 1;
            break;
        default:
            break;
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
int reload_blacklists(black_list_t &v4_list, black_list_t &v6_list, string &file)
{
    ifstream input;
    string line, ip, bl_flag_str;
    size_t str_pos;
    uint64_t bl_flag;
    int line_num = 0;
    ip_blist_t bl_entry; // black list entry associated with ip address

    // Open file with blacklists
    input.open(file.c_str(), ifstream::in);
    if (!input.is_open()) {
        cerr << "Cannot open file with updates!" << endl;
        return BLIST_FILE_ERROR;
    }

    while (!input.eof()) {
        getline(input, line);
        line_num++;

        // Trim all white spaces (if any)
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

        // Transform all letters to lowercase (if any)
        transform(line.begin(), line.end(), line.begin(), ::tolower);

        // Skip empty lines
        if (!line.length()) {
            continue;
        }

        // Find IP-blacklist index separator
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

            bl_entry.pref_length = (u_int8_t) strtol(ip.c_str(), NULL, 0);
        }

        // Determine blacklist
        bl_entry.in_blacklist = bl_flag;

        // Add entry to vector
        if (ip_is4(&bl_entry.ip))
            v4_list.push_back(bl_entry);
        else
            v6_list.push_back(bl_entry);
    }

    input.close();

    return ALL_OK;
}

/**
 * \brief Function for binary searching in prefix lists. It uses binary search
 * algorithm to determine whether the given ip address fits any of the prefix in the list.
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
    ip_addr_t ip = ur_get(ur_tmp, record, F_SRC_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, F_SRC_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
        ur_set(ur_det, detected, F_SRC_BLACKLIST, net_bl[search_result].in_blacklist);
        marked = true;
    } else {
        ur_set(ur_det, detected, F_SRC_BLACKLIST, 0x0);
    }

    // Check destination IP
    ip = ur_get(ur_tmp, record, F_DST_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, F_DST_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
        ur_set(ur_det, detected, F_DST_BLACKLIST, net_bl[search_result].in_blacklist);
        marked = true;
    } else {
        ur_set(ur_det, detected, F_DST_BLACKLIST, 0x0);
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
    ip_addr_t ip = ur_get(ur_tmp, record, F_SRC_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, F_SRC_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
        ur_set(ur_det, detected, F_SRC_BLACKLIST, net_bl[search_result].in_blacklist);
        marked = true;
    } else {
        ur_set(ur_det, detected, F_SRC_BLACKLIST, 0x0);
    }

    // Check destination IP
    ip = ur_get(ur_tmp, record, F_DST_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_tmp, record, F_DST_IP), v4mm, v6mm, net_bl)) != IP_NOT_FOUND) {
        ur_set(ur_det, detected, F_DST_BLACKLIST, net_bl[search_result].in_blacklist);
        marked = true;
    } else {
        ur_set(ur_det, detected, F_DST_BLACKLIST, 0x0);
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
 * the vectors explicitly.
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
 * operations both for prefixes and addresses.
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
 * \brief Setup arguments structure for Blacklist Downloader.
 * \param args Pointer to arguments structure.
 * \param down_config Configuration structure parsed from XML file.
 */
void setup_downloader(bl_down_args_t *args, downloader_config_struct_t *down_config)
{
    // Convert blacklist names to IDs and merge them together (binary OR)
    args->sites = bld_translate_names_to_cumulative_id(
            down_config->blacklist_arr,
            BL_NAME_MAX_LENGTH);

    // Set other arguments for downloader
    args->file       = down_config->file;
    args->delay      = down_config->delay;
    args->update_mode     = 1;//down_config.update_mode;
    args->line_max_length = down_config->line_max_len;
    args->el_max_length   = down_config->element_max_len;
    args->el_max_count    = down_config->element_max_cnt;
}




bool initialize_downloader(const char *patternFile, const char *userFile, downloader_config_struct_t *down_config, int patternType)
{
    bl_down_args_t bl_args;

    // Load configuration for BLD
    if (!bld_load_xml_configs(patternFile, userFile, patternType)) {
        cerr << "Error: Could not load XML configuration for blacklist downloader." << endl;
        return false;
    }
    // Start Blacklist Downloader
    setup_downloader(&bl_args, down_config);
    if (bl_args.sites == 0) {
        fprintf(stderr, "Error: No blacklists were specified!\n");
        return false;
    }

    int ret = bl_down_init(&bl_args);
    if (ret < 0) {
        fprintf(stderr, "Error: Could not initialize downloader!\n");
        return false;
    } else {
        // Wait for initial update
        while (!update) {
            sleep(1);
            if (stop) {
                return false;
            }
            check_update();
        }
        update = 0;
    }

    return true;
}


/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{
    int retval = 0;
    int send_terminating_unirec = 1;

    // Set default files names
    char *userFile = (char*) SYSCONFDIR "/ipblacklistfilter/userConfigFile.xml";
    char *bld_userFile = (char*) SYSCONFDIR "/ipblacklistfilter/bld_userConfigFile.xml";

    // For use with prefixes
    black_list_t v4_list;
    black_list_t v6_list;

    // Mask array for prefixes
    ipv4_mask_map_t v4_masks;
    ipv6_mask_map_t v6_masks;
    create_v4_mask_map(v4_masks);
    create_v6_mask_map(v6_masks);

    // TRAP initialization
    //TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    trap_ifc_spec_t ifc_spec;
    int ret = trap_parse_params(&argc, argv, &ifc_spec);
    if (ret != TRAP_E_OK) {
        if (ret == TRAP_E_HELP) {
            trap_print_help(module_info);
            return 0;
        }
        trap_free_ifc_spec(ifc_spec);
        fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
        return 1;
    }
    ret = trap_init(module_info, ifc_spec);
    if (ret != TRAP_E_OK) {
        trap_free_ifc_spec(ifc_spec);
        fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
        return 1;
    }
    trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
    trap_free_ifc_spec(ifc_spec);

    // UniRec templates for recieving data and reporting blacklisted IPs
    char *errstr = NULL;
    ur_template_t *templ = ur_create_input_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL", &errstr);

    if (templ == NULL) {
        cerr << "Error: Invalid UniRec specifier." << endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        trap_finalize();
        return EXIT_FAILURE;
    }

    ur_template_t *tmpl_det = ur_create_output_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL,SRC_BLACKLIST,DST_BLACKLIST", &errstr);
    if (tmpl_det == NULL) {
        cerr << "Error: Invalid UniRec specifier." << endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        trap_finalize();
        ur_free_template(templ);
        return EXIT_FAILURE;
    }

    // Create detection record
    void *detection = NULL;
    detection = ur_create_record(tmpl_det, 0);
    if (detection == NULL) {
        cerr << "ERROR: No memory available for detection report. Unable to continue." << endl;
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        return EXIT_FAILURE;
    }

    // Turn off buffer on output interface
    //trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0x0);

    // Set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);
    signal(SIGUSR2, signal_handler);

    int opt;
    string file, bl_str;
    int bl_mode = BL_STATIC_MODE; // default mode

    // ********** Parse arguments **********
    while ((opt = getopt(argc, argv, "nDu:U:")) != -1) {
        switch (opt) {
            case 'u': // user configuration file for IPBlacklistFilter
                userFile = optarg;
                break;
            case 'U': // user configuration file for blacklist downlooader
                bld_userFile = optarg;
                break;
            case 'D': // Dynamic mode
                bl_mode = BL_DYNAMIC_MODE;
                break;
            case 'n': // Do not send terminating Unirec
                send_terminating_unirec = 0;
                break;
            case '?': if (optopt == 'I' || optopt == 'A' || optopt == 's') {
                    fprintf (stderr, "ERROR: Option -%c requires an argumet.\n", optopt);
                } else {
                    fprintf (stderr, "ERROR: Unknown option -%c.\n", optopt);
                }
                ur_free_template(templ);
                ur_free_template(tmpl_det);
                trap_finalize();
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                return EXIT_FAILURE;
        }
    }



    // Allocate memory for configuration
    downloader_config_struct_t *down_config = (downloader_config_struct_t *) malloc(sizeof(downloader_config_struct_t));
    if (down_config == NULL) {
        cerr << "Error: Could not allocate memory for configuration structure." << endl;
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }

    // Load configuration
    if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, down_config, CONF_PATTERN_STRING)) {
        cerr << "Error: Could not parse XML configuration." << endl;
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }


    // ***** Initialize Blacklist Downloader *****
    if (bl_mode == BL_DYNAMIC_MODE) {
        // Load configuration for BLD
        if (!initialize_downloader(BLD_CONFIG_PATTERN_STRING, bld_userFile, down_config, CONF_PATTERN_STRING)) {
            ur_free_template(templ);
            ur_free_template(tmpl_det);
            trap_finalize();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return EXIT_FAILURE;
        }
    }

    // Set file string
    file = down_config->file;

    // Load ip addresses from sources
    retval = reload_blacklists(v4_list, v6_list, file);

    // If update from file could not be processed, return error
    if (retval == BLIST_FILE_ERROR) {
        fprintf(stderr, "Error: Unable to read file '%s'\n", file.c_str());
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        trap_finalize();
        if (bl_mode == BL_DYNAMIC_MODE) {
            bld_finalize();
        }
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }


    // ***** Main processing loop *****
    while (!stop) {
        const void *data;
        uint16_t data_size;
        // Retrieve data from sender
        retval = TRAP_RECEIVE(0, data, data_size, templ);
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

        // Try to match the IP addresses to blacklist
        if (ip_is4(&(ur_get(templ, data, F_SRC_IP)))) {
            // Check blacklisted IPs
            retval = v4_blacklist_check(templ, tmpl_det, data, detection, v4_masks, v6_masks, v4_list);
        } else {
            retval = v6_blacklist_check(templ, tmpl_det, data, detection, v4_masks, v6_masks, v6_list);
        }

        // If IP address was found on blacklist
        if (retval == BLACKLISTED) {
            ur_copy_fields(tmpl_det, detection, templ, data);
            trap_send(0, detection, ur_rec_fixlen_size(tmpl_det));
        }

        // Critical section starts here
        bld_lock_sync();
        if (bl_mode == BL_DYNAMIC_MODE && BLD_SYNC_FLAG) {
            // Update blacklists
            string upd_path = file;
            retval = reload_blacklists(v4_list, v6_list, upd_path);
            if (retval == BLIST_FILE_ERROR) {
                cerr << "ERROR: Unable to load update files. Will use the old tables instead." << endl;
                update = 0;
                continue;
            }

            BLD_SYNC_FLAG = 0;
        }

        // Reconfigure module if needed
        if (RECONF_FLAG) {
            // Terminate blacklist downloader thread if in dynamic mode
            if (bl_mode == BL_DYNAMIC_MODE) {
                // Need to unlock to avoid possible deadlock
                bld_unlock_sync();
                bld_finalize();
                configuratorFreeUAMBS();
                update = 0;
                // No need to lock, blacklist downloader is no more
            }

            v4_list.clear();
            v6_list.clear();

            // LOAD NEW CONFIGURATION FOR BOTH FILTER AND DOWNLOADER
            // Load configuration
            if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, down_config, CONF_PATTERN_STRING)) {
                cerr << "Error: Could not parse XML configuration." << endl;
                return EXIT_FAILURE;
            }

            // START DOWNLOADER AGAIN
            if (bl_mode == BL_DYNAMIC_MODE) {
                if (!initialize_downloader(BLD_CONFIG_PATTERN_STRING, bld_userFile, down_config, CONF_PATTERN_STRING)) {
                    ur_free_template(templ);
                    ur_free_template(tmpl_det);
                    trap_finalize();
                    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                    return EXIT_FAILURE;
                }
            }

            // Load ip addresses from sources
            file = down_config->file;

            retval = reload_blacklists(v4_list, v6_list, file);

            // If update from file could not be processed, return error
            if (retval == BLIST_FILE_ERROR) {
                fprintf(stderr, "Error: Unable to read file '%s'\n", file.c_str());
                ur_free_template(templ);
                ur_free_template(tmpl_det);
                trap_finalize();
                if (bl_mode == BL_DYNAMIC_MODE) {
                    bld_finalize();
                }
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                return EXIT_FAILURE;
            }

            RECONF_FLAG = 0;
        }

        bld_unlock_sync();
        // Critical section ends here
    }
    // Module is stopping, set appropriate flag
    stop = 1;

    // Terminate blacklist downloader thread if in dynamic mode
    if (bl_mode == BL_DYNAMIC_MODE) {
        bld_finalize();
        configuratorFreeUAMBS();
    }

    // If set, send terminating message to modules on output
    if (send_terminating_unirec) {
        trap_send(0, "TERMINATE", 1);
    }

    // Clean up before termination
    if (detection != NULL) {
        ur_free_record(detection);
        detection = NULL;
    }
    ur_free_template(templ);
    ur_free_template(tmpl_det);

    TRAP_DEFAULT_FINALIZATION();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    return EXIT_SUCCESS;
}
