/**
 * \file ipblacklistfilter.cpp
 * \brief Module for detecting blacklisted IP addresses.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Filip Suster, sustefil@fit.cvut.cz
 * \date 2013
 * \date 2014
 * \date 2015
 * \date 2018
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
#include <pthread.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif

#include <nemea-common/nemea-common.h>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include <poll.h>
#include "ipblacklistfilter.h"
#include "patternstrings.h"
#include "fields.h"
#include "../blacklist_watcher/blacklist_watcher.h"

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
        uint8 DIR_BIT_FIELD,    //Bit field used for determining incoming/outgoing flow
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
    "an index of the blacklist(s) which blacklisted the address" \
    "This module uses configurator tool. To specify file with blacklists (prepared by blacklist_downloader)" \
    "use XML configuration file for IPBlacklistFilter (userConfigurationFile.xml). " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bld_userConfigurationFile.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "", "Specify user configuration file for IPBlacklistFilter. [Default: " SYSCONFDIR "/ipblacklistfilter/userConfigurationFile.xml]", required_argument, "string") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none")

using namespace std;

// Global variable for signaling the program to stop execution
static int stop = 0;

// Global variable for signaling the program to update blacklists
int BL_RELOAD_FLAG = 0;

// Reconfiguration flag, set if signal SIGUSR1 received
int RECONF_FLAG = 0;

static bool WATCH_BLACKLISTS_FLAG;

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
            RECONF_FLAG = 1;
            break;
        default:
            break;
    }
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
 * \brief Function for loading blacklists. It parses file with blacklisted IP
 * addresses (created and preprocessed by blacklist downloader).
 * Function also checks validity of line on which the IP address was found. Invalid of bad formated lines
 * are ignored.
 * \param v4_list IPv4 vector to be filled
 * \param v6_list IPv6 vector to be filled
 * \param file Blacklist file.
 * \return ALL_OK if everything goes well, BLIST_FILE_ERROR if file cannot be accessed.
 */
int reload_blacklists(black_list_t &v4_list, black_list_t &v6_list, std::string &file)
{
    std::ifstream input;
    std::string line, ip, bl_index_str;
    uint64_t bl_index;
    int line_num = 0;
    ip_blist_t bl_entry; // black list entry associated with ip address

    black_list_t v4_list_new;
    black_list_t v6_list_new;

    input.open(file.c_str(), std::ifstream::in);
    if (!input.is_open()) {
        std::cerr << "Cannot open file with updates. Is the downloader running?" << std::endl;
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
        size_t sep = line.find_first_of(',');

        if (sep == std::string::npos) {
            // Blacklist index delimeter not found (bad format?), skip it
            std::cerr << "WARNING: File '" << file << "' has bad formated line number '" << line_num << "'" << std::endl;
            continue;
        }

        // Parse blacklist ID
        bl_index = strtoull((line.substr(sep + 1, std::string::npos)).c_str(), NULL, 10);

        // Parse IP
        ip = line.substr(0, sep);

        // Are we loading prefix?
        sep = ip.find_first_of('/');

        if (sep == std::string::npos) {
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
            if (!ip_from_str((ip.substr(0, sep)).c_str(), &bl_entry.ip)) {
                continue;
            }

            ip.erase(0, sep + 1);

            bl_entry.pref_length = (u_int8_t) strtol(ip.c_str(), NULL, 0);
        }

        // Determine blacklist
        bl_entry.in_blacklist = bl_index;

        // Add entry to vector
        if (ip_is4(&bl_entry.ip))
            v4_list_new.push_back(bl_entry);
        else
            v6_list_new.push_back(bl_entry);
    }

    input.close();

    v4_list = move(v4_list_new);
    v6_list = move(v6_list_new);

    DBG((stderr, "Blacklists reloaded. Entries: IP4: %lu, IP6: %lu\n", v4_list.size(), v6_list.size()));

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
    int end, begin, mid;
    int mask_result = 1;
    ip_addr_t masked;

    begin = 0;
    end = black_list.size() - 1;

    // Binary search
    // Mask the searched IP with the mask of the mid IP, if it matches the network IP -> found
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
 * with the respective blacklist(s) number.
 * \param ur_tmp Template of input UniRec record.
 * \param ur_det Template of detection UniRec record.
 * \param record Record being analyzed.
 * \param detected Detection record used if any address matches the blacklist.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param net_bl List of prefixes to be compared with.
 * \return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int v4_blacklist_check(ur_template_t* ur_in,
                       ur_template_t* ur_det,
                       const void *record,
                       void *detected,
                       ipv4_mask_map_t& v4mm,
                       ipv6_mask_map_t& v6mm,
                       black_list_t& bl)
{
    bool blacklisted = false;

    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;

    // Check source IP
    ip_addr_t ip = ur_get(ur_in, record, F_SRC_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_in, record, F_SRC_IP), v4mm, v6mm, bl)) != IP_NOT_FOUND) {
        ur_set(ur_det, detected, F_SRC_BLACKLIST, bl[search_result].in_blacklist);
        blacklisted = true;
    } else {
        ur_set(ur_det, detected, F_SRC_BLACKLIST, 0x0);
    }

    // Check destination IP
    ip = ur_get(ur_in, record, F_DST_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_in, record, F_DST_IP), v4mm, v6mm, bl)) != IP_NOT_FOUND) {
        ur_set(ur_det, detected, F_DST_BLACKLIST, bl[search_result].in_blacklist);
        blacklisted = true;
    } else {
        ur_set(ur_det, detected, F_DST_BLACKLIST, 0x0);
    }

    if (blacklisted) {
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

    if (marked) {
        // IP was found
        return BLACKLISTED;
    }
    return ADDR_CLEAR;
}



int main (int argc, char **argv)
{
    int retval = 0;
    int send_terminating_unirec = 1;

    // Set default files names
    char *userFile = (char*) SYSCONFDIR "/ipblacklistfilter/userConfigFile.xml";

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
        std::cerr << "Error: Invalid UniRec specifier." << std::endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        trap_finalize();
        return EXIT_FAILURE;
    }

    ur_template_t *tmpl_det = ur_create_output_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL,SRC_BLACKLIST,DST_BLACKLIST", &errstr);
    if (tmpl_det == NULL) {
        std::cerr << "Error: Invalid UniRec specifier." << std::endl;
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
        std::cerr << "ERROR: No memory available for detection report. Unable to continue." << std::endl;
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        return EXIT_FAILURE;
    }


    // Turn off buffer on output interface
    //trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0x0);

    // Set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGUSR1, signal_handler);

    int opt;
    std::string bl_file, bl_str;

    // ********** Parse arguments **********
    while ((opt = getopt(argc, argv, "nu:")) != -1) {
        switch (opt) {
            case 'u': // user configuration file for IPBlacklistFilter
                userFile = optarg;
                break;
            case 'n': // Do not send terminating Unirec
                send_terminating_unirec = 0;
                break;
            case '?':
                ur_free_template(templ);
                ur_free_template(tmpl_det);
                trap_finalize();
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                return EXIT_FAILURE;
        }
    }

    config_t config;

    if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, &config, CONF_PATTERN_STRING)) {
        std::cerr << "Error: Could not parse XML configuration." << std::endl;
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }

    if (strcmp(config.watch_blacklists, "true") == 0) {
        WATCH_BLACKLISTS_FLAG = true;
    } else {
        WATCH_BLACKLISTS_FLAG = false;
    }

    bl_file = config.blacklist_file;

    // Load ip addresses from sources
    retval = reload_blacklists(v4_list, v6_list, bl_file);

    // If update from bl_file could not be processed, return error
    if (retval == BLIST_FILE_ERROR) {
        fprintf(stderr, "Error: Unable to read bl_file '%s'\n", bl_file.c_str());
        ur_free_template(templ);
        ur_free_template(tmpl_det);
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }

    pthread_t watcher_thread;
    if (WATCH_BLACKLISTS_FLAG) {
        pthread_create(&watcher_thread, NULL, watch_blacklist_files, &bl_file);
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
                std::cerr << "ERROR: Corrupted data or wrong data template was specified. ";
                std::cerr << "Size computed from record: " << ur_rec_size(templ, data) << " ";
                std::cerr << "Size returned from Trap: " << data_size << std::endl;
                break;
            }
        }

        // Try to match the IP addresses to blacklist
        if (ip_is4(&(ur_get(templ, data, F_SRC_IP)))) {
            // Check blacklisted IPs
            if (! v4_list.empty())
                retval = v4_blacklist_check(templ, tmpl_det, data, detection, v4_masks, v6_masks, v4_list);
        } else {
            if (! v6_list.empty()) {
                retval = v6_blacklist_check(templ, tmpl_det, data, detection, v4_masks, v6_masks, v6_list);
            }
        }

        // If IP address was found on blacklist
        if (retval == BLACKLISTED) {
            ur_copy_fields(tmpl_det, detection, templ, data);
            trap_send(0, detection, ur_rec_fixlen_size(tmpl_det));
            DBG((stderr, "IP detected on blacklist\n", ))
        }

        if (BL_RELOAD_FLAG) {
            DBG((stderr, "Reloading blacklists\n"));
            retval = reload_blacklists(v4_list, v6_list, bl_file);
            if (retval == BLIST_FILE_ERROR) {
                std::cerr << "ERROR: Unable to load update blacklist. Will use the old one instead." << std::endl;
                continue;
            }

            // this lazy locking is fine, we don't need to reload the blacklists immediately
            // and locking the mutex in every iteration is ineffective
            pthread_mutex_lock(&BLD_SYNC_MUTEX);
            BL_RELOAD_FLAG = 0;
            pthread_mutex_unlock(&BLD_SYNC_MUTEX);
        }

        // TODO: Do we need any reconfiguration at all?
        if (RECONF_FLAG) {
            DBG((stderr, "Reconfiguration..\n"))

            v4_list.clear();
            v6_list.clear();

            if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, &config, CONF_PATTERN_STRING)) {
                std::cerr << "Error: Could not parse XML configuration." << std::endl;
                ur_free_template(templ);
                ur_free_template(tmpl_det);
                trap_finalize();
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                return EXIT_FAILURE;
            }

            if (strcmp(config.watch_blacklists, "true") == 0) {
                WATCH_BLACKLISTS_FLAG = true;
            } else {
                WATCH_BLACKLISTS_FLAG = false;
            }

            bl_file = config.blacklist_file;

            // Load ip addresses from sources
            retval = reload_blacklists(v4_list, v6_list, bl_file);

            // If update from file could not be processed, return error
            if (retval == BLIST_FILE_ERROR) {
                fprintf(stderr, "Error: Unable to read bl_file '%s'\n", bl_file.c_str());
                ur_free_template(templ);
                ur_free_template(tmpl_det);
                trap_finalize();
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                return EXIT_FAILURE;
            }

            RECONF_FLAG = 0;
        }

    }

    // Module is stopping, set appropriate flag
    stop = 1;

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

    if (WATCH_BLACKLISTS_FLAG)
        pthread_cancel(watcher_thread);

    return EXIT_SUCCESS;
}
