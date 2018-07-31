/**
 * \file ipblacklistfilter.cpp
 * \brief Module for detecting blacklisted IP addresses.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Filip Suster, sustefil@fit.cvut.cz
 * \date 2013-2018
 */

/*
 * Copyright (C) 2013, 2014, 2015, 2018 CESNET
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
#include <algorithm>
#include <iostream>
#include <fstream>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include <ipdetect/patternstrings.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif

#include <nemea-common/nemea-common.h>
#include "ipblacklistfilter.h"
#include "fields.h"
#include "blacklist_watcher.h"

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
    "This module uses configurator tool. To specify file with blacklists (prepared by blacklist downloader)" \
    "use XML configuration file for IPBlacklistFilter (ipdetect_config.xml). " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bl_downloader_config.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "", "Specify user configuration file for IPBlacklistFilter. [Default: " SYSCONFDIR "/blacklistfilter/ipdetect_config.xml]", required_argument, "string") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none")

using namespace std;

// Global variable for signaling the program to stop execution
int stop = 0;

// Global variable for signaling the program to update blacklists
int BL_RELOAD_FLAG = 0;

// Reconfiguration flag, set if signal SIGUSR1 received
int RECONF_FLAG = 0;

// Blacklist watcher flag. If set, the inotify based thread for watching blacklists is created
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
                cerr << "Another terminating signal caught!\nTerminating without clean up!" << endl;
                exit(EXIT_FAILURE);
            }
            stop = 1;
            cerr << "Terminating signal caught...\nPlease wait for clean up." << endl;
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
 * \param in Input byte.
 * \return Byte with reversed bits.
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
void create_v4_mask_map(ipv4_mask_map_t &m)
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
void create_v6_mask_map(ipv6_mask_map_t &m)
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
 * addresses. The file shall be preprocessed by blacklist downloader (no redundant whitespaces, forcing lowercase etc.)
 * Function also checks validity of line on which the IP address was found. Invalid of bad formatted lines
 * are ignored.
 * \param v4_list IPv4 vector to be filled
 * \param v6_list IPv6 vector to be filled
 * \param file Blacklist file.
 * \return ALL_OK if everything goes well, BLIST_FILE_ERROR if file cannot be accessed.
 */
int reload_blacklists(black_list_t &v4_list, black_list_t &v6_list, string &file)
{
    ifstream input;
    string line, ip, bl_index_str;
    uint64_t bl_index;      // blacklist ID is a 64bit map
    int line_num = 0;
    ip_bl_entry_t bl_entry; // black list entry associated with ip address

    black_list_t v4_list_new;
    black_list_t v6_list_new;

    input.open(file.c_str(), ifstream::in);
    if (!input.is_open()) {
        cerr << "ERROR: Cannot open file with updates. Is the downloader running?" << endl;
        return BLIST_FILE_ERROR;
    }

    while (!input.eof()) {
        getline(input, line);
        line_num++;

        if (input.bad()) {
            cerr << "ERROR: Failed reading blacklist file (getline badbit)" << endl;
            input.close();
            return BLIST_FILE_ERROR;
        }

        // Find IP-blacklist index separator
        size_t sep = line.find_first_of(',');

        if (sep == string::npos) {
            if (line.empty()) {
                // probably just newline at the end of file
                continue;
            }
            // Blacklist index delimeter not found (bad format?), skip it
            cerr << "WARNING: File '" << file << "' has bad formatted line number '" << line_num << "'" << endl;
            continue;
        }

        // Parse blacklist ID
        bl_index = strtoull((line.substr(sep + 1, string::npos)).c_str(), NULL, 10);

        // Parse IP
        ip = line.substr(0, sep);

        // Are we loading prefix?
        sep = ip.find_first_of('/');

        if (sep == string::npos) {
            // IP only
            if (!ip_from_str(ip.c_str(), &bl_entry.ip)) {
                cerr << "WARNING: Invalid IP address in file '" << file << "' on line '" << line_num << "'" << endl;
                continue;
            }
            if (ip_is4(&bl_entry.ip)) {
                bl_entry.prefix_len = PREFIX_V4_DEFAULT;
            } else {
                bl_entry.prefix_len = PREFIX_V6_DEFAULT;
            }

        } else {
            // IP prefix
            if (!ip_from_str((ip.substr(0, sep)).c_str(), &bl_entry.ip)) {
                cerr << "WARNING: Invalid IP address in file '" << file << "' on line '" << line_num << "'" << endl;
                continue;
            }

            ip.erase(0, sep + 1);
            bl_entry.prefix_len = (uint8_t) strtol(ip.c_str(), NULL, 0);
        }

        // Determine blacklist
        bl_entry.in_blacklist = bl_index;

        // Add entry to vector
        if (ip_is4(&bl_entry.ip)) {
            v4_list_new.push_back(bl_entry);
        }
        else {
            v6_list_new.push_back(bl_entry);
        }
    }

    input.close();

    v4_list = move(v4_list_new);
    v6_list = move(v6_list_new);

    DBG((stderr, "Blacklists reloaded. Entries: IP4: %lu, IP6: %lu\n", v4_list.size(), v6_list.size()));

    return ALL_OK;
}

/**
 * \brief Function for searching in blacklists. It uses binary search
 * algorithm to determine whether the given ip address fits any of the prefix/IP in the list.
 * \param searched IP address that we are checking.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param black_list List of prefixes to be compared with. Either IPv4 or IPv6
 * \return IP_NOT_FOUND if the ip address doesn't fit any prefix. Index of the prefix otherwise.
 */
int ip_binary_search(const ip_addr_t *searched,
                     const ipv4_mask_map_t &v4mm,
                     const ipv6_mask_map_t &v6mm,
                     const black_list_t &black_list)
{
    int end, begin, mid;
    int mask_result = 1;
    ip_addr_t masked;

    begin = 0;
    end = black_list.size() - 1;

    // Binary search
    if (ip_is4(searched)) {
        // Searching in IPv4 blacklist
        // Mask the searched IP with the mask of the mid IP, if it matches the network IP -> found
        while (begin <= end) {
            mid = (begin + end) >> 1;
            masked.ui32[2] = searched->ui32[2] & v4mm[black_list[mid].prefix_len];
            mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);

            if (mask_result < 0) {
                begin = mid + 1;
            } else if (mask_result > 0) {
                end = mid - 1;
            } else {
                break;
            }
        }
    } else {
        // Searching in IPv6 blacklist
        while (begin <= end) {
            mid = (begin + end) >> 1;
            if (black_list[mid].prefix_len <= 64) {
                masked.ui64[0] = searched->ui64[0] & v6mm[black_list[mid].prefix_len][0];
                mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
            } else {
                masked.ui64[1] = searched->ui64[1] & v6mm[black_list[mid].prefix_len][1];
                mask_result = memcmp(&(black_list[mid].ip.ui8), &(masked.ui8), 16);
            }

            if (mask_result < 0) {
                begin = mid + 1;
            } else if (mask_result > 0) {
                end = mid - 1;
            } else {
                break;
            }
        }
    }

    if (mask_result == 0) {
        // Address found, return blacklist index
        return mid;
    }

    return IP_NOT_FOUND;
}

/**
 * \brief Function for checking blacklisted IPv4/IPv6 addresses.
 *
 * It extracts both source and
 * destination addresses from the UniRec record and tries to match them to either
 * address or prefix. If the match is positive the field in detection record is filled
 * with the respective blacklist(s) number.
 * \param ur_in  Template of input UniRec record.
 * \param ur_out Template of detection UniRec record.
 * \param record Record being analyzed.
 * \param detected Detection record used if any address matches the blacklist.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param v4blacklist List of IPv4 prefixes to be compared with.
 * \param v6blacklist List of IPv6 prefixes to be compared with.
 * \return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int blacklist_check(ur_template_t *ur_in,
                    ur_template_t *ur_out,
                    const void *record,
                    void *detected,
                    const ipv4_mask_map_t &v4mm,
                    const ipv6_mask_map_t &v6mm,
                    const black_list_t &v4blacklist,
                    const black_list_t &v6blacklist)
{
    bool blacklisted = false;

    // determine which blacklist (ipv4/ipv6) we are working with
    const black_list_t & bl = ip_is4(&(ur_get(ur_in, record, F_SRC_IP))) ? v4blacklist : v6blacklist;

    // index of the prefix the source ip fits in (return value of binary search)
    int search_result;

    // Check source IP
    ip_addr_t ip = ur_get(ur_in, record, F_SRC_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_in, record, F_SRC_IP), v4mm, v6mm, bl)) != IP_NOT_FOUND) {
        ur_set(ur_out, detected, F_SRC_BLACKLIST, bl[search_result].in_blacklist);
        blacklisted = true;
    } else {
        ur_set(ur_out, detected, F_SRC_BLACKLIST, 0x0);
    }

    // Check destination IP
    ip = ur_get(ur_in, record, F_DST_IP);
    if ((search_result = ip_binary_search(ur_get_ptr(ur_in, record, F_DST_IP), v4mm, v6mm, bl)) != IP_NOT_FOUND) {
        ur_set(ur_out, detected, F_DST_BLACKLIST, bl[search_result].in_blacklist);
        blacklisted = true;
    } else {
        ur_set(ur_out, detected, F_DST_BLACKLIST, 0x0);
    }

    if (blacklisted) {
        return BLACKLISTED;
    }

    return ADDR_CLEAR;
}


int main(int argc, char **argv)
{
    int main_retval = 0;
    int retval = 0;
    int send_terminating_unirec = 1;

    // Set default files names
    char *userFile = (char *) SYSCONFDIR "/blacklistfilter/ipdetect_config.xml";

    // For use with prefixes
    black_list_t v4_list;
    black_list_t v6_list;

    // Mask array for prefixes
    ipv4_mask_map_t v4_masks;
    ipv6_mask_map_t v6_masks;
    create_v4_mask_map(v4_masks);
    create_v6_mask_map(v6_masks);

    // TRAP initialization
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    void *detection = NULL;
    ur_template_t *ur_output = NULL;
    ur_template_t *ur_input = NULL;
    string bl_file, bl_str;
    pthread_t watcher_thread = 0;

    // UniRec templates for recieving data and reporting blacklisted IPs
    ur_input = ur_create_input_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST", NULL);
    ur_output = ur_create_output_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,SRC_BLACKLIST,DST_BLACKLIST", NULL);

    if (ur_input == NULL || ur_output == NULL) {
        cerr << "Error: Input or output template could not be created" << endl;
        main_retval = 1; goto cleanup;
    }

    // Create detection record
    detection = ur_create_record(ur_output, 0);
    if (detection == NULL) {
        cerr << "Error: Memory allocation problem (output record)" << endl;
        main_retval = 1; goto cleanup;
    }

    // Set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT,  signal_handler);
    signal(SIGUSR1, signal_handler);

    int opt;

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
                main_retval = 1; goto cleanup;
        }
    }

    config_t config;

    if (loadConfiguration((char *) MODULE_CONFIG_PATTERN_STRING, userFile, &config, CONF_PATTERN_STRING)) {
        cerr << "Error: Could not parse XML configuration." << endl;
        main_retval = 1; goto cleanup;
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
        cerr << "Error: Unable to read bl_file '" << bl_file.c_str() << "'" << endl;
        main_retval = 1; goto cleanup;
    }

    if (WATCH_BLACKLISTS_FLAG) {
        if (pthread_create(&watcher_thread, NULL, watch_blacklist_files, (void *) bl_file.c_str()) > 0) {
            cerr << "Error: Couldnt create watcher thread" << endl;
            main_retval = 1; goto cleanup;
        }
    }

    // ***** Main processing loop *****
    while (!stop) {
        const void *data;
        uint16_t data_size;

        // Retrieve data from sender
        // TODO: Maybe non-blocking trap receive (when some flags set, it hangs here until trap data are received)
        retval = TRAP_RECEIVE(0, data, data_size, ur_input);
        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval, continue, break);

        // Check the data size
        if (data_size != ur_rec_size(ur_input, data)) {
            if (data_size <= 1) { // end of data
                break;
            } else { // data corrupted
                cerr << "ERROR: Corrupted data or wrong data template was specified. ";
                cerr << "Size computed from record: " << ur_rec_size(ur_input, data) << " ";
                cerr << "Size returned from Trap: " << data_size << endl;
                break;
            }
        }

        // Try to match the IP addresses to blacklist
        retval = blacklist_check(ur_input, ur_output, data, detection, v4_masks, v6_masks, v4_list, v6_list);

        // If IP address was found on blacklist
        if (retval == BLACKLISTED) {
            ur_copy_fields(ur_output, detection, ur_input, data);
            trap_send(0, detection, ur_rec_fixlen_size(ur_output));
            DBG((stderr, "IP detected on blacklist\n"))
        }

        if (BL_RELOAD_FLAG) {
            DBG((stderr, "Reloading blacklists\n"));
            retval = reload_blacklists(v4_list, v6_list, bl_file);
            if (retval == BLIST_FILE_ERROR) {
                cerr << "ERROR: Unable to load update blacklist. Will use the old one instead." << endl;
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

            if (loadConfiguration((char *) MODULE_CONFIG_PATTERN_STRING, userFile, &config, CONF_PATTERN_STRING)) {
                cerr << "Error: Could not parse XML configuration." << endl;
                main_retval = 1; goto cleanup;
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
                cerr << "Error: Unable to read bl_file '" << bl_file.c_str() << "'" << endl;
                main_retval = 1; goto cleanup;
            }

            RECONF_FLAG = 0;
        }
    }

    // If set, send terminating message to modules on output
    if (send_terminating_unirec) {
        trap_send(0, "TERMINATE", 1);
    }

cleanup:
    // Clean up before termination
    ur_free_record(detection);
    ur_free_template(ur_input);
    ur_free_template(ur_output);
    ur_finalize();

    TRAP_DEFAULT_FINALIZATION();
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

    if (WATCH_BLACKLISTS_FLAG && watcher_thread != 0) {
        // since watcher hangs on poll(), pthread_cancel is fine (poll is a cancelation point)
        if (pthread_cancel(watcher_thread) == 0) {
            pthread_join(watcher_thread, NULL);
            DBG((stderr, "Watcher thread successfully canceled\n"));
        } else {
            cerr << "Warning: Failed to cancel watcher thread" << endl;
        }
    }

    return main_retval;
}
