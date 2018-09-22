/**
 * \file dnsblacklistfilter.cpp
 * \brief Main module for DNSBlackListDetector.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Filip Suster, sustefil@fit.cvut.cz
 * \date 2013-2018
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

#include <algorithm>
#include <cctype>
#include <iostream>
#include <fstream>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <cstdlib>
#include <dirent.h>
#include <vector>
#include <nemea-common/nemea-common.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#include "fields.h"
#ifdef __cplusplus
}
#endif

#include "dnsblacklistfilter.h"
#include "blacklist_watcher.h"

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif


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
    //DNS
    uint16 DNS_ID,
    uint16 DNS_ANSWERS,
    string DNS_NAME,
    uint16 DNS_QTYPE,
    uint16 DNS_RLENGTH,
    uint8  DNS_RCODE,
    bytes  DNS_RDATA,
    uint8  DNS_DO,       //DNSSEC OK bit
    //Blacklist items
    uint64  BLACKLIST,   //ID of blacklist which contains suspicious domain name
)

trap_module_info_t *module_info = NULL;

using namespace std;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("DNSBlacklistFilter", "Module receives the UniRec record and checks if the domain name (FQDN) " \
    "is present in any DNS/FQDN blacklist that are available. " \
    "If the FQDN is present in any blacklist the record is changed by adding an index of the blacklist. " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bl_downloader_config.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "", "Specify user configuration file for DNSBlacklistFilter. [Default: " SYSCONFDIR "/blacklistfilter/dnsdetect_config.xml]", required_argument, "string") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none") \

int stop = 0; // global variable for stopping the program
int BL_RELOAD_FLAG = 0;
static bool WATCH_BLACKLISTS_FLAG;

/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


/**
 * Function for loading blacklist file.
 * Function gets path to the file and loads the blacklisted DNS/FQDN entities
 * The FQDNs are stored in a prefix tree
 * @param tree Prefix tree to be filled.
 * @param file Path to the file with sources.
 * @return BLIST_LOAD_ERROR if directory cannot be accessed, ALL_OK otherwise.
 */
int reload_blacklists(prefix_tree_t **tree, string &file)
{
    // TODO: ineffective, make it work just with diffs
    prefix_tree_destroy(*tree);
    *tree = prefix_tree_initialize(SUFFIX, sizeof(info_t), '.', DOMAIN_EXTENSION_NO, RELAXATION_AFTER_DELETE_YES);

    ifstream input;
    string line, fqdn, bl_flag_str;
    uint64_t bl_index;
    int line_num = 0;
    size_t sep;

    input.open(file.c_str(), ifstream::in);
    if (!input.is_open()) {
        std::cerr << "ERROR: Cannot open file with updates. Is the downloader running?" << std::endl;
        return BLIST_LOAD_ERROR;
    }

    // load file line by line
    while (!input.eof()) {
        getline(input, line);
        line_num++;

        if (input.bad()) {
            cerr << "ERROR: Failed reading blacklist file (getline badbit)" << endl;
            input.close();
            return BLIST_LOAD_ERROR;
        }

        // find DNS-blacklist separator
        sep = line.find_first_of('\\');

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

        // Parse DNS
        fqdn = line.substr(0, sep);

        prefix_tree_domain_t *elem = prefix_tree_insert(*tree, fqdn.c_str(), strlen(fqdn.c_str()));

        if (elem != NULL) {
            info_t *info = (info_t *) elem->value;
            info->bl_id = bl_index;
        } else {
            cerr << "WARNING: Can't insert element \'" << fqdn.c_str() << "\' to the prefix tree" << endl;
        }
    }

    DBG((stderr, "DNS Blacklists Reloaded.\n"))

    input.close();

    return ALL_OK;
}

/**
 * Function for checking the DNS/FQDN.
 * Function gets the UniRec record with DNS/FQDN to check and tries to find it
 * in the given blacklist. If the function succeeds then the appropriate
 * field in detection record is filled with the number of blacklist asociated
 * with the DNS/FQDN. If the DNS/FQDN is clean nothing is done.
 *
 * @param tree Prefix tree with blacklisted elements.
 * @param in Template of input UniRec (record).
 * @param out Template of output UniRec (detect).
 * @param record Record with DNS/FQDN for checking.
 * @param detect Record for reporting detection of blacklisted DNS/FQDN.
 * @return BLACKLISTED if the address is found in table, FQDN_CLEAR otherwise.
 */
int check_blacklist(prefix_tree_t *tree, ur_template_t *in, ur_template_t *out, const void *record, void *detect)
{
    string fqdn;

    if (ur_get_var_len(in, record, F_DNS_NAME) == 0) {
        return DNS_CLEAR;
    }

    fqdn = string(ur_get_ptr(in, record, F_DNS_NAME), ur_get_var_len(in, record, F_DNS_NAME));

    // erase WWW prefix
    if (fqdn.find(WWW_PREFIX) == 0) {
        fqdn.erase(0, strlen(WWW_PREFIX));
    }

    std::transform(fqdn.begin(), fqdn.end(), fqdn.begin(), ::tolower);

    prefix_tree_domain_t *domain = prefix_tree_search(tree, fqdn.c_str(), fqdn.length());

    if (domain != NULL) {
        DBG((stderr, "Detected blacklisted DNS/FQDN: '%s'\n", fqdn.c_str()));
        info_t *info = (info_t *) domain->value;
        ur_set(out, detect, F_BLACKLIST, info->bl_id);
        return BLACKLISTED;
    }

    // DNS/FQDN was not found
    return DNS_CLEAR;
}


/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{
    int retval = 0;
    int main_retval = 0;
    int send_terminating_unirec = 1;

    // Set default files names
    char *userFile = (char *) SYSCONFDIR "/blacklistfilter/dnsdetect_config.xml";

    // TRAP initialization
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

    void *detection = NULL;
    ur_template_t *ur_output = NULL;
    ur_template_t *ur_input = NULL;
    string bl_file, bl_str;
    pthread_t watcher_thread = 0;

    // UniRec templates for recieving data and reporting blacklisted DNS/FQDN
    ur_input = ur_create_input_template(0, "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,"
                                           "time TIME_LAST,uint32 DNS_RR_TTL,uint32 PACKETS,"
                                           "uint16 DNS_ANSWERS,uint16 DNS_CLASS,uint16 DNS_ID,uint16 DNS_PSIZE,uint16 DNS_QTYPE,"
                                           "uint16 DNS_RLENGTH,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 DNS_DO,"
                                           "uint8 DNS_RCODE,uint8 PROTOCOL,string DNS_NAME,bytes DNS_RDATA", NULL);

    ur_input = ur_create_input_template(0, "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,time TIME_FIRST,"
                                           "time TIME_LAST,uint32 DNS_RR_TTL,uint32 PACKETS,"
                                           "uint16 DNS_ANSWERS,uint16 DNS_CLASS,uint16 DNS_ID,uint16 DNS_PSIZE,uint16 DNS_QTYPE,"
                                           "uint16 DNS_RLENGTH,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 DNS_DO,"
                                           "uint8 DNS_RCODE,uint8 PROTOCOL,string DNS_NAME,bytes DNS_RDATA, uint64 BLACKLIST", NULL);

    if (ur_input == NULL || ur_output == NULL) {
        cerr << "Error: Input or output template could not be created" << endl;
        main_retval = 1; goto cleanup;
    }

    // Create detection record
    detection = ur_create_record(ur_output, DETECTION_ALLOC_LEN);
    if (detection == NULL) {
        cerr << "Error: Memory allocation problem (output record)" << endl;
        main_retval = 1; goto cleanup;
    }

    // ********** Parse arguments **********
    int opt;
    while ((opt = getopt(argc, argv, "nu:")) != -1) {
        switch (opt) {
            case 'u': // user configuration file for DNSBlacklistFilter
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

    // Load FQDNs from file
    bl_file = config.blacklist_file;
    if (reload_blacklists(&tree, bl_file) == BLIST_LOAD_ERROR) {
        cerr << "Error: Unable to read bl_file " << bl_file.c_str() << endl;
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

        // retrieve data from server
        retval = TRAP_RECEIVE(0, data, data_size, ur_input);
        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval, continue, break);

        // check the data size -- we can only check static part since DNS is dynamic
        if ((data_size - ur_rec_varlen_size(ur_input, data)) != ur_rec_fixlen_size(ur_input)) {
            if (data_size <= 1) { // end of data
                break;
            } else { // data corrupted
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_fixlen_size(ur_input) << " ";
                cerr << "Recieved: " << data_size - ur_rec_varlen_size(ur_input,data) << " in static part." << endl;
                break;
            }
        }

        // check for blacklist match
        retval = check_blacklist(tree, ur_input, ur_output, data, detection);

        // is blacklisted? send report
        if (retval == BLACKLISTED) {
            ur_copy_fields(ur_output, detection, ur_input, data);
            trap_send(0, detection, ur_rec_size(ur_output, detection));
        }

        if (BL_RELOAD_FLAG) {
            // Update blacklists
            DBG((stderr, "Reloading blacklists\n"));
            if (reload_blacklists(&tree, bl_file) == BLIST_LOAD_ERROR) {
                cerr << "ERROR: Unable to load update files. Will use the old tables instead." << endl;
            }

            // this lazy locking is fine, we don't need to reload the blacklists immediately
            // and locking the mutex in every iteration is ineffective
            pthread_mutex_lock(&BLD_SYNC_MUTEX);
            BL_RELOAD_FLAG = 0;
            pthread_mutex_unlock(&BLD_SYNC_MUTEX);
        }
    }

    // send terminate message
    if (send_terminating_unirec) {
        trap_send(0, "TERMINATE", 1);
    }

    cleanup:
    // clean up before termination
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