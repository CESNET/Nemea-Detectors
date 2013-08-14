/**
 * \file dnsblacklistfilter.cpp
 * \brief Main module for DNSBlackListDetector.
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
#include <idna.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif

#include "dnsblacklistfilter.h"

#define DEBUG 1

using namespace std;

trap_module_info_t module_info = {
    "DNS blacklist detection module", // Module name
    // Module description
    "Interfaces:\n"
    "   Inputs: 2 (UniRec record)\n"
    "   Outputs: 2 (UniRec record)\n", 
    2, // Number of input interfaces
    2, // Number of output interfaces
};


int stop = 0;
int update = 0;

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
 * Function for loading domain names for startup.
 * Function goes through all files listed in "path" folders and load the domain 
 * names to the table for use in cheking thread.
 *
 * @param blacklist Table for storing loaded domain names.
 * @param path Path to the folder with source files.
 * @return -1 if folder in "path" cannot be used, 0 otherwise.
 */
int load_dns(cc_hash_table_t* blacklist, const char* path)
{
    DIR* dp;
    struct dirent *file;

    ifstream in;

    string line;
    char *url_norm;
    int ret;
    uint8_t bl;

    dp = opendir(path);

    if (dp == NULL) { // directory cannot be openned
        cerr << "ERROR: Cannot open directory " << path << ". Directory doesn't exist";
        cerr << " or you don't have proper permissions. Unable to continue." << endl;
        return -1;
    }

    while (file = readdir(dp)) {

        if (file->d_name[0] == '.' || file->d_type == 0x4) {
            // exclude hidden files, directory references
            // and stay don't go recursively through directories
            continue;
        }

        in.open(string(string(path) + file->d_name).c_str(), ifstream::in);

        if (!in.is_open()) {
            cerr << "WARNING: File " << file->d_name << " cannot be opened. Will be skipped." << endl;
            continue;
        }

        // load file line by line
        while (!in.eof()) {
            getline(in, line);
#ifdef DEBUG
            cout << line << endl;
#endif

            // don't add the remaining empty line
            if (!line.length()) {
                continue;
            }

            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

            ret = idna_to_ascii_lz(line.c_str(), &url_norm, 0);
            if (ret != IDNA_SUCCESS) {
#ifdef DEBUG
                cerr << "Unable to normalize URL. Will skip." << endl;
#endif
                continue;
            }

            bl = strtoul(file->d_name, NULL, 0);
            if (bl == 0x0) {
                cerr << "WARNING: Cannot determine source blacklist. Will be skipped." << endl;
                in.close();
                break;
            }
#ifdef DEBUG
            cout << url_norm << endl;
#endif
            // insert to table
            ht_insert(blacklist, url_norm, &bl, strlen(url_norm));
            free(url_norm);
        }
        in.close();
    }

    closedir(dp);
    return 0;
}

/**
 * Function for loading updates.
 * Function gets path to the directory with update files and loads them the into 
 * the vectors used for update operation. Loaded entries are sorted depending 
 * on whterher they are removed from blacklist or added to blacklist.
 *
 * @param add_upd Vector with entries that will be added or updated.
 * @param rm_upd Vector with entries that will be removed.
 * @param path Path to the directory with updates.
 * @return 0 if everything goes well, -1 if directory cannot be accessed.
 */
int load_update(vector<upd_item_t>& add_upd, vector<upd_item_t>& rm_upd, const char* path)
{
    DIR* dp;
    struct dirent *file;

    ifstream in;

    string line;
    char *url_norm;
    int ret;

    upd_item_t upd;
    bool add_rem = false;

    dp = opendir(path);

    if (dp == NULL) { // directory cannot be openned
        cerr << "ERROR: Cannot open directory " << path << ". Directory doesn't exist";
        cerr << " or you don't have proper permissions. Unable to continue." << endl;
        return -1;
    }

    while (file = readdir(dp)) {

        if (file->d_name[0] == '.' || file->d_type == 0x4) {
            // exclude hidden files, directory references
            // and stay don't go recursively through directories
            continue;
        }

        in.open(string(string(path) + file->d_name).c_str(), ifstream::in);

        if (!in.is_open()) {
            cerr << "WARNING: File " << file->d_name << " cannot be opened. Will be skipped." << endl;
            continue;
        }

        // load file line by line
        while (!in.eof()) {
            getline(in, line);

            // don't add the remaining empty line
            if (!line.length()) {
                continue;
            }

            line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

#ifdef DEBUG
            cout << line << endl;
#endif

            if (line == "#remove") {
                add_rem = true;
                continue;
            }

            // normalize the URL
            ret = idna_to_ascii_lz(line.c_str(), &url_norm, 0);
            if (ret != IDNA_SUCCESS) {

#ifdef DEBUG
                cerr << "Unable to normalize URL. Will skip." << endl;
#endif
                continue;
            }

            upd.dns = url_norm; 
            // fill blacklist number
            upd.bl = strtoul(file->d_name, NULL, 0);
            if (upd.bl == 0x0) {
                cerr << "WARNING: Cannot determine source blacklist. Will be skipped." << endl;
                in.close();
                break;
            }
            // put loaded update to apropriate vector (add/update or remove)
            if (add_rem) {
                rm_upd.push_back(upd);
            } else {
                add_upd.push_back(upd);
            }
        }
        in.close();
        free(url_norm);
    }
    
    closedir(dp);
    return 0;
}

/**
 * Function for updating the blacklist (remove).
 * Function removes all items specified in the vector of updates from 
 * the table since these items are no longer valid.
 *
 * @param blacklist Blacklist to be updated.
 * @param rm Vector with items to remove.
 */
static void update_remove(cc_hash_table_t* blacklist, vector<upd_item_t>& rm)
{
    for (int i = 0; i < rm.size(); i++) {
        ht_remove_by_key(blacklist, rm[i].dns, strlen(rm[i].dns));
    }
}

/**
 * Function for updating the blacklist (add/update).
 * Function adds the items specified in the vector of updates to 
 * the table. If the item already exists it writes the new data.
 *
 * @param blacklist Blacklist to be updated.
 * @param add Vector with items to add or update.
 */
static void update_add(cc_hash_table_t* blacklist, vector<upd_item_t>& add)
{
    int bl_index;
    for (int i = 0; i < add.size(); i++) {
        if ((bl_index = ht_get_index(blacklist, add[i].dns, strlen(add[i].dns))) >= 0) {
            *((uint8_t *) blacklist->table[bl_index].data) = add[i].bl;
        } else {
            if (ht_insert(blacklist, add[i].dns, &add[i].bl, strlen(add[i].dns))) {
#ifdef DEBUG
                cerr << "Failure during adding new items. Update interrupted." << endl;
#endif
                return;
            }
        }
    }
}

/**
 * Function for checking incomming DNS queries for blacklisted domain names.
 * Function recieves UniRec with DNS query and checks if the requested domain 
 * name is in blacklist. If the domain name is found in blacklist the detection 
 * record is filled and sent with the number of source blacklist. Function also 
 * updates the IP table with the ip address associated with the domain name.
 * NOTE: The function is executed by a thread.
 *
 * @param args Arguments for the executing thread.
 * @return NULL if everything is ok, numeric value otherwise.
 */
void *check_dns(void *args)
{
    dns_params_t* params;
    params = (dns_params_t *) args;

    int retval = 0;

    const void* record;
    uint16_t record_size;

    void* is_dns = NULL;

    vector<upd_item_t> add_upd;
    vector<upd_item_t> rm_upd;

    while (!stop) {
#ifdef DEBUG
        cout << "DNS: Waiting for data ..." << endl;
#endif
        retval = trap_get_data(0x1, &record, &record_size, TRAP_WAIT);
        if (retval == TRAP_E_TERMINATED) {
            retval = EXIT_SUCCESS;
            break;
        } else {
            cerr << "ERROR: DNS thread cannot recieve data. Unable to continue." << endl;
            break;
        }
#ifdef DEBUG
        cout << "DNS: Checking data ..." << endl;
#endif
        if (record_size /* minus the size of domain name */ != ur_rec_static_size(params->input)) {
            if (record_size <= 1) { // trap terminated
                retval = EXIT_SUCCESS;
                break;
            } else {
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_static_size(params->input) << " ";
                cerr << "Recieved: " << record_size /* minus the size of domain name */ << " in static part." << endl;
                retval = EXIT_FAILURE;
                break;
            }
        }

#ifdef DEBUG
        cout << "DNS: Checking obtained domain name ..." << endl;
#endif
        // check blacklist for recieved domain name
        //is_dns = ht_get_index(params->dns_table, ur_get_dyn(params->input, record, DNS/URL), ur_get_dyn_size(params->input, record, DNS/URL));
        if (is_dns != NULL) {

#ifdef DEBUG
            cout << "DNS: Match found. Sending report ..." << endl;
#endif            
            /* ur_set(params->output, params->detection, UR_DNS_BLACKLIST, *(uint8_t *) is_dns); */
            trap_send_data(0, params->detection, ur_rec_size(params->output, params->detection), TRAP_HALFWAIT);

#ifdef DEBUG
            cout << "DNS: Updating IP table for IP thread ...." << endl;
#endif
            /* update IP table */
/*            if (ht_get_v2(params->ip_table, ur_get(params->input, UR_SRC_IP)) == NULL) {
                ht_insert_v2(params->ip_table, ur_get(params->input, UR_SRC_IP), is_dns);
            }*/
            if (ht_get_v2(params->ip_table, (char *) ur_get(params->input, record, UR_DST_IP).bytes) == NULL) {
                ht_insert_v2(params->ip_table, (char *) ur_get(params->input, record, UR_DST_IP).bytes, is_dns);
            }
        } else {
            // drop the record
        }

        // recieved update signal?
        if (update) {
#ifdef DEBUG
            cout << "DNS: Updating DNS table ..." << endl;
#endif
            update = 0;
            retval = load_update(add_upd, rm_upd, params->upd_path);

            if (!rm_upd.empty()) {
                update_remove(params->dns_table, rm_upd);
            }
            if (!add_upd.empty()) {
                update_add(params->dns_table, add_upd);
            }
        }
    }

#ifdef DEBUG
    cout << "DNS: Terminating ..." << endl;
#endif

    if (retval) {
        return (void *) retval;
    }
    return NULL;
}
/*
 * Function for checking IP addresses for blacklisted entries.
 * Function recieves UniRec and checks if both source and destination addresses 
 * are in blacklist. If the address is found in blacklist the detection
 * record is filled and sent with the number of source blacklist. Addresses for 
 * its blacklist are obtained from the DNS thread.
 * NOTE: The function is executed by a thread.
 *
 * @param args Arguments for the executing thread.
 * @return NULL if everything is ok, numeric value otherwise.
 */
void* check_ip(void *args)
{

    ip_params_t* params;
    params = (ip_params_t*) args; // get paramters for thread
    bool marked = false;

    void *bl = NULL;
    ip_addr_t ip;

    int retval = 0;
    const void* record;
    uint16_t record_size;

    while (!stop) {
#ifdef DEBUG
        cout << "IP: Waiting for data ..." << endl;
#endif
        // recieve data
        retval = trap_get_data(0x2, &record, &record_size, TRAP_WAIT);
        if (retval == TRAP_E_TERMINATED) {
            retval = EXIT_SUCCESS;
            break;
        } else {
            cerr << "ERROR: IP thread cannot recieve data. Unable to continue." << endl;
            break;
        }
#ifdef DEBUG
        cout << "IP: Checking data ..." << endl;
#endif
        // check the recieved data size
        if (record_size != ur_rec_static_size(params->input)) {
            if (record_size <= 1) { // trap terminated
                retval = EXIT_SUCCESS;
                break;
            } else {
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_static_size(params->input) << " ";
                cerr << "Recieved: " << record_size << endl;
                retval = EXIT_FAILURE;
                break;
            }
        }
        
        ip = ur_get(params->input, record, UR_SRC_IP);    

        // try to match the blacklist for src IP
        bl = ht_get_v2(params->ip_table, (char *) ip.bytes);

#ifdef DEBUG
        cout << "IP: Checking obtained IP addresses ..." << endl;
#endif

        if (bl != NULL) {
            ur_set(params->output, params->detection, UR_SRC_BLACKLIST, *(uint8_t*) bl);
            marked = true;
        }

        ip = ur_get(params->output, record, UR_DST_IP);

        // try to match the blacklist for dst IP
        bl = ht_get_v2(params->ip_table, (char *) ip.bytes);

        if (bl != NULL) {
            ur_set(params->output, params->detection, UR_DST_BLACKLIST, *(uint8_t*) bl);
            marked = true;
        }

        if (marked) {
#ifdef DEBUG
            cout << "IP: Match found. Sending report ..." << endl;
#endif            
            trap_send_data(1, params->detection, ur_rec_size(params->output, params->detection), TRAP_HALFWAIT);
        }
    }
#ifdef DEBUG
    cout << "IP: Terminating ..." << endl;
#endif

    if (retval != EXIT_SUCCESS) {
        return (void *) retval;
    }
    return NULL;
}

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{

    int retval = 0; // return value

    cc_hash_table_v2_t ip_table;
    cc_hash_table_t dns_table;

    // prepare tables

    ht_init(&dns_table, DNS_TABLE_SIZE, sizeof(uint8_t), 0, REHASH_ENABLE);
    ht_init_v2(&ip_table, IP_TABLE_SIZE, sizeof(uint8_t), sizeof(ip_addr_t));

    // prepare parameters for both threads
    dns_params_t dns_thread_params;
    ip_params_t ip_thread_params;

    // link tables
    dns_thread_params.dns_table = &dns_table;
    dns_thread_params.ip_table = ip_thread_params.ip_table = &ip_table;

    ur_template_t *dns_input, *ip_input, *dns_det, *ip_det;

    // link templates
    dns_input = ur_create_template("<COLLECTOR_FLOW>"); // + DNS request items
    ip_input = ur_create_template("<COLLECTOR_FLOW>");
    dns_det = ur_create_template("<BASIC_FLOW>"); // + DNS blacklist flag
    ip_det = ur_create_template("<BASIC_FLOW>,SRC_BLACKLIST,DST_BLACKLIST");

    dns_thread_params.input = dns_input;
    dns_thread_params.output = dns_det;
    ip_thread_params.input = ip_input;
    ip_thread_params.output = ip_det;

    // create detection records
    dns_thread_params.detection = ur_create(dns_thread_params.output, 0);
    ip_thread_params.detection = ur_create(ip_thread_params.output, 0);

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

    // intialize TRAP interfaces
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        if (retval == TRAP_E_HELP) {
            trap_print_help(&module_info);
            ur_free(ip_thread_params.detection);
            ur_free(dns_thread_params.detection);
            ur_free_template(ip_thread_params.input);
            ur_free_template(dns_thread_params.input);
            ur_free_template(ip_thread_params.output);
            ur_free_template(dns_thread_params.output);
            ht_destroy_v2(ip_thread_params.ip_table);
            ht_destroy(dns_thread_params.dns_table);
            return EXIT_SUCCESS;
        }
        cerr << "ERROR: Cannot parse input parameters: " << trap_last_error_msg << endl;
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return retval;
    }
    
    // Initialize TRAP library (create and init all interfaces)     
    retval = trap_init(&module_info, ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP couldn't be initialized: " << trap_last_error_msg << endl;
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return retval;
    }

    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    // check if the source folder for DNS thread was specified
    if (argc != 2) {
        cerr << "ERROR: Directory with DNS sources not specified. Unable to continue." << endl;
        //trap_finalize();
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return EXIT_FAILURE;
    }

    // load domain names from blacklist folder
    retval = load_dns(dns_thread_params.dns_table, (const char *) argv[1]);
    if (retval) {
        cerr << "ERROR: DNS table cannot be loaded. Unable to continue." << endl;
        //trap_finalize();
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return EXIT_FAILURE;
    }

    // did we load anything?
    if (ht_is_empty(dns_thread_params.dns_table)) {
        cerr << "ERROR: DNS table is empty. Continuing makes no sense." << endl;
        //trap_finalize();
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return EXIT_FAILURE;
    }

    dns_thread_params.upd_path = argv[1];

    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    pthread_t threads[THR_COUNT];
    pthread_attr_t th_attr;

    pthread_attr_init(&th_attr);
    pthread_attr_setdetachstate(&th_attr, PTHREAD_CREATE_JOINABLE);

    // start the DNS thread (preferably first so the IP table can be slightly in advance)
    retval = pthread_create(&threads[0], &th_attr, check_dns, (void *) &dns_thread_params);
    if (retval) {
        cerr << "ERROR: Cannot create DNS checking thread. Terminating ..." << endl;
        trap_finalize();
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return EXIT_FAILURE;
    }

    // start the IP thread
    retval = pthread_create(&threads[1], &th_attr, check_ip, (void *) &ip_thread_params);
    if (retval) {
        cerr << "ERROR: Cannot create IP checking thread. Terminating ..." << endl;
        pthread_cancel(threads[0]);
        //trap_finalize();
        ur_free(ip_thread_params.detection);
        ur_free(dns_thread_params.detection);
        ur_free_template(ip_thread_params.input);
        ur_free_template(dns_thread_params.input);
        ur_free_template(ip_thread_params.output);
        ur_free_template(dns_thread_params.output);
        ht_destroy_v2(ip_thread_params.ip_table);
        ht_destroy(dns_thread_params.dns_table);
        return EXIT_FAILURE;
    }

    void *thr_exit_state;
#ifdef DEBUG
        cout << "MAIN: Waiting for processing threads ..." << endl;
#endif

    // Main thread should wait for termination of both working threads
    for (int i = 0; i < THR_COUNT; i++) {
        retval = pthread_join(threads[i], &thr_exit_state);
        
        // thread couldn't be joined (something very wrong happened)
        if (retval) {
            cerr << "ERROR: Problem when joining threads. Terminating ..." << endl;
            pthread_cancel(threads[0]);
            pthread_cancel(threads[1]);
            //trap_finalize();
            ur_free(ip_thread_params.detection);
            ur_free(dns_thread_params.detection);
            ur_free_template(ip_thread_params.input);
            ur_free_template(dns_thread_params.input);
            ur_free_template(ip_thread_params.output);
            ur_free_template(dns_thread_params.output);
            ht_destroy_v2(ip_thread_params.ip_table);
            ht_destroy(dns_thread_params.dns_table);
            exit(EXIT_FAILURE);
        }

        // Termination of any of the thread was not successful -- terminate
        if (thr_exit_state != NULL) {
            cerr << "ERROR: Thread returned FAILURE value. Terminating ..." << endl;
            //trap_finalize();
            ur_free(ip_thread_params.detection);
            ur_free(dns_thread_params.detection);
            ur_free_template(ip_thread_params.input);
            ur_free_template(dns_thread_params.input);
            ur_free_template(ip_thread_params.output);
            ur_free_template(dns_thread_params.output);
            ht_destroy_v2(ip_thread_params.ip_table);
            ht_destroy(dns_thread_params.dns_table);
            exit(EXIT_FAILURE);
        }
    }

    // threads were successfully terminated -- cleanup and shut down

#ifdef DEBUG
    cout << "Cleaning up..." << endl;
#endif
    // trap_finalize();
#ifdef DEBUG
    cout << "TRAP Offline" << endl;
#endif
    ur_free(ip_thread_params.detection);
    ur_free(dns_thread_params.detection);

#ifdef DEBUG
    cout << "Detection records destroyed" << endl;
#endif
    ur_free_template(ip_thread_params.input);
    ur_free_template(dns_thread_params.input);
    ur_free_template(ip_thread_params.output);
    ur_free_template(dns_thread_params.output);
#ifdef DEBUG
    cout << "UR templates destroyed" << endl;
#endif
    ht_destroy_v2(ip_thread_params.ip_table);
    ht_destroy(dns_thread_params.dns_table);
#ifdef DEBUG
    cout << "Tables destroyed -- Terminating ..." << endl;
#endif 
    return EXIT_SUCCESS;
}