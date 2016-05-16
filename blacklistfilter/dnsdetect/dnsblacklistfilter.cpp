/**
 * \file dnsblacklistfilter.cpp
 * \brief Main module for DNSBlackListDetector.
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
#include "fields.h"
#ifdef __cplusplus
}
#endif

#include "dnsblacklistfilter.h"

#define DEBUG
//#undef DEBUG

    // link templates

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
    string DNS_NAME,
    uint16 DNS_QTYPE,
    uint16 DNS_RLENGTH,
    string DNS_RDATA,
    uint8 DNS_DO,       //DNSSEC OK bit
    //Blacklist items
    uint8 DNS_BLACKLIST,    //ID of blacklist which contains suspicious domain name
    uint64 SRC_BLACKLIST,   //Bit field of blacklists IDs which contains the source address of the flow
    uint64 DST_BLACKLIST,   //Bit field of blacklists IDs which contains the destination address of the flo
    uint8 BLACKLIST_TYPE,   //Type of the used blacklist (spam, C&C, malware, etc.)
)


using namespace std;

trap_module_info_t module_info = {
    (char *)"DNS blacklist detection module", // Module name
    // Module description
    (char *)"Interfaces:\n"
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
    // get parameters for thread
    dns_params_t* params = (dns_params_t *) args;

    int retval = 0;

    const void* record;
    uint16_t record_size;

    void* is_dns = NULL;

    vector<upd_item_t> add_upd;
    vector<upd_item_t> rm_upd;

    unsigned dets = 0, flows = 0;

    while (!stop) {
        retval = TRAP_RECEIVE(0x1, record, record_size, params->input);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) {
                retval = EXIT_SUCCESS;
                break;
            } else {
                cerr << "ERROR: DNS thread cannot recieve data. Unable to continue." << endl;
                break;
            }
        }
        if ((record_size - ur_rec_varlen_size(params->input,record)) != ur_rec_fixlen_size(params->input)) {
            if (record_size <= 1) { // trap terminated
                retval = EXIT_SUCCESS;
                break;
            } else {
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_fixlen_size(params->input) << " ";
                cerr << "Recieved: " << record_size - ur_rec_varlen_size(params->input,record) << " in static part." << endl;
                retval = EXIT_FAILURE;
                break;
            }
        }

        flows++;

        if (ur_get(params->input, record, F_DNS_QTYPE) != 1 && ur_get(params->input, record, F_DNS_QTYPE) != 28)
            continue;

#ifdef DEBUG
        char *dn = ur_get_ptr(params->input, record, F_DNS_NAME);
//        cout << "DNS: Checking obtained domain name " << dn << " ..." << endl;
#endif

	int s = ur_get_var_len(params->input, record, F_DNS_NAME);
        if (s < 0) {
            s = 0;
        }
        // check blacklist for recieved domain name
        is_dns = ht_get(params->dns_table, ur_get_ptr(params->input, record, F_DNS_NAME), s);
        if (is_dns != NULL) {

#ifdef DEBUG
            cout << "DNS: Match found (" << dn << "). Sending report ..." << endl;
            dets++;
#endif
            //create detection record (must be created here because of dynamic items)
            params->detection = ur_create_record(params->output, ur_get_var_len(params->input, record, F_DNS_NAME));

            ur_copy_fields(params->output, params->detection, params->input, record);

            // set blacklist
            ur_set(params->output, params->detection, F_DNS_BLACKLIST, *(uint8_t *) is_dns);

#ifdef DEBUG
            dn = ur_get_ptr(params->output, params->detection, F_DNS_NAME);
#endif

            trap_send(0, params->detection, ur_rec_size(params->output, params->detection));

            ur_free_record(params->detection);

#ifdef DEBUG
            if (ur_get(params->input, record, F_DNS_RLENGTH) == 4) {
                string resp = string(ur_get_ptr(params->input, record, F_DNS_RDATA), ur_get_var_len(params->input, record, F_DNS_RDATA));
                cout << "DNS: Updating IP table for IP thread " << resp << " ..." << endl;
            }
#endif

            if (ur_get(params->input, record, F_DNS_RLENGTH) == 4 || ur_get(params->input, record, F_DNS_RLENGTH) == 16) {
                char *ip = ur_get_ptr(params->input, record, F_DNS_RDATA);
                void *bl = NULL;
                ip_addr_t ip_conv;
                if (ip_from_str(ip, &ip_conv)) {
                    if ((bl = ht_get_v2(params->ip_table, (char *) ip_conv.bytes)) == NULL) {
                        ht_insert_v2(params->ip_table, (char *) ip_conv.bytes, is_dns);
                    } else {
                        *(uint8_t *) bl = *(uint8_t *) is_dns;
                    }
                }
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

            // clean update vectors for another use
            rm_upd.clear();
            add_upd.clear();
        }
    }

#ifdef DEBUG
    cout << "DNS: Terminating ..." << endl;
    cout << dets << "/" << flows << " blacklisted domains." << endl;
#endif

    if (retval) {
        pthread_exit((void *) &retval);
    }
    return NULL;
}

/**
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
    // get paramters for thread
    ip_params_t* params = (ip_params_t*) args;
    bool marked = false;

    void *bl = NULL;
    ip_addr_t ip;

    int retval = 0;
    const void* record;
    uint16_t record_size;

#ifdef DEBUG
    unsigned dets = 0, flows = 0;
    char matched[INET6_ADDRSTRLEN];
#endif

    while (!stop) {
/*#ifdef DEBUG
        cout << "IP: Waiting for data ..." << endl;
#endif*/
        // recieve data
        retval = TRAP_RECEIVE(0x2, record, record_size, params->input);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) {
                retval = EXIT_SUCCESS;
                break;
            } else {
                cerr << "ERROR: IP thread cannot recieve data. Unable to continue." << endl;
                break;
            }
        }
/*#ifdef DEBUG
        cout << "IP: Checking data ..." << endl;
#endif*/
        // check the recieved data size
        if (record_size != ur_rec_fixlen_size(params->input)) {
            if (record_size <= 1) { // trap terminated
                retval = EXIT_SUCCESS;
                break;
            } else {
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_fixlen_size(params->input) << " ";
                cerr << "Recieved: " << record_size << endl;
                retval = EXIT_FAILURE;
                break;
            }
        }

        flows++;

        ip = ur_get(params->input, record, F_SRC_IP);

        // try to match the blacklist for src IP
        bl = ht_get_v2(params->ip_table, (char *) ip.bytes);

/*#ifdef DEBUG
        cout << "IP: Checking obtained IP addresses ..." << endl;
#endif*/

        uint8_t ip_bl = 0x0;

        if (bl != NULL) {
            ur_set(params->output, params->detection, F_SRC_IP, ur_get(params->input, record, F_SRC_IP));
            ur_set(params->output, params->detection, F_SRC_BLACKLIST, *(uint8_t*) bl);
            ip_bl |= ((*(uint8_t*) bl) << 4);
            marked = true;
#ifdef DEBUG
            ip_to_str(&ip, matched);
            cout << "IP: Source " << matched << " found in blacklist." << endl;
#endif
        }

        ip = ur_get(params->output, record, F_DST_IP);

        // try to match the blacklist for dst IP
        bl = ht_get_v2(params->ip_table, (char *) ip.bytes);

        if (bl != NULL) {
            ur_set(params->output, params->detection, F_DST_IP, ur_get(params->input, record, F_DST_IP));
            ur_set(params->output, params->detection, F_DST_BLACKLIST, *(uint8_t*) bl);
            ip_bl |= (*(uint8_t*) bl);
            marked = true;
#ifdef DEBUG
            ip_to_str(&ip, matched);
            cout << "IP: Destination " << matched << " found in blacklist." << endl;
#endif
        }

        if (marked) {
#ifdef DEBUG
            cout << "IP: Sending report ..." << endl;
            dets++;
#endif
            ur_set(params->output, params->detection, F_BLACKLIST_TYPE, ip_bl);
            ur_copy_fields(params->output, params->detection, params->input, record);
            trap_send(1, params->detection, ur_rec_size(params->output, params->detection));
            marked = false;
        }
    }
#ifdef DEBUG
    cout << "IP: Terminating ..." << endl;
    cout << dets << "/" << flows << " blacklisted IPs." << endl;
#endif

    if (retval != EXIT_SUCCESS) {
        pthread_exit((void *) &retval);
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
    char *errstr = NULL;
    dns_input = ur_create_input_template(0x1, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,DNS_NAME,DNS_QTYPE,DNS_RLENGTH,DNS_RDATA", &errstr);
    if (dns_input == NULL) {
        cerr << "Error: Invalid UniRec specifier." << endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        trap_finalize();
        return EXIT_FAILURE;
    }
    ip_input = ur_create_input_template(0x2, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL", &errstr);
    if (ip_input == NULL) {
        cerr << "Error: Invalid UniRec specifier." << endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        ur_free_template(dns_input);
        trap_finalize();
        return EXIT_FAILURE;
    }
    dns_det = ur_create_output_template(0x1, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,DNS_BLACKLIST,DNS_NAME", &errstr); // + DNS blacklist flag and BLACKLIST_TYPE
    if (dns_det == NULL) {
        cerr << "Error: Invalid UniRec specifier." << endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        trap_finalize();
        return EXIT_FAILURE;
    }
    ip_det = ur_create_output_template(0x2, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL,SRC_BLACKLIST,DST_BLACKLIST,BLACKLIST_TYPE", &errstr); // + BLACKLIST_TYPE
    if (ip_det == NULL) {
        cerr << "Error: Invalid UniRec specifier." << endl;
        if(errstr != NULL){
            fprintf(stderr, "%s\n", errstr);
            free(errstr);
        }
        trap_finalize();
        return EXIT_FAILURE;
    }

    dns_thread_params.input = dns_input;
    dns_thread_params.output = dns_det;
    ip_thread_params.input = ip_input;
    ip_thread_params.output = ip_det;

    // create detection records
    ip_thread_params.detection = ur_create_record(ip_thread_params.output, 0);

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

    // intialize TRAP interfaces
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        if (retval == TRAP_E_HELP) {
            trap_print_help(&module_info);
            DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                               dns_thread_params.input, dns_thread_params.output,
                               ip_thread_params.input, ip_thread_params.output);
             return EXIT_SUCCESS;
        }
        cerr << "ERROR: Cannot parse input parameters: " << trap_last_error_msg << endl;
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
         return retval;
    }

    // Initialize TRAP library (create and init all interfaces)
    retval = trap_init(&module_info, ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP couldn't be initialized: " << trap_last_error_msg << endl;
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
        return retval;
    }
    trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
    trap_ifcctl(TRAPIFC_OUTPUT, 1, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);
    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    // check if the source folder for DNS thread was specified
    if (argc != 2) {
        cerr << "ERROR: Directory with DNS sources not specified. Unable to continue." << endl;
        trap_terminate();
        trap_finalize();
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
        return EXIT_FAILURE;
    }

    // load domain names from blacklist folder
    retval = load_dns(dns_thread_params.dns_table, (const char *) argv[1]);
    if (retval) {
        cerr << "ERROR: DNS table cannot be loaded. Unable to continue." << endl;
        trap_terminate();
        trap_finalize();
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);

        return EXIT_FAILURE;
    }

    // did we load anything?
    if (ht_is_empty(dns_thread_params.dns_table)) {
        cerr << "ERROR: DNS table is empty. Continuing makes no sense." << endl;
        trap_terminate();
        trap_finalize();
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
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
        trap_terminate();
        trap_finalize();
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
        return EXIT_FAILURE;
    }

    // start the IP thread
    retval = pthread_create(&threads[1], &th_attr, check_ip, (void *) &ip_thread_params);
    if (retval) {
        cerr << "ERROR: Cannot create IP checking thread. Terminating ..." << endl;
        pthread_cancel(threads[0]);
        trap_terminate();
        trap_finalize();
        DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
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
            trap_terminate();
            trap_finalize();
            DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
            exit(EXIT_FAILURE);
        }

        // Termination of any of the thread was not successful -- terminate
        if (thr_exit_state != NULL) {
            cerr << "ERROR: Thread returned FAILURE value. Terminating ..." << endl;
            trap_terminate();
            trap_finalize();
            DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                           dns_thread_params.input, dns_thread_params.output,
                           ip_thread_params.input, ip_thread_params.output);
            exit(EXIT_FAILURE);
        }
    }

    // threads were successfully terminated -- cleanup and shut down

#ifdef DEBUG
    cout << "Cleaning up..." << endl;
#endif
    trap_finalize();
    DESTROY_STRUCTURES(ip_thread_params.ip_table, dns_thread_params.dns_table,
                       dns_thread_params.input, dns_thread_params.output,
                       ip_thread_params.input, ip_thread_params.output);
    ur_free_record(ip_thread_params.detection);
    return EXIT_SUCCESS;
}
