/**
 * \file urlblacklistfilter.cpp
 * \brief Main module for URLBlackLIstDetector.
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
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <clocale>
#include <stdint.h>
#include <signal.h>
#include <dirent.h>
#include <idna.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif
#include "../../../unirec/unirec.h"
#include "urlblacklistfilter.h"
#include "../../../common/cuckoo_hash/cuckoo_hash.h"
#include "../../../common/super_fast_hash/super_fast_hash.h"

#define DEBUG 1

using namespace std;

trap_module_info_t module_info = {
    "IP blacklist detection module", // Module name
    // Module description
    "Module recieves the UniRec record and checks if the URL in record isn't\n"
    "present in any blacklist that are available. If so the module creates\n"
    "a detection report (UniRec) with blacklist where the URL was found.\n"
    "The report is the send to further processing.\n"
    "Interfaces:\n"
    "   Inputs: 1 (UniRec record)\n"
    "   Outputs: 1 (UniRec record)\n", 
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
 * Function for loading source files.
 * Function gets path to the directory with source files and use these to fill the 
 * given blacklist with URLs. Since URL can have variable length its hashed first 
 * and this hash used in blacklist for all operations.
 *
 * @param blacklist Blacklist table to be filled.
 * @param path Path to the directory with sources.
 * @return BLIST_LOAD_ERROR if directory cannot be accessed, ALL_OK otherwise.
 */
int load_url(cc_hash_table_t& blacklist, const char* path)
{
    DIR* dp;
    struct dirent *file;

    ifstream in;

    string line;
    char *url_norm;
    int ret;
    uint32_t hashed_url;
    uint8_t bl;

    dp = opendir(path);

    if (dp == NULL) { // directory cannot be openned
        cerr << "ERROR: Cannot open directory " << path << ". Directory doesn't exist";
        cerr << " or you don't have proper permissions. Unable to continue." << endl;
        return BLIST_LOAD_ERROR;
    }

    while (file = readdir(dp)) {

        if (file->d_name[0] == '.' || file->d_type == 0x4) {
            // exclude hidden files, directory references and recursive directories
            continue;
        }

        in.open(file->d_name, ifstream::in);

        if (!in.is_open()) {
            cerr << "WARNING: File " << file->d_name << " cannot be opened. Will be skipped." << endl;
            continue;
        }

        // load file line by line
        while (!in.eof()) {
            getline(in, line);

            ret = idna_to_ascii_lz(line.c_str(), &url_norm, 0);
            if (ret != IDNA_SUCCESS) {
#ifdef DEBUG
                cerr << "Unable to normalize URL. Will skip." << endl;
#endif
                continue;
            }

            // hash the url
            hashed_url = SuperFastHash(url_norm, strlen(url_norm));

            bl = strtoul(file->d_name, NULL, 0);
            if (bl == 0x0) {
                cerr << "WARNING: Cannot determine source blacklist. Will be skipped." << endl;
                in.close();
                break;
            }

            // insert to table
            ht_insert(&blacklist, (char *) &hashed_url, &bl);
        }
        in.close();
    }

    closedir(dp);
    return ALL_OK;
}

/**
 * Function for loading updates.
 * Function gets path to the directory with update files and loads the into 
 * the vectors used for update operation. Loaded entries are sorted depending 
 * on whterher they are removed from blacklist or added to blacklist.
 *
 * @param add_upd Vector with entries that will be added or updated.
 * @param rm_upd Vector with entries that will be removed.
 * @param path Path to the directory with updates.
 * @return ALL_OK if everything goes well, BLIST_LOAD_ERROR if directory cannot be accessed.
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
        return BLIST_LOAD_ERROR;
    }

    while (file = readdir(dp)) {

        if (file->d_name[0] == '.' || file->d_type == 0x4) {
            // exclude hidden files, directory references and recursive directories
            continue;
        }

        in.open(file->d_name, ifstream::in);

        if (!in.is_open()) {
            cerr << "WARNING: File " << file->d_name << " cannot be opened. Will be skipped." << endl;
            continue;
        }

        // load file line by line
        while (!in.eof()) {
            getline(in, line);

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
            
            // hash the URL
            upd.url_hash = SuperFastHash(url_norm, strlen(url_norm));
            delete url_norm;
            // fill blacklist number
            upd.bl = strtoul(file->d_name, NULL, 0);
            if (upd.bl == 0x0) {
                cerr << "WARNING: Cannot determine source blacklist. Will be skipped." << endl;
                in.close();
                break;
            }
            // add/update or remove ?
            if (add_rem) {
                rm_upd.push_back(upd);
            } else {
                add_upd.push_back(upd);
            }
        }
        in.close();
    }

    closedir(dp);
    return ALL_OK;
}

/**
 * Function for checking the URL.
 * Function gets the UniRec record with URL to check and tries to find it 
 * in the given blacklist. If the function succeedes then the appropriate 
 * field in detection record is filled with the number of blacklist asociated 
 * with the URL. If the URL is clean nothing is done.
 *
 * @param blacklist Blacklist used for checking.
 * @param in Template of input UniRec (record).
 * @param out Template of output UniRec (detect).
 * @param record Record with URL for checking.
 * @param detect Record for reporting detection of blacklisted URL.
 * @return BLACKLISTED if the address is found in table, URL_CLEAR otherwise.
 */
int check_blacklist(cc_hash_table_t& blacklist, ur_template_t* in, ur_template_t* out, const void* record, void* detect)
{
    // get pointer to URL
    char* url = ur_get_dyn(in, record, UR_URL);

    uint8_t* bl = NULL;

    // hash the recieved URL
    uint32_t hash_url = SuperFastHash(url, ur_get_dyn_size(in, record, UR_URL));

    // try to find the URL in table.
    bl = (uint8_t *) ht_get(&blacklist, (char *) &hash_url);

    if (bl != NULL) {
        // we found this URL in blacklist -- fill the detection record
        // ur_set(out, detect, /* UR_URL_BLACKLIST */);
        return BLACKLISTED;
    }

    // URL was not found
    return URL_CLEAR;
}

/**
 * Function for updating the blacklist (remove).
 * Function removes all items specified in the vector of updates from 
 * the table since these items are no longer valid.
 *
 * @param blacklist Blacklist to be updated.
 * @param rm Vector with items to remove.
 */
static void update_remove(cc_hash_table_t& blacklist, vector<upd_item_t>& rm)
{
    for (int i = 0; i < rm.size(); i++) {
        ht_remove_by_key(&blacklist, (char *) &rm[i].url_hash);
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
static void update_add(cc_hash_table_t& blacklist, vector<upd_item_t>& add)
{
    int bl_index;
    for (int i = 0; i < add.size(); i++) {
        if ((bl_index = ht_get_index(&blacklist, (char *) &add[i].url_hash)) >= 0) {
            *((uint8_t *) blacklist.table[bl_index].data) = add[i].bl;
        } else {
            ht_insert(&blacklist, (char *) &add[i].url_hash, &add[i].bl);
        }
    }
}

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{

    int retval = 0; // return value

    cc_hash_table_t blacklist;

    ht_init(&blacklist, BLACKLIST_DEF_SIZE, sizeof(uint8_t), sizeof(uint32_t), REHASH_ENABLE);

    ur_template_t* templ = ur_create_template("<COLLECTOR_FLOW>,URL");
    ur_template_t* det = ur_create_template("<COLLECTOR_FLOW>");

    // zero dynamic size for now may change in future if URL will be passed.
    void *detection = ur_create(det, 0);

    if (detection == NULL) {
        cerr << "ERROR: No memory available for detection record. Unable to continue." << endl;
        ur_free_template(templ);
        ur_free_template(det);
        return EXIT_FAILURE;
    }
    
    // initialize TRAP interface (nothing special is needed so we can use the macro
    TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

    // check if the directory with URLs is specified
    if (argc != 2) {
        cerr << "ERROR: Directory with sources not specified. Unable to continue." << endl;
        ht_destroy(&blacklist);
        ur_free_template(templ);
        ur_free_template(det);
        ur_free(detection);
        trap_finalize();
        return EXIT_FAILURE;
    }

    // load source files
    const char* source = argv[1];
    setlocale(LC_ALL, "");
    retval = load_url(blacklist, source);

    if (retval = BLIST_LOAD_ERROR) {
        ht_destroy(&blacklist);
        ur_free_template(templ);
        ur_free_template(det);
        ur_free(detection);
        trap_finalize();
        return EXIT_FAILURE;
    }

    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    const void *data;
    uint16_t data_size;

    // update vectors
    vector<upd_item_t> add_update;
    vector<upd_item_t> rm_update;
    
    // ***** Main processing loop *****
    while (!stop) {
               
        // retrieve data from server
        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval, continue, break);

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

        // check for blacklist match
        retval = check_blacklist(blacklist, templ, det, data, detection);

        // is blacklisted? send report
        if (retval == BLACKLISTED) {
            trap_send_data(0, data, ur_rec_size(det, detection), TRAP_HALFWAIT);
        }

        // should update?
        if (update) {
            retval = load_update(add_update, rm_update, source);

            if (retval = BLIST_LOAD_ERROR) {
                cerr << "WARNING: Unable to load updates. Will use old table instead." << endl;
                update = 0;
                continue;
            }
            
            if (!rm_update.empty()) {
                update_remove(blacklist, rm_update);
            }
            if (!add_update.empty()) {
                update_add(blacklist, add_update);
            }

            rm_update.clear();
            add_update.clear();
            update = 0;       
        }

    }

    // send terminate message
    trap_send_data(0, data, 1, TRAP_HALFWAIT);

    // clean up before termination

    ur_free_template(templ);
    ur_free_template(det);
    ur_free(detection);
    ht_destroy(&blacklist);
    trap_finalize();

    return EXIT_SUCCESS;
}
