/**
 * \file ipblacklistfilter.cpp
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
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdint.h>
#include <signal.h>
#include <dirent.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif
#include "../../unirec/unirec.h"
#include "urlblacklistfilter.h"
#include "../../common/cuckoo_hash/cuckoo_hash.h"

#define DEBUG 1

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
 * Function for loading source files.
 * Function goes through all files in given directory and loads their content
 * (ip addresses/prefixes) to module's tables/vectors used for IP address
 * classification. Pure addresses are then saved in one hash table (both V4 
 * and V6), prefixes are put into separate vectors for according to their 
 * IP version. Vectors are then sorted for the purpose of binary search.
 * The function also checks whether the record in file is valid ip address 
 * or if the file contains valid data. Invalid records/files are automatically 
 * skipped.
 *
 * @param ip_bl Hash table for storing the addresses.
 * @param source_dir Path to the directory with IP addresses.
 * @return ALL_OK if everything goes well, BLIST_FILE_ERROR if directory cannot be accessed.
 */
int load_url(cc_hash_table_t& blacklist, string& path)
{

    DIR* dp;
    struct dirent *file;

    ifstream in;

    string line;
    uint32_t hashed_url;
    uint8_t bl;

    dp = opendir(path.c_str());

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

        while (!in.eof()) {
            getline(in, line);

            /*TODO: hash the url*/
            // hashed_url = sfhash(...)

            bl = strtoul(file->d_name, NULL, 0);
            if (bl == 0x0) {
                cerr << "WARNING: Cannot determine source blacklist. Will be skipped." << endl;
                in.close();
                break;
            }

            // insert to table
            ht_insert(&blacklist, (char *)  &hashed_url, &bl);
        }
        in.close();
    }

    closedir(dp);
    return ALL_OK;
}

/*
 * Function for loading updates.
 * Function goes through all files in given directory and loads their content
 * (ip addresses/prefixes) for updating its classification tables. Records are 
 * sorted to two update lists based on adding/removal operation. These list are 
 * used for both V4 and V6 addresses and both for pure addresses and prefixes.
 * The function also checks whether the record in file is valid ip address 
 * or if the file contains valid data. Invalid records/files are automatically 
 * skipped.
 *
 * @param update_list_a Vector with entries that will be added or updated.
 * @param update_list_rm Vector with entries that will be removed.
 * @param path Path to the directory with updates.
 * @return ALL_OK if everything goes well, BLIST_FILE_ERROR if directory cannot be accessed.
 */
int load_update()
{
    return ALL_OK;
}

int check_blacklist(cc_hash_table_t& blacklist, ur_template_t* in, ur_template_t* out, const void* record, void* detect)
{
    char* url = ur_get_dyn(in, record, UR_URL);

    uint8_t* bl = NULL;
/*    uint32_t hash_url = sfhash(...); */
//    bl = ht_get(&blacklist, hash_url);

    if (bl = NULL) {
        // mark url
        return BLACKLISTED;
    }
    return URL_CLEAR;
}

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{

    int retval = 0; // return value

    cc_hash_table_t blacklist;

    ht_init(&blacklist, BLACKLIST_DEF_SIZE, sizeof(uint8_t), sizeof(uint32_t));

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

    TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

    if (argc != 2) {
        cerr << "ERROR: Directory with sources not specified. Unable to continue." << endl;
        ht_destroy(&blacklist);
        ur_free_template(templ);
        ur_free_template(det);
        ur_free(detection);
        trap_finalize();
        return EXIT_FAILURE;
    }

    string source = string(argv[1]);
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
            // update blacklists
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
