/**
 * \file urlblacklistfilter.cpp
 * \brief Main module for URLBlackLIstDetector.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Erik Sabik, <xsabik02@stud.fit.vutbr.cz>
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
#include <cstdlib>
#include <clocale>
#include <stdint.h>
#include <signal.h>
#include <dirent.h>
#include <idna.h>
#include <unistd.h>



#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#include "../blacklist_downloader/blacklist_downloader.h"
#include "fields.c"
#ifdef __cplusplus
}
#endif

#include "urlblacklistfilter.h"

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
  //HTTP
  string HTTP_REQUEST_HOST,          //HTTP request host
  string HTTP_REQUEST_URL,           //HTTP request url
  //other
  uint8 URL_BLACKLIST,               //ID of blacklist which contains recieved URL
)

//#define DEBUG 1

using namespace std;

trap_module_info_t module_info = {
    (char *)"URL blacklist detection module", // Module name
    // Module description
    (char *)"Module recieves the UniRec record and checks if the URL in record isn't\n"
    "present in any blacklist that are available. If so the module creates\n"
    "a detection report (UniRec) with blacklist where the URL was found.\n"
    "The report is the send to further processing.\n"
    "Usage:\n"
    "\t./ipblacklistfilter -i <trap_interface> -f <file> [-D blacklists] [-n]\n"
    "Module specific parameters:\n"
    "   -f file         Specify file with blacklisted IP URLs.\n"
    "   -D list         Switch to dynamic mode and specify which blacklists to use.\n"
    "   -n              Do not send terminating Unirec when exiting program.\n"
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
    }
}

/**
 *
 */
void check_update()
{
   bld_lock_sync();
   update = BLD_SYNC_FLAG;
   bld_unlock_sync();
}



/**
 * Function for loading source files.
 * Function gets path to the directory with source files and use these to fill the
 * given blacklist with URLs. Since URL can have variable length its hashed first
 * and this hash used in blacklist for all operations.
 *
 * @param blacklist Blacklist table to be filled.
 * @param file Path to the file with sources.
 * @return BLIST_LOAD_ERROR if directory cannot be accessed, ALL_OK otherwise.
 */
int load_update(black_list_t &add_update, black_list_t &rm_update, string &file)
{
    ifstream input; // data input

    string line, url, bl_flag_str;
    char *url_norm;
    int ret;
    uint64_t bl_flag;
    int line_num = 0;

    size_t str_pos;

    url_blist_t bl_entry; // black list entry associated with ip address

    bool add_rem = false; // add or remove from table ?

    input.open(file.c_str(), ifstream::in);

    if (!input.is_open()) {
        cerr << "WARNING: File " << file << " cannot be opened!" << endl;
        return BLIST_LOAD_ERROR;
    }

    // load file line by line
    while (!input.eof()) {
        getline(input, line);
        line_num++;

        // trim all white spaces (if any)
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());

        // transform all letters to lowercase (if any)
        transform(line.begin(), line.end(), line.begin(), ::tolower);

        // encountered a remove line?
        if (line == "#remove") {
            add_rem = true; // switch to remove mode
            continue;
        }

        // Skip empty lines
        if (!line.length()) {
            continue;
        }

        // find URL-blacklist separator
        str_pos = line.find_first_of(',');
        if (str_pos == string::npos) {
           // Blacklist index delimeter not found (bad format?), skip it
           cerr << "WARNING: File '" << file << "' has bad formated line number '" << line_num << "'" << endl;
           continue;
        }

        // Parse blacklist ID
        bl_flag = strtoull((line.substr(str_pos + 1, string::npos)).c_str(), NULL, 10);

        // Parse URL
        url = line.substr(0, str_pos);
        ret = idna_to_ascii_lz(url.c_str(), &url_norm, 0);
        if (ret != IDNA_SUCCESS) {
#ifdef DEBUG
            cerr << "Unable to normalize URL. Will skip." << endl;
#endif
            continue;
        }

        // store normalized url
        bl_entry.url = url_norm;

        // store blacklist
        bl_entry.bl = bl_flag;

        // put entry into its respective update list
        if (!add_rem) {
            add_update.push_back(bl_entry);
        } else {
            rm_update.push_back(bl_entry);
        }

        free(url_norm);
    }
    input.close();

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
int check_blacklist(blacklist_map_t &blacklist, ur_template_t *in, ur_template_t *out, const void *record, void *detect)
{
   uint64_t host_id, host_url_id, bl_id;

    // Skip flows with empty HTTP host
    if (ur_get_var_len(in, record, F_HTTP_REQUEST_HOST) == 0) {
       return URL_CLEAR;
    }

    string host = string(ur_get_ptr(in, record, F_HTTP_REQUEST_HOST), ur_get_var_len(in, record, F_HTTP_REQUEST_HOST));
    string host_url = host.append(string(ur_get_ptr(in, record, F_HTTP_REQUEST_URL), ur_get_var_len(in, record, F_HTTP_REQUEST_URL)));

    // Strip / (slash) from URL if it is last character
    if (host_url[host_url.length() - 1] == '/') {
        host_url.resize(host_url.length() - 1);
    }

    // Find URL in map
    blacklist_map_t::iterator host_check = blacklist.find(host);
    blacklist_map_t::iterator host_url_check = blacklist.find(host_url);

    // Get detected blacklist ids and merge them together
    host_id     = host_check     != blacklist.end() ? host_check->second : 0;
    host_url_id = host_url_check != blacklist.end() ? host_url_check->second : 0;
    bl_id       = host_id | host_url_id;

    if (bl_id != 0) {
        // we found this URL in blacklist -- fill the detection record
        ur_set(out, detect, F_URL_BLACKLIST, bl_id);
//#ifdef DEBUG
        //cout << "URL \"" << host_url << "\" has been found in blacklist." << endl;
//#endif
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
static void update_remove(blacklist_map_t &blacklist, black_list_t &rm)
{
   for (int i = 0; i < rm.size(); i++) {
      blacklist.erase(rm[i].url);
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
static int  update_add(blacklist_map_t &blacklist, black_list_t &add)
{
   for (int i = 0; i < add.size(); i++) {
      blacklist.insert(pair<string, uint64_t>(add[i].url, add[i].bl));
    }
}

static void setup_downloader(bl_down_args_t *args, const char *file, const char *b_str)
{
   uint64_t sites;
   uint8_t num = bl_translate_to_id((char*)b_str, &sites);

   args->use_regex = (uint8_t*)malloc(sizeof(uint8_t) * num);
   args->reg_pattern = (char**)malloc(sizeof(char *) * num);
   args->comment_ar = (char*)malloc(sizeof(char) * num);

   for (int i = 0; i < num; i++) {
      args->comment_ar[i] = '#';
      args->use_regex[i] = 1;
      args->reg_pattern[i] = strdup(URL_REGEX);
   }

   args->sites      = sites;
   args->file       = (char*)file;
   args->num        = num;
   args->delay      = 3600;
   args->update_mode     = DIFF_UPDATE_MODE;
   args->line_max_length = 1024;
   args->el_max_length   = 256;
   args->el_max_count    = 50000;
}



/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{
    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGUSR1, signal_handler);

    bl_down_args_t bl_args;
    int retval = 0; // return value
    int send_terminating_unirec = 1;

    //cc_hash_table_t blacklist;
    blacklist_map_t blacklist;

    // Update lists
    black_list_t add_update;
    black_list_t rm_update;

    // Unirec templates
    char *errstr = NULL;
    ur_template_t* templ = ur_create_input_template(0,"SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL,HTTP_REQUEST_HOST,HTTP_REQUEST_URL,HTTP_REQUEST_REFERER", &errstr);
    if (templ == NULL) {
      cerr << "Error: Invalid UniRec specifier." << endl;
      if(errstr != NULL){
        fprintf(stderr, "%s\n", errstr);
        free(errstr);
      }
      trap_finalize();
      return EXIT_FAILURE;
    }
    ur_template_t* det = ur_create_output_template(0,"SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD,TOS,TTL,URL_BLACKLIST,HTTP_REQUEST_URL,HTTP_REQUEST_HOST", &errstr); // + BLACKLIST_TYPE
    if (det == NULL) {
      cerr << "Error: Invalid UniRec specifier." << endl;
      if(errstr != NULL){
        fprintf(stderr, "%s\n", errstr);
        free(errstr);
      }
      ur_free_template(templ);
      trap_finalize();
      return EXIT_FAILURE;
    }
    void *detection = ur_create_record(det, 2048);

    // initialize TRAP interface (nothing special is needed so we can use the macro)
    TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);

    // set locale so we can use URL normalization library
    setlocale(LC_ALL, "");

    int opt;
    string file, bl_str;
    int bl_mode = BL_STATIC_MODE; // default mode

    // ********** Parse arguments **********
    while ((opt = getopt(argc, argv, "nD:f:")) != -1) {
        switch (opt) {
            case 'D': // Dynamic mode
                      bl_mode = BL_DYNAMIC_MODE;
                      bl_str = string(optarg);
                      break;
            case 'f': // Specify file with blacklisted IPs
                      file = string(optarg);
                      break;
            case 'n': // Do not send terminating Unirec
                      send_terminating_unirec = 0;
                      break;
        }
    }

    // ***** Check module arguments *****
    if (file.length() == 0) {
        fprintf(stderr, "Error: Parameter -f is mandatory.\nUsage: %s -i <trap_interface> -f <file> [-D]\n", argv[0]);
        ur_free_template(templ);
        ur_free_template(det);
        trap_terminate();
        trap_finalize();
        return EXIT_FAILURE;
    }
    if (bl_mode == BL_DYNAMIC_MODE && bl_str.length() == 0) {
        fprintf(stderr, "Error: Parameter -D needs argument.\nUsage: %s -i <trap_interface> -f <file> [-D <blacklists>]\n", argv[0]);
        ur_free_template(templ);
        ur_free_template(det);
        trap_terminate();
        trap_finalize();
        return EXIT_FAILURE;
    }


    // Initialize blacklist downloader
    if (bl_mode == BL_DYNAMIC_MODE) {
       setup_downloader(&bl_args, file.c_str(), bl_str.c_str());
       if (bl_args.sites == 0) {
           fprintf(stderr, "Error: No blacklists were specified!\n");
           ur_free_template(templ);
           ur_free_template(det);
           trap_terminate();
           trap_finalize();
           return EXIT_FAILURE;
        }
       int ret = bl_down_init(&bl_args);
       if (ret < 0) {
           fprintf(stderr, "Error: Could not initialize downloader!\n");
           return 1;
       } else {
           while (!update) {
               sleep(1);
               if (stop) {
                  ur_free_template(templ);
                  ur_free_template(det);
                  trap_finalize();
                  fprintf(stderr, "Quiting before first update\n");
                  bld_finalize();
                  return EXIT_FAILURE;
               }
               cout << "Checking signal value\n";
               check_update();
           }
           update = 0;
       }
    }

    // Load URLs from file
    retval = load_update(add_update, rm_update, file);

    if (retval == BLIST_LOAD_ERROR) {
        trap_terminate();
        trap_finalize();
        ur_free_template(templ);
        ur_free_template(det);
        if (bl_mode == BL_DYNAMIC_MODE) {
           bld_finalize();
        }
        return EXIT_FAILURE;
    }

    // Add initial update
    if (!add_update.empty()) {
       if (!update_add(blacklist, add_update)) {
          fprintf(stderr, "Update failed\n");
          if (bl_mode == BL_DYNAMIC_MODE) {
              bld_finalize();
          }
          return EXIT_FAILURE;
       }
    } else {
        cerr << "No addresses were loaded. Continuing makes no sense." << endl;
        trap_terminate();
        trap_finalize();
        ur_free_template(templ);
        ur_free_template(det);
        if (bl_mode == BL_DYNAMIC_MODE) {
           bld_finalize();
        }
        return EXIT_FAILURE;



    }
    add_update.clear();
    rm_update.clear();

    // Create thread for Inactive timeout checking
    /*pthread_t inactive_timeout_thread_id;
    if (pthread_create(&inactive_timeout_thread_id, NULL, &inactive_timeout_thread_func, tmpl_det)) {
       fprintf(stderr, "ERROR: Could not create inactive timeout flush thread.\n");
       ur_free_record(detection);
       ur_free_template(templ);
       ur_free_template(tmpl_det);
       fht_destroy(AGGR_TABLE);
       ht_destroy(&hash_blacklist);
       trap_finalize();
       return EXIT_SUCCESS;
    }*/


    const void *data;
    uint16_t data_size;

    // ***** Main processing loop *****
    while (!stop) {

        // retrieve data from server
        retval = TRAP_RECEIVE(0, data, data_size, templ);
        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval, continue, break);
#ifdef DEBUG
        int dyn_size = ur_rec_varlen_size(templ, data);
#endif

        // check the data size -- we can only check static part since URL is dynamic
        if ((data_size - ur_rec_varlen_size(templ,data)) != ur_rec_fixlen_size(templ)) {
            if (data_size <= 1) { // end of data
                break;
            } else { // data corrupted
                cerr << "ERROR: Wrong data size. ";
                cerr << "Expected: " << ur_rec_fixlen_size(templ) << " ";
                cerr << "Recieved: " << data_size - ur_rec_varlen_size(templ,data) << " in static part." << endl;
                break;
            }
        }

#ifdef DEBUG
        ++recieved;
#endif

        // check for blacklist match
        retval = check_blacklist(blacklist, templ, det, data, detection);

        // is blacklisted? send report

        if (retval == BLACKLISTED) {
#ifdef DEBUG
            ++marked;
#endif
            ur_copy_fields(det, detection, templ, data);
            trap_send_data(0, detection, ur_rec_size(det, detection), TRAP_HALFWAIT);
        }

        // should update?
        //cout << "Checking update";
        fflush(stdout);
        bld_lock_sync();
        //cout << "...\n";
        if (BLD_SYNC_FLAG) {
           cout << "Processing update...\n";
            retval = load_update(add_update, rm_update, file);

            if (retval == BLIST_LOAD_ERROR) {
                cerr << "WARNING: Unable to load updates. Will use old table instead." << endl;
                update = 0;
                continue;
            }

#ifdef DEBUG
            cout << "Updating blacklist filter (" << add_update.size() << " additions / " << rm_update.size() << " removals)." << endl;
#endif

            if (!rm_update.empty()) {
                update_remove(blacklist, rm_update);
            }
            if (!add_update.empty()) {
                update_add(blacklist, add_update);
            }

#ifdef DEBUG
            // for debug only -- show content of the new blacklist
            show_blacklist(blacklist);
#endif

            rm_update.clear();
            add_update.clear();
            BLD_SYNC_FLAG = 0;
            cout << "Successfully updated\n";
        }
        bld_unlock_sync();
    }

    cout << "Terminating\n";
    if (bl_mode == BL_DYNAMIC_MODE) {
       bld_finalize();
    }

    // send terminate message
    trap_send_data(0, data, 1, TRAP_NO_WAIT);

    // clean up before termination
    ur_free_template(templ);
    ur_free_template(det);
    ur_free_record(detection);
    trap_finalize();


#ifdef DEBUG
    cout << marked << "/" << recieved << " were marked by blacklist." << endl;
#endif

    return EXIT_SUCCESS;
}
