/**
 * \file urlblacklistfilter.cpp
 * \brief Main module for URLBlackLIstDetector.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Erik Sabik, <xsabik02@stud.fit.vutbr.cz>
 * \author Filip Suster, <sustefil@fit.cvut.cz>
 * \date 2013
 * \date 2014
 * \date 2016
 * \date 2018
 */

/*
 * Copyright (C) 2013,2014,2016 CESNET
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

#include <vector>
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
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif


#ifdef __cplusplus
extern "C" {
#endif
#include <nemea-common/nemea-common.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

#ifdef __cplusplus
}
#endif

#include "patternstrings.h"
#include "urlblacklistfilter.h"
#include "../blacklist_watcher/blacklist_watcher.h"

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif


/**
 * Register allocated unirec template.
 */
#define REGISTER_UR_TEMPLATE(tmpl_name) do { ALLOCATED_UR_TEMPLATES.push_back(&tmpl_name); } while (0)

/**
 * Free all allocated unirec templates.
 */
#define FREE_UR_TEMPLATES() \
{ \
    for (unsigned int i = 0; i < ALLOCATED_UR_TEMPLATES.size(); ++i) { \
        ur_free_template(*ALLOCATED_UR_TEMPLATES[i]); \
    } \
    ALLOCATED_UR_TEMPLATES.clear(); \
}

/**
 * Used for handling errors when creating unirec templates.
 */
#define DEFAULT_UR_CREATE_ERROR_HANDLING(tmpl_name, err_str, commands) \
{ \
    if (tmpl_name == NULL) { \
        fprintf(stderr, "Error: Invalid UniRec specifier.\n"); \
        if (err_str != NULL){ \
            fprintf(stderr, "%s\n", err_str); \
            free(err_str); \
        } \
        commands; \
        return EXIT_FAILURE; \
    } \
    REGISTER_UR_TEMPLATE(tmpl_name); \
} \


/**
 * Used to clean terminate module.
 */
#define FINALIZE_MODULE() \
do  {\
    ; \
    FREE_UR_TEMPLATES(); \
    trap_finalize(); \
    FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS) \
    } while (0)


UR_FIELDS(
  ipaddr SRC_IP,
  ipaddr DST_IP,
  time TIME_FIRST,    //Timestamp of the first packet of a flow
  time TIME_LAST,     //Timestamp of the last packet of a flow
  // HTTP
  string HTTP_HOST,
  string HTTP_REFERER,
  string HTTP_URL,
  // detection
  uint64 DST_BLACKLIST,               //ID of blacklist which contains recieved URL
)

using namespace std;

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("URLBlacklistFilter", "Module receives the UniRec record and checks if the URL (HTTP Host + HTTP Path) " \
    "is present in any blacklist that are available. " \
    "If the URL is present in any blacklist the record is changed by adding an index of the blacklist. " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bld_userConfigurationFile.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "", "Specify user configuration file for URLBlacklistFilter. [Default: " SYSCONFDIR "/urlblacklistfilter/userConfigurationFile.xml]", required_argument, "string") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none") \

static int stop = 0; // global variable for stopping the program
int BL_RELOAD_FLAG = 0;
static bool WATCH_BLACKLISTS_FLAG;

vector<ur_template_t**> ALLOCATED_UR_TEMPLATES;


/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


/**
 * Function for loading source files.
 * Function gets path to the directory with source files and use these to fill the
 * given blacklist with URLs. The URLs are stored in a prefix tree
 * @param tree Prefix tree to be filled.
 * @param file Path to the file with sources.
 * @return BLIST_LOAD_ERROR if directory cannot be accessed, ALL_OK otherwise.
 */
int reload_blacklists(prefix_tree_t **tree, string &file)
{
    // TODO: ineffective, make it work just with diffs
    prefix_tree_destroy(*tree);
    *tree = prefix_tree_initialize(PREFIX, sizeof(info_t), -1, DOMAIN_EXTENSION_NO, RELAXATION_AFTER_DELETE_YES);

    ifstream input; // data input

    string line, url, bl_flag_str;
    const char *url_norm;
    uint64_t bl_flag;
    int line_num = 0;

    size_t str_pos;

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

        // Skip empty lines
        if (!line.length()) {
            continue;
        }

        // find URL-blacklist separator
        str_pos = line.find_first_of('\\');
        if (str_pos == string::npos) {
            // Blacklist index delimeter not found (bad format?), skip it
            cerr << "WARNING: File '" << file << "' has bad formatted line number '" << line_num << "'" << endl;
            continue;
        }

        // Parse blacklist ID
        bl_flag = strtoull((line.substr(str_pos + 1, string::npos)).c_str(), NULL, 10);

        // Parse URL
        url = line.substr(0, str_pos);
        url_norm = url.c_str();

        // TODO: is this necessary? Preprocessing should be done by downloader
//        ret = idna_to_ascii_lz(url.c_str(), &url_norm, 0);
//        if (ret != IDNA_SUCCESS) {
//            cerr << "Unable to normalize URL " << url.c_str() << " Will skip." << endl;
//            continue;
//        }

        prefix_tree_domain_t *elem = prefix_tree_insert(*tree, url_norm, strlen(url_norm));

        if (elem != NULL) {
            info_t *info = (info_t *) elem->value;
            info->bl_id = bl_flag;
        } else {
            cerr << "WARNING: Can't insert element \'" << url_norm << "\' to the prefix tree" << endl;
        }
    }

    DBG((stderr, "URL Blacklists Reloaded.\n"))

    input.close();

    return ALL_OK;
}


/**
 * Function for checking the URL.
 * Function gets the UniRec record with URL to check and tries to find it
 * in the given blacklist. If the function succeeds then the appropriate
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
int check_blacklist(prefix_tree_t *tree, ur_template_t *in, ur_template_t *out, const void *record, void *detect)
{
    string host, host_url;

    if (ur_get_var_len(in, record, F_HTTP_HOST) == 0) {
        return URL_CLEAR;
    }

    host = string(ur_get_ptr(in, record, F_HTTP_HOST), ur_get_var_len(in, record, F_HTTP_HOST));
    host_url = host + string(ur_get_ptr(in, record, F_HTTP_URL), ur_get_var_len(in, record, F_HTTP_URL));

    // Strip / (slash) from URL if it is last character
    while (host_url[host_url.length() - 1] == '/') {
        host_url.resize(host_url.length() - 1);
    }

    prefix_tree_domain_t *domain = prefix_tree_search(tree, host_url.c_str(), host_url.length());

    if (domain != NULL) {
        DBG((stderr, "Detected blacklisted URL: '%s'\n", host_url.c_str()));
        info_t *info = (info_t *) domain->value;
        ur_set(out, detect, F_DST_BLACKLIST, info->bl_id);
        return BLACKLISTED;
    }

    // URL was not found
    return URL_CLEAR;
}


/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{
    int retval = 0;
    int send_terminating_unirec = 1;

    // Set default files names
    char *userFile = (char*) SYSCONFDIR "/urlblacklistfilter/userConfigFile.xml";

    // TODO: Delegate idna functionality to downloader
    // set locale so we can use URL normalization library
//     setlocale(LC_ALL, "");

    // ***** Initialize TRAP *****
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
    trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);


    // ********** Parse arguments **********
    int opt;
    while ((opt = getopt(argc, argv, "nu:")) != -1) {
        switch (opt) {
            case 'u': // user configuration file for URLBlacklistFilter
                userFile = optarg;
                break;
            case 'n': // Do not send terminating Unirec
                send_terminating_unirec = 0;
                break;
            case '?':
                fprintf(stderr, "ERROR: Unknown option -%c.\n", optopt);
                FINALIZE_MODULE();
                return EXIT_FAILURE;
        }
    }


    // ***** Create Unirec templates ******
    char *errstr = NULL;
    ur_template_t *templ;
    ur_template_t *det;

    templ = ur_create_input_template(0,"DST_IP,SRC_IP,TIME_FIRST,TIME_LAST,HTTP_HOST,HTTP_REFERER,HTTP_URL", &errstr);
    DEFAULT_UR_CREATE_ERROR_HANDLING(templ, errstr, FINALIZE_MODULE())
    det = ur_create_output_template(0,"DST_IP,SRC_IP,TIME_FIRST,TIME_LAST,HTTP_HOST,HTTP_REFERER,HTTP_URL,DST_BLACKLIST", &errstr);
    DEFAULT_UR_CREATE_ERROR_HANDLING(det, errstr, ur_free_template(templ); FINALIZE_MODULE())

    void *detection = ur_create_record(det, 2048);

    config_t config;

    if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, &config, CONF_PATTERN_STRING)) {
        std::cerr << "Error: Could not parse XML configuration." << std::endl;
        ur_free_template(templ);
        ur_free_template(det);
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }

    if (strcmp(config.watch_blacklists, "true") == 0) {
        WATCH_BLACKLISTS_FLAG = true;
    } else {
        WATCH_BLACKLISTS_FLAG = false;
    }

    // Load URLs from file
    string bl_file = config.blacklist_file;
    if (reload_blacklists(&tree, bl_file) == BLIST_LOAD_ERROR) {
        FINALIZE_MODULE();
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

        // retrieve data from server
        retval = TRAP_RECEIVE(0, data, data_size, templ);
        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval, continue, break);

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

        // check for blacklist match
        retval = check_blacklist(tree, templ, det, data, detection);

        // is blacklisted? send report
        if (retval == BLACKLISTED) {
            ur_copy_fields(det, detection, templ, data);
            trap_send(0, detection, ur_rec_size(det, detection));
        }

        if (BL_RELOAD_FLAG) {
            // Update blacklists
            DBG((stderr, "Reloading blacklists\n"));
            retval = reload_blacklists(&tree, bl_file);
            if (retval == BLIST_LOAD_ERROR) {
                std::cerr << "ERROR: Unable to load update files. Will use the old tables instead." << std::endl;
                continue;
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
        trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
        trap_send(0, "TERMINATE", 1);
    }

    // clean up before termination
    ur_free_record(detection);
    FINALIZE_MODULE();

    if (WATCH_BLACKLISTS_FLAG)
        pthread_cancel(watcher_thread);

    return EXIT_SUCCESS;
}
