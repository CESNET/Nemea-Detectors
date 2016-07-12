/**
 * \file urlblacklistfilter.cpp
 * \brief Main module for URLBlackLIstDetector.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Erik Sabik, <xsabik02@stud.fit.vutbr.cz>
 * \date 2013
 * \date 2014
 * \date 2016
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
#include <nemea-common.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "../blacklist_downloader/blacklist_downloader.h"
#include "fields.h"
#ifdef __cplusplus
}
#endif

#include "patternstrings.h"
#include "urlblacklistfilter.h"



#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, "DEBUG: "  __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif


/**
 * Register allocated unirec template.
 */
#define REGISTER_UR_TEMPLATE(tmpl_name) do { ALLOCATED_UR_TEMPLATES.push_back(&tmpl_name); } while(0)

/**
 * Free all allocatd unirec templates.
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
  string HTTP_SDM_REQUEST_HOST,
  string HTTP_SDM_REQUEST_REFERER,
  string HTTP_SDM_REQUEST_URL,
  string HTTP_REQUEST_HOST,
  string HTTP_REQUEST_REFERER,
  string HTTP_REQUEST_URL,
  // detection
  uint64 DST_BLACKLIST,               //ID of blacklist which contains recieved URL
)




using namespace std;

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("URLBlacklistFilter", "Module receives the UniRec record and checks if the HTTP Host field" \
    "is present in any blacklist that are available. " \
    "If HTTP Host field is present in any blacklist the record is changed by adding " \
    "a identification number of the list which blacklisted the HTTP Host field and " \
    "a number specifying intensity of the communication between those addresses. Unirec records " \
    "are aggregated by source,destination address and protocol for a given time. After this time " \
    "aggregated UniRec is sent by output interface. " \
    "This module uses configurator tool. To specify file with blacklist URL addresses or public " \
    "blacklists, use XML configuration file for IPBlacklistFilter (userConfigurationFile.xml). " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bld_userConfigurationFile.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "", "Specify user configuration file for URLBlacklistFilter. [Default: " SYSCONFDIR "/urlblacklistfilter/userConfigurationFile.xml]", required_argument, "string") \
  PARAM('U', "", "Specify user configuration file for blacklist downloader. [Default: " SYSCONFDIR "/urlblacklistfilter/bld_userConfigurationFile.xml]", required_argument, "string") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none") \
  PARAM('S', "", "Switch to SDM version of HTTP fields.", no_argument, "none")

/* AGGREGATION IS NOT YET IMPLEMENTED
  PARAM('A', "", "Specify active timeout in seconds. [Default: 300]", required_argument, "uint32") \
  PARAM('I', "", "Specify inactive timeout in seconds. [Default: 30]", required_argument, "uint32") \
  PARAM('s', "", "Size of aggregation hash table. [Default: 500000]", required_argument, "uint32") \
*/


static int stop = 0; // global variable for stopping the program
static int update = 0; // global variable for updating blacklists

static bool sdm_fields_flag = false;


vector<ur_template_t**> ALLOCATED_UR_TEMPLATES;


/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


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
    string host, host_url;

    // Skip flows with empty HTTP host
    if (sdm_fields_flag) {
       if (ur_get_var_len(in, record, F_HTTP_SDM_REQUEST_HOST) == 0) {
          return URL_CLEAR;
       }
    } else {
       if (ur_get_var_len(in, record, F_HTTP_REQUEST_HOST) == 0) {
          return URL_CLEAR;
       }
    }

    if (sdm_fields_flag) {
        host = string(ur_get_ptr(in, record, F_HTTP_SDM_REQUEST_HOST), ur_get_var_len(in, record, F_HTTP_SDM_REQUEST_HOST));
        host_url = host + string(ur_get_ptr(in, record, F_HTTP_SDM_REQUEST_URL), ur_get_var_len(in, record, F_HTTP_SDM_REQUEST_URL));
    } else {
        host = string(ur_get_ptr(in, record, F_HTTP_REQUEST_HOST), ur_get_var_len(in, record, F_HTTP_REQUEST_HOST));
        host_url = host + string(ur_get_ptr(in, record, F_HTTP_REQUEST_URL), ur_get_var_len(in, record, F_HTTP_REQUEST_URL));
    }
 
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
        DEBUG_PRINT("Detectec blacklisted URL: '%s'\n", host_url.c_str());
        ur_set(out, detect, F_DST_BLACKLIST, bl_id);
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
   for (unsigned int i = 0; i < rm.size(); i++) {
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
    for (unsigned int i = 0; i < add.size(); i++) {
        blacklist.insert(pair<string, uint64_t>(add[i].url, add[i].bl));
    }
    return 1;
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
   args->update_mode     = DEFAULT_UPDATE_MODE;//down_config.update_mode;
   args->line_max_length = down_config->line_max_len;
   args->el_max_length   = down_config->element_max_len;
   args->el_max_count    = down_config->element_max_cnt;
}


/**
 * \brief Read configuration file and initialize both configurator
 *        and blacklist downloader.
 * \param patternFile
 * \param userFile
 * \param down_config
 * \param patternType
 * \return True on success, false otherwise.
 */
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
    //int hash_table_size = 100000;
    blacklist_map_t blacklist;
    black_list_t add_update;
    black_list_t rm_update;

    // Set defaukt files names
    char *userFile = (char*) SYSCONFDIR "/ipblacklistfilter/userConfigFile.xml";
    char *bld_userFile = (char*) SYSCONFDIR "/ipblacklistfilter/bld_userConfigFile.xml";

    // set locale so we can use URL normalization library
    setlocale(LC_ALL, "");


    // ***** Initialize TRAP *****
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
    trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT);


    // ********** Parse arguments **********
    int opt;
    string file, bl_str;
    int bl_mode = BL_STATIC_MODE; // default mode 
    while ((opt = getopt(argc, argv, "Snau:U:")) != -1) {
        switch (opt) {
            case 'u': // user configuration file for IPBlacklistFilter
                userFile = optarg;
                break;
            case 'U': // user configuration file for blacklist downlooader
                bld_userFile = optarg;
                break;
            case 'n': // Do not send terminating Unirec
                send_terminating_unirec = 0;
                break;
            /*case 'A': // Active timeout
                TIMEOUT_ACTIVE = atoi(optarg);
                break;
            case 'I': // Inactive timeout
                TIMEOUT_INACTIVE = atoi(optarg);
                break;
            case 's': // FHT table size
                hash_table_size = atoi(optarg);
                break;*/
            case 'S': // Switch to SDM version of HTTP fields
                sdm_fields_flag = true;
                break;
            case '?':
                if (optopt == 'I' || optopt == 'A' || optopt == 's') {
                    fprintf (stderr, "ERROR: Option -%c requires an argumet.\n", optopt);
                } else {
                    fprintf (stderr, "ERROR: Unknown option -%c.\n", optopt);
                }
                FINALIZE_MODULE();
                return EXIT_FAILURE;
        }
    }


    // ***** Create Unirec templates ******
    char *errstr = NULL;
    ur_template_t* templ;
    ur_template_t* det;
    if (sdm_fields_flag) {
        templ = ur_create_input_template(0,"DST_IP,SRC_IP,TIME_FIRST,TIME_LAST,HTTP_SDM_REQUEST_HOST,HTTP_SDM_REQUEST_REFERER,HTTP_SDM_REQUEST_URL", &errstr);
        DEFAULT_UR_CREATE_ERROR_HANDLING(templ, errstr, FINALIZE_MODULE())
        det = ur_create_output_template(0,"DST_IP,SRC_IP,TIME_FIRST,TIME_LAST,HTTP_SDM_REQUEST_HOST,HTTP_SDM_REQUEST_REFERER,HTTP_SDM_REQUEST_URL,DST_BLACKLIST", &errstr);
        DEFAULT_UR_CREATE_ERROR_HANDLING(det, errstr, ur_free_template(templ); FINALIZE_MODULE())
    } else {
        templ = ur_create_input_template(0,"DST_IP,SRC_IP,TIME_FIRST,TIME_LAST,HTTP_REQUEST_HOST,HTTP_REQUEST_REFERER,HTTP_REQUEST_URL", &errstr);
        DEFAULT_UR_CREATE_ERROR_HANDLING(templ, errstr, FINALIZE_MODULE())
        det = ur_create_output_template(0,"DST_IP,SRC_IP,TIME_FIRST,TIME_LAST,HTTP_REQUEST_HOST,HTTP_REQUEST_REFERER,HTTP_REQUEST_URL,DST_BLACKLIST", &errstr);
        DEFAULT_UR_CREATE_ERROR_HANDLING(det, errstr, ur_free_template(templ); FINALIZE_MODULE())
    }
    void *detection = ur_create_record(det, 2048);


   // Allocate memory for configuration
   downloader_config_struct_t *down_config = (downloader_config_struct_t *) malloc(sizeof(downloader_config_struct_t));
   if (down_config == NULL) {
      cerr << "Error: Could not allocate memory for configuration structure." << endl;
      FINALIZE_MODULE();
      return EXIT_FAILURE;
   }

   // Load configuration
   if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, down_config, CONF_PATTERN_STRING)) {
      cerr << "Error: Could not parse XML configuration." << endl;
      FINALIZE_MODULE();
      return EXIT_FAILURE;
   }



   // Set additional variables from userConfiguration
   if (strcmp(down_config->update_mode, "dynamic") == 0) {
      bl_mode = BL_DYNAMIC_MODE;
   }


   // ***** Initialize Blacklist Downloader *****
   if (bl_mode == BL_DYNAMIC_MODE) {
      // Load configuration for BLD
      if (!initialize_downloader(BLD_CONFIG_PATTERN_STRING, bld_userFile, down_config, CONF_PATTERN_STRING)) {
         //fht_destroy(AGGR_TABLE);
         FINALIZE_MODULE();
         return EXIT_FAILURE;
      }
   }


    // Load URLs from file
    file = down_config->file;
    if (load_update(add_update, rm_update, file) == BLIST_LOAD_ERROR) {
        if (bl_mode == BL_DYNAMIC_MODE) {
           bld_finalize();
        }
        FINALIZE_MODULE();
        return EXIT_FAILURE;
    }

    // Add initial update
    if (!add_update.empty()) {
       if (!update_add(blacklist, add_update)) {
          fprintf(stderr, "Update failed\n");
          if (bl_mode == BL_DYNAMIC_MODE) {
              bld_finalize();
          }
            FINALIZE_MODULE();
          return EXIT_FAILURE;
       }
    } else {
        cerr << "No addresses were loaded. Continuing makes no sense." << endl;
        if (bl_mode == BL_DYNAMIC_MODE) {
           bld_finalize();
        }
        FINALIZE_MODULE();
        return EXIT_FAILURE;
    }
    add_update.clear();
    rm_update.clear();


    // ***** Create thread for Inactive timeout checking *****
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
        retval = check_blacklist(blacklist, templ, det, data, detection);

        // is blacklisted? send report
        if (retval == BLACKLISTED) {
            ur_copy_fields(det, detection, templ, data);
            trap_send(0, detection, ur_rec_size(det, detection));
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

            if (!rm_update.empty()) {
                update_remove(blacklist, rm_update);
            }
            if (!add_update.empty()) {
                update_add(blacklist, add_update);
            }

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
    if (send_terminating_unirec) {
        trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_NO_WAIT);
        trap_send(0, {0}, 1);
    }

    // clean up before termination
    ur_free_record(detection);
    FINALIZE_MODULE();


    return EXIT_SUCCESS;
}
