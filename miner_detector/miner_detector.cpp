/**
 * \file miner_detector.cpp
 * \brief Nemea module for detecting bitcoin miners.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2016
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

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <nemea-common.h>
#include <ctype.h>
#include "fields.h"
#include "miner_detector.h"
#include "utils.h"
#include "sender.h"

#include <algorithm>
#include <iostream>
#include <fstream>
#include <map>
#include <string>



//#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, "DEBUG: "  __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif


using namespace std;



fht_table_t *BLACKLIST_DB;
fht_table_t *WHITELIST_DB;
fht_table_t *SUSPECT_DB;
pthread_t MINER_DETECTOR_CHECK_THREAD_ID;
uint32_t CURRENT_TIME;
bool CHECK_STRATUM_FLAG;

const char *BL_STORE_FILE;
const char *WL_STORE_FILE;
uint32_t TIMEOUT_INACTIVE;
uint32_t TIMEOUT_EXPORT;
uint32_t CHECK_THREAD_SLEEP_PERIOD;
uint32_t SUSPECT_SCORE_THRESHOLD;
uint32_t SUSPECT_DB_SIZE;
uint32_t SUSPECT_DB_STASH_SIZE;
uint32_t WHITELIST_DB_SIZE;
uint32_t WHITELIST_DB_STASH_SIZE;
uint32_t BLACKLIST_DB_SIZE;
uint32_t BLACKLIST_DB_STASH_SIZE;




extern int STOP;
extern Sender *SENDER;



/**
 * \brief Reads IP addresses with ports from specified file into database.
 * \param db    Database to read data into.
 * \param fname Name of the file from which to read.
 * \return True on success, False otherwise.
 */
void create_db_from_file(fht_table_t *db, string fname)
{
    list_key_t key;

    uint8_t value = 1;
    fstream fin;
    fin.open(fname.c_str(), ios::in);

    while (fin.good()) {
        string line;
        string ip;
        uint16_t port;

        getline(fin, line);

        size_t delim_pos = line.find(':');
        if (delim_pos == string::npos) {
            // No port specified
            ip = line;
            port = 0;
        } else {
            // IP:port
            ip = line.substr(0, delim_pos);
            port = strtol(line.substr(delim_pos + 1).c_str(), NULL, 10);
        }

        // Trim whitespaces from IP string and check its length
        ip.erase(remove_if(ip.begin(), ip.end(), ::isspace), ip.end());
        if (ip.size() == 0) {
            continue; // Ignore zero size lines
        }

        memset(&key, 0, sizeof(list_key_t));
        //key.ip = convert_string_to_unirec_ip(ip);
        ip_from_str(ip.c_str(), &key.ip);
        key.port = port;

        // Insert into db
        int ret = fht_insert(db, &key, &value, NULL, NULL);
        switch (ret) {
            case FHT_INSERT_OK:     // Insert was successfull
                                    break;
            case FHT_INSERT_LOST:   // Insert kicked out item
                                    DEBUG_PRINT("Not enough space to store items in DB when reading from input file.\n");
                                    break;
            case FHT_INSERT_FAILED: // Item with same key is already in the table, this can not happen or can?
                                    DEBUG_PRINT("Item '%s:%u' has multiple occurrences in input file.\n", ip.c_str(), port);
                                    break;
        }
    }
    fin.close();
}


/**
 * \brief Initialize suspect database.
 * \return True on success, false otherwise.
 */
bool initialize_suspect_db(void)
{
    if ((SUSPECT_DB = fht_init(SUSPECT_DB_SIZE, sizeof(suspect_item_key_t), sizeof(suspect_item_t), SUSPECT_DB_STASH_SIZE)) == NULL) {
        return false;
    } else {
        return true;
    }
}

/**
 * \brief Initialize whitelist database.
 * \return True on success, false otherwise.
 */
bool initialize_whitelist_db(void)
{
    if ((WHITELIST_DB = fht_init(WHITELIST_DB_SIZE, sizeof(list_key_t), sizeof(uint8_t), WHITELIST_DB_STASH_SIZE)) == NULL) {
        return false;
    } else {
        return true;
    }
}

/**
 * \brief Initialize whitelist database.
 * \return True on success, false otherwise.
 */
bool initialize_blacklist_db(void)
{
    if ((BLACKLIST_DB = fht_init(BLACKLIST_DB_SIZE, sizeof(list_key_t), sizeof(uint8_t), BLACKLIST_DB_STASH_SIZE)) == NULL) {
        return false;
    } else {
        return true;
    }
}





/**
 * \brief Compute score of suspect, higher value means higher chance of suspect
 *        being miner.
 * \param s Structure containg suspect aggregated flow information.
 * \return Score of the suspect.
 */
uint32_t compute_suspect_score(suspect_item_t &s)
{
    // ACK+ACKPUSH >= 80%       MEDIUM    2
    // 50 < BPP < 130           MEDIUM    2
    // PPF < 10 || PPF > 20     LOW       1
    // 8 < PPM < 30             MEDIUM    2
    // ActiveTimeSec > 1800     HIGH      3

    uint32_t ackpush_flows = s.ack_flows + s.ackpush_flows;
    uint32_t flows = s.ack_flows + s.ackpush_flows + s.other_flows;
    uint32_t bpp = (uint32_t)(((float) s.bytes) / s.packets);
    uint32_t ppf = (uint32_t) (((float) s.packets) / flows);
    uint32_t active_time = (s.last_seen - s.last_exported);
    int32_t ppm = active_time < 5 ? -1 : (int32_t)(((float) s.packets) / (active_time / 60.0));  // Prevent divide by low numbers


    uint32_t score = 0;
    if ((int) (((float)ackpush_flows) / flows * 100) >= SUSPECT_ACKPUSH_FLOW_RATIO) {
        score += SUSPECT_SCORE_ACKPUSH_FLOW_RATIO;
    }

    if (bpp > SUSPECT_LOW_BPP_TRESHOLD && bpp < SUSPECT_HIGH_BPP_THRESHOLD) {
        score += SUSPECT_SCORE_BPP;
    }

    if (ppf < SUSPECT_REVERSE_LOW_PPF_TRESHOLD || ppf > SUSPECT_REVERSE_HIGH_PPF_TRESHOLD) {
        score += SUSPECT_SCORE_PPF;
    }

    if (ppm != -1 && ppm >= SUSPECT_LOW_PPM_TRESHOLD && ppm <= SUSPECT_HIGH_PPM_TRESHOLD) {
        score += SUSPECT_SCORE_PPM;
    }

    if (active_time >= SUSPECT_MIN_ACTIVE_TIME) {
        score += SUSPECT_SCORE_ACTIVE_TIME;
    }

    return score;
}


/**
 * \brief Add suspect into database.
 * \param key     Key to the database (used for later referencing).
 * \param suspect Aggregated flow data about suspect.
 */
void insert_suspect_to_db(suspect_item_key_t &key, suspect_item_t &suspect)
{
    suspect_item_key_t lost_key;
    suspect_item_t lost_suspect;

    int ret = fht_insert(SUSPECT_DB, &key, &suspect, &lost_key, &lost_suspect);

    switch (ret) {
        case FHT_INSERT_OK:     // Insert was successfull
                                break;
        case FHT_INSERT_LOST:   // Insert kicked out item
                                DEBUG_PRINT("Item was kicked out from table :(\n");
                                break;
        case FHT_INSERT_FAILED: // Item with same key is already in the table, this can not happen or can?
                                DEBUG_PRINT("Item already in the table!!!\n");
                                break;
    }

    // Check kicked out suspect
    if (ret == FHT_INSERT_LOST) {
        ip_addr_t miner_ip = lost_key.suspect_ip;
        ip_addr_t pool_ip = lost_key.pool_ip;
        uint16_t port = lost_key.port;

        list_key_t check_key;
        memset(&check_key, 0, sizeof(list_key_t));
        check_key.ip = pool_ip;
        check_key.port = port;

        if (fht_get_data(BLACKLIST_DB, &check_key)) {
            // Is blacklisted -> report
            //trap_send(0, ((aggr_data_t*)iter->data_ptr)->data, ur_rec_fixlen_size((ur_template_t*)tmplt));
            SENDER->send(miner_ip, pool_ip, port, lost_suspect.first_seen, lost_suspect.last_seen, lost_suspect.packets);
            DEBUG_PRINT("Miner detected (kicked out): %s -> %s:%u\n",
                        convert_unirec_ip_to_string(miner_ip).c_str(),
                        convert_unirec_ip_to_string(pool_ip).c_str(), port);
        }
    }
}

/**
 * \brief Store current W/B list database in file for use in next run.
 */
 void store_list_db(fht_table_t *db, const char *fname)
 {
    char buff[128];
    ofstream myfile;
    if (!fname) {
        // Store file was not set, do not store databases
        return;
    }

    myfile.open(fname);

    fht_iter_t *iter = fht_init_iter(db);
    while (fht_get_next_iter(iter) == FHT_ITER_RET_OK) {
        // Get IP address and port from iterator
        ip_addr_t *ip = &((list_key_t*)iter->key_ptr)->ip;
        uint16_t *port = &((list_key_t*)iter->key_ptr)->port;

        ip_to_str(ip, buff);
        string ip_str = string(buff);

        myfile << ip_str << ":" << *port << endl;
    }
    fht_destroy_iter(iter);

    myfile.close();
 }


/**
 * \brief Check every suspect in suspect database and export everyone
 *        on blacklist.
 */
void export_suspects(void)
{
    fht_iter_t *iter = fht_init_iter(SUSPECT_DB);

    while (fht_get_next_iter(iter) == FHT_ITER_RET_OK) {
        // Get IP addresses and port from iterator
        ip_addr_t *miner_ip = &((suspect_item_key_t*)iter->key_ptr)->suspect_ip;
        ip_addr_t *pool_ip = &((suspect_item_key_t*)iter->key_ptr)->pool_ip;
        uint16_t port = ((suspect_item_key_t*)iter->key_ptr)->port;

        list_key_t key;
        memset(&key, 0, sizeof(list_key_t));
        key.ip = *pool_ip;
        key.port = port;

        if (fht_get_data(BLACKLIST_DB, &key)) {
            // Is blacklisted -> report
            SENDER->send(*miner_ip, *pool_ip, port, ((suspect_item_t*)iter->data_ptr)->first_seen,
                         ((suspect_item_t*)iter->data_ptr)->last_seen, ((suspect_item_t*)iter->data_ptr)->packets);
            DEBUG_PRINT("Miner detection expired (terminating): %s -> %s:%u\n",
                        convert_unirec_ip_to_string(*miner_ip).c_str(),
                        convert_unirec_ip_to_string(*pool_ip).c_str(), port);
        }
    }
    fht_destroy_iter(iter);
}


/**
 * \brief Thread for checking, exporting and removing suspects from database.
 * \param data Nothing, null.
 * \return Nothing, null.
 */
 void *check_thread(void *data)
{
    ip_addr_t *miner_ip, *pool_ip;
    uint16_t port;
    char buff[128];

    // Cycle through suspect database and check for suspects with high score
    while(!STOP) {
        fht_iter_t *iter = fht_init_iter(SUSPECT_DB);

        while (fht_get_next_iter(iter) == FHT_ITER_RET_OK) {
            bool blacklisted_flag = false;
            if (STOP) {
                DEBUG_PRINT("STOP signal detected\n");
                break;
            }
            // Get IP addresses and port from iterator
            miner_ip = &((suspect_item_key_t*)iter->key_ptr)->suspect_ip;
            pool_ip = &((suspect_item_key_t*)iter->key_ptr)->pool_ip;
            port = ((suspect_item_key_t*)iter->key_ptr)->port;

            list_key_t key;
            memset(&key, 0, sizeof(list_key_t));
            key.ip = *pool_ip;
            key.port = port;

            // Check if pool IP is in blacklist database
            if (fht_get_data(BLACKLIST_DB, &key)) {
                blacklisted_flag = true;
            } // Check if pool IP is in the whitelist database
            else if (fht_get_data(WHITELIST_DB, &key)) {
                // Remove suspect from database
                fht_remove_iter(iter);
                continue;
            } else {
                // Check score
                uint32_t score = compute_suspect_score(*(suspect_item_t*)iter->data_ptr);
                if (score >= SUSPECT_SCORE_THRESHOLD) {
                     //DEBUG_PRINT("Suspect '%s' (-> %s) scored '%u', checking for stratum protocol!\n",
                     //           convert_unirec_ip_to_string(*miner_ip).c_str(), convert_unirec_ip_to_string(*pool_ip).c_str(), score);
                    int ret;
                    uint16_t value = 1;
                    if (CHECK_STRATUM_FLAG) {
                        // Check pool IP if it support stratum protocol
                        ip_to_str(pool_ip, buff);
                        string ip_str = string(buff);
                        if (check_for_stratum_protocol(ip_str, port)) {
                            // Add pool IP to blacklist
                            DEBUG_PRINT("Stratum detected, blacklisting!\n");
                            //BLACKLIST_DB.insert(pair<string,uint16_t>(convert_unirec_ip_to_string(*pool_ip),port));
                            ret = fht_insert(BLACKLIST_DB, &key, &value, NULL, NULL);
                            blacklisted_flag = true;
                        } else {
                            // Add pool IP to whitelist
                            DEBUG_PRINT("Stratum not detected, whitelisting!\n");
                            //WHITELIST_DB.insert(pair<string,uint16_t>(convert_unirec_ip_to_string(*pool_ip),port));
                            ret = fht_insert(WHITELIST_DB, &key, &value, NULL, NULL);
                            fht_remove_iter(iter);
                        }
                    } else {
                        // Not checking for stratum, rely only on score
                        ret = FHT_INSERT_OK;//ret = fht_insert(BLACKLIST_DB, &key, &value, NULL, NULL);
                    }
                    // Check insert to DB
                    switch (ret) {
                        case FHT_INSERT_OK:     // Insert was successfull
                                                break;
                        case FHT_INSERT_LOST:   // Insert kicked out item
                                                DEBUG_PRINT("Some item was kicked out from W/BList DB due to inserting new one.\n");
                                                break;
                        case FHT_INSERT_FAILED: // Item with same key is already in the table, this can not happen or can?
                                                break;
                    }
                }
            }

            // TimeCheck only blacklisted records
            if (!blacklisted_flag) {
                continue;
            }


            // For every item in suspect db, check if expired (INACTIVE TIMEOUT)
            if (CURRENT_TIME - ((suspect_item_t*)iter->data_ptr)->last_seen >= TIMEOUT_INACTIVE) {
                // Inactive timeout expired
                if (blacklisted_flag) {
                    SENDER->send(*miner_ip, *pool_ip, port, ((suspect_item_t*)iter->data_ptr)->first_seen,
                                 ((suspect_item_t*)iter->data_ptr)->last_seen, ((suspect_item_t*)iter->data_ptr)->packets);
                    DEBUG_PRINT("Miner detection expired (inactive): %s -> %s:%u\n",
                        convert_unirec_ip_to_string(*miner_ip).c_str(),
                        convert_unirec_ip_to_string(*pool_ip).c_str(), port);
                }
                fht_remove_iter(iter);
                continue;
            }

            // Check flow last seen timestamp (ACTIVE TIMEOUT)
            if (CURRENT_TIME - ((suspect_item_t*)iter->data_ptr)->last_exported >= TIMEOUT_EXPORT) {
                // Export timeout expired, send data to output
                SENDER->send(*miner_ip, *pool_ip, port, ((suspect_item_t*)iter->data_ptr)->first_seen,
                             ((suspect_item_t*)iter->data_ptr)->last_seen, ((suspect_item_t*)iter->data_ptr)->packets);
                DEBUG_PRINT("Miner detection expired (active): %s -> %s:%u\n",
                        convert_unirec_ip_to_string(*miner_ip).c_str(),
                        convert_unirec_ip_to_string(*pool_ip).c_str(), port);

                // Reset counters
                ((suspect_item_t*)iter->data_ptr)->last_exported = CURRENT_TIME;
                ((suspect_item_t*)iter->data_ptr)->ack_flows = 0;
                ((suspect_item_t*)iter->data_ptr)->bytes = 0;
                ((suspect_item_t*)iter->data_ptr)->packets = 0;
                ((suspect_item_t*)iter->data_ptr)->other_flows = 0;
                ((suspect_item_t*)iter->data_ptr)->ackpush_flows = 0;
            }
        }
        fht_destroy_iter(iter);

        sleep(CHECK_THREAD_SLEEP_PERIOD);
    }

    // We are terminating, export every blacklisted suspect
    export_suspects();

    // Write current blacklist/whitelist database to file for further use
    store_list_db(BLACKLIST_DB, BL_STORE_FILE);
    store_list_db(WHITELIST_DB, WL_STORE_FILE);

    // Free all databases
    fht_destroy(SUSPECT_DB);
    fht_destroy(BLACKLIST_DB);
    fht_destroy(WHITELIST_DB);


    DEBUG_PRINT("Terminating checking thread\n");
    return NULL;
}



/**
 * \brief Initialize miner detector, read file with addresses
 *        and create needed data structures.
 * \param bl_fname Name of the file with blacklisted IP addresses.
 * \param wl_fname Name of the file with whitelisted IP addresses.
 * \return True on success, False otherwise.
 */
bool miner_detector_initialization(config_struct_t* config)
{
    DEBUG_PRINT("Initializing miner detector...\n");


    TIMEOUT_INACTIVE = config->timeout_inactive;
    TIMEOUT_EXPORT = config->timeout_active;
    CHECK_THREAD_SLEEP_PERIOD = config->check_period;
    SUSPECT_SCORE_THRESHOLD = config->score_treshold;
    SUSPECT_DB_SIZE = config->suspect_db_size;
    SUSPECT_DB_STASH_SIZE = config->suspect_db_stash_size;
    WHITELIST_DB_SIZE = config->whitelist_db_size;
    WHITELIST_DB_STASH_SIZE = config->whitelist_db_stash_size;
    BLACKLIST_DB_SIZE = config->blacklist_db_size;
    BLACKLIST_DB_STASH_SIZE = config->blacklist_db_stash_size;


    // Create DBs
    if (!initialize_suspect_db() || !initialize_whitelist_db() || !initialize_blacklist_db()) {
        fprintf(stderr, "Error initializing databases!\n");
        return false;
    }


    if (config->blacklist_file != NULL && strcmp(config->blacklist_file, "-") != 0) {
        // Create blacklist DB
        create_db_from_file(BLACKLIST_DB, config->blacklist_file);
    }

    if (config->whitelist_file != NULL && strcmp(config->whitelist_file, "-") != 0) {
         // Create whitelist DB
        create_db_from_file(WHITELIST_DB, config->whitelist_file);
    }

    if (config->store_blacklist_file != NULL && strcmp(config->store_blacklist_file, "-") != 0) {
        // Set store file for blacklistlist
        BL_STORE_FILE = config->store_blacklist_file;
    }

    if (config->store_whitelist_file != NULL && strcmp(config->store_whitelist_file, "-") != 0) {
        // Set store file for whitelist
        WL_STORE_FILE = config->store_whitelist_file;
    }

    if (config->stratum_check != NULL && strcmp(config->stratum_check, "true")) {
        CHECK_STRATUM_FLAG = true;
    } else  {
        CHECK_STRATUM_FLAG = false;
    }




    // Create checking thread
    pthread_create(&MINER_DETECTOR_CHECK_THREAD_ID, NULL, check_thread, NULL);


    return true;
}



/**
 * \brief Processes flow data, finds suspicious flows and updates suspect database.
 * \param tmplt Template of given Unirec data.
 * \param data  Flow data.
 */
void miner_detector_process_data(ur_template_t *tmplt, const void *data)
{
    //DEBUG_PRINT("Processing given data...\n");
    bool blacklist_src_flag = false;
    bool blacklist_dst_flag = false;
    bool whitelist_dst_flag = false;
    bool suspect_flag = false;
    bool only_ack_flow_flag = false;
    bool only_ackpush_flow_flag = false;
    int8_t *lock = NULL;

    // Update global timestamp
    uint32_t actual_time = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));
    if (actual_time > CURRENT_TIME) {
        CURRENT_TIME = actual_time;
    }

    // Convert src/dst ip to string
    ip_addr_t src_ip = ur_get(tmplt, data, F_SRC_IP);
    ip_addr_t dst_ip = ur_get(tmplt, data, F_DST_IP);

    // Store ports
    uint16_t src_port = ur_get(tmplt, data, F_SRC_PORT);
    uint16_t dst_port = ur_get(tmplt, data, F_DST_PORT);

    list_key_t key;
    memset(&key, 0, sizeof(list_key_t));
    key.ip = dst_ip;
    key.port = dst_port;

    // Check if IP addresses in flow are not blacklisted    // NOT USED RIGHT NOW
    /*if ((blacklist_ip_it = BLACKLIST_DB.find(convert_unirec_ip_to_string(src_ip))) != BLACKLIST_DB.end()) {
        if (blacklist_ip_it->second == 0 || blacklist_ip_it->second == src_port) {
            blacklist_src_flag = suspect_flag = true;
        }
    }*/

    if (fht_get_data(BLACKLIST_DB, &key)) {
        blacklist_dst_flag = suspect_flag = true;
    }

    // If destination is whitelisted, do not add suspect to databse
    if (fht_get_data(WHITELIST_DB, &key)) {
        whitelist_dst_flag = true;
    }


    // Check if flow is TCP and has only ACK or ACK&PUSH flags set
    if (ur_get(tmplt, data, F_PROTOCOL) == PROTO_TCP) {
        uint8_t tcp_flags = ur_get(tmplt, data, F_TCP_FLAGS);
        if (tcp_flags == TCP_ACK) {
            only_ack_flow_flag = suspect_flag = true;
        } else if (tcp_flags == (TCP_ACK & TCP_PSH)) {
            only_ackpush_flow_flag = suspect_flag = true;
        }
    }

    // Check if IP addresses are already suspects
    suspect_item_key_t suspect_key = create_suspect_key(src_ip, dst_ip, dst_port);
    suspect_item_t *suspect = (suspect_item_t*) fht_get_data_locked(SUSPECT_DB, &suspect_key, &lock);
    if (suspect) {
        // Update suspect
        suspect->flagged += blacklist_dst_flag;
        suspect->ack_flows += (int) only_ack_flow_flag;
        suspect->ackpush_flows += (int) only_ackpush_flow_flag;
        suspect->other_flows += (int) (!only_ack_flow_flag && !only_ackpush_flow_flag);
        suspect->packets += ur_get(tmplt, data, F_PACKETS);
        suspect->bytes += ur_get(tmplt, data, F_BYTES);
        suspect->last_seen = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));

        suspect_flag = false;
        fht_unlock_data(lock);
    }



    // Add IP as suspect if new
    // TODO: Do not add if it is pool->miner direction for now...
    if (suspect_flag && !whitelist_dst_flag) {
        suspect_item_t suspect;
        memset(&suspect, 0, sizeof(suspect_item_t));


        if (blacklist_src_flag) {
            // DEAD CODE // NOT USED RIGHT NOW
            // Incoming data from pool to miner, need to create new key
            suspect_key = create_suspect_key(dst_ip, src_ip, src_port);
            suspect.flagged = true;

            DEBUG_PRINT("New suspect: %s\n", convert_unirec_ip_to_string(dst_ip).c_str());
        } else {
            // Miner to pool communication
            suspect.flagged = blacklist_dst_flag;
            suspect.ack_flows += (int) only_ack_flow_flag;
            suspect.ackpush_flows += (int) only_ackpush_flow_flag;
            suspect.other_flows += (int) (!only_ack_flow_flag && !only_ackpush_flow_flag);
            suspect.packets += ur_get(tmplt, data, F_PACKETS);
            suspect.bytes += ur_get(tmplt, data, F_BYTES);
            suspect.first_seen = ur_time_get_sec(ur_get(tmplt, data, F_TIME_FIRST));
            suspect.last_seen = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));
            suspect.last_exported = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));

            //DEBUG_PRINT("New suspect: %s\n", convert_unirec_ip_to_string(src_ip).c_str());
        }

        // Insert suspect to database
        insert_suspect_to_db(suspect_key, suspect);
    }
}


