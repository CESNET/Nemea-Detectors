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
#include <time.h>

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
#include <vector>


//#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stdout, "DEBUG: "  __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif


using namespace std;


//vector<>
fht_table_t *BLACKLIST_DB;
fht_table_t *WHITELIST_DB;
fht_table_t *SUSPECT_DB;
pthread_t MINER_DETECTOR_CHECK_THREAD_ID;
pthread_t MINER_DETECTOR_LISTTIMEOUT_THREAD_ID;
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

    uint32_t value = BWL_PERMANENT_RECORD;
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
    if ((WHITELIST_DB = fht_init(WHITELIST_DB_SIZE, sizeof(list_key_t), sizeof(uint32_t), WHITELIST_DB_STASH_SIZE)) == NULL) {
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
    if ((BLACKLIST_DB = fht_init(BLACKLIST_DB_SIZE, sizeof(list_key_t), sizeof(uint32_t), BLACKLIST_DB_STASH_SIZE)) == NULL) {
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

    if (s.req_flows / (double) flows > SUSPECT_REQ_FLOWS_TRESHOLD) {
        score += SUSPECT_SCORE_REQ_FLOWS;
    }

    if (active_time >= SUSPECT_MIN_ACTIVE_TIME) {
        score += SUSPECT_SCORE_ACTIVE_TIME;
    }

    return score;
}

/**
 * \brief Decide if a suspect is miner or not, based on decision tree
 *        created by Weka.
 * \param s Structure containg suspect aggregated flow information.
 * \return 0 if not miner, 1 if miner.
 */
uint8_t compute_weka_tree(suspect_item_t &s)
{
    uint32_t ackpush_flows = s.ack_flows + s.ackpush_flows;
    uint32_t flows = s.ack_flows + s.ackpush_flows + s.other_flows;
    uint32_t bpp = (uint32_t)(((float) s.bytes) / s.packets);
    uint32_t ppf = (uint32_t) (((float) s.packets) / flows);
    uint32_t active_time = (s.last_seen - s.last_exported);
    int32_t ppm = active_time < 5 ? -1 : (int32_t)(((float) s.packets) / (active_time / 60.0));  // Prevent divide by low numbers

    uint32_t ackpushSall = (uint32_t)((ackpush_flows / ((double)flows)) * 100);
    uint32_t synSall = (uint32_t)((s.syn_flows / ((double)flows)) * 100);
    uint32_t rstSall = (uint32_t)((s.rst_flows / ((double)flows)) * 100);
    uint32_t finSall = (uint32_t)((s.fin_flows / ((double)flows)) * 100);
    uint32_t reqSall = (uint32_t)((s.req_flows / ((double)flows)) * 100);

    // Decision Tree created by Weka
    if (ppm <=  135) {
        if (bpp <=  70) {
            if (ppm <=  12) {
                if (rstSall <=  1) {
                    if (finSall <=  7) {
                        if (ppf <=  3) {
                            if (bpp <=  59) {
                                if (ackpushSall <=  86) {
                                    return 0;
                                }
                                if (ackpushSall >  86) {
                                    if (ppf <=  1) {
                                        if (bpp <=  54) {
                                            if (ppm <=  5) {
                                                if (synSall <=  1) {
                                                    if (ackpushSall <=  95) {
                                                        return 0;
                                                    }
                                                    if (ackpushSall >  95) {
                                                        if (ppm <=  1) {
                                                            return 1;
                                                        }
                                                        if (ppm >  1) {
                                                            if (ackpushSall <=  97) {
                                                                return 0;
                                                            }
                                                            if (ackpushSall >  97) {
                                                                if (finSall <=  0) {
                                                                    if (ackpushSall <=  99) {
                                                                        if (ppm <=  4) {
                                                                            return 0;
                                                                        }
                                                                        if (ppm >  4) {
                                                                            return 1;
                                                                        }
                                                                    }
                                                                    if (ackpushSall >  99) {
                                                                        return 1;
                                                                    }
                                                                }
                                                                if (finSall >  0) {
                                                                    return 0;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                if (synSall >  1) {
                                                    if (finSall <=  6) {
                                                        return 0;
                                                    }
                                                    if (finSall >  6) {
                                                        return 1;
                                                    }
                                                }
                                            }
                                            if (ppm >  5) {
                                                return 0;
                                            }
                                        }
                                        if (bpp >  54) {
                                            return 0;
                                        }
                                    }
                                    if (ppf >  1) {
                                        if (ppf <=  2) {
                                            if (synSall <=  6) {
                                                if (rstSall <=  0) {
                                                    if (bpp <=  55) {
                                                        if (finSall <=  3) {
                                                            if (ackpushSall <=  93) {
                                                                if (ppm <=  5) {
                                                                    return 0;
                                                                }
                                                                if (ppm >  5) {
                                                                    return 1;
                                                                }
                                                            }
                                                            if (ackpushSall >  93) {
                                                                if (bpp <=  52) {
                                                                    if (ppm <=  6) {
                                                                        if (ackpushSall <=  99) {
                                                                            if (finSall <=  0) {
                                                                                return 0;
                                                                            }
                                                                            if (finSall >  0) {
                                                                                if (bpp <=  43) {
                                                                                    return 1;
                                                                                }
                                                                                if (bpp >  43) {
                                                                                    if (synSall <=  0) {
                                                                                        return 1;
                                                                                    }
                                                                                    if (synSall >  0) {
                                                                                        return 0;
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        if (ackpushSall >  99) {
                                                                            return 1;
                                                                        }
                                                                    }
                                                                    if (ppm >  6) {
                                                                        return 0;
                                                                    }
                                                                }
                                                                if (bpp >  52) {
                                                                    if (ppm <=  3) {
                                                                        if (ackpushSall <=  97) {
                                                                            return 0;
                                                                        }
                                                                        if (ackpushSall >  97) {
                                                                            return 1;
                                                                        }
                                                                    }
                                                                    if (ppm >  3) {
                                                                        if (ackpushSall <=  98) {
                                                                            if (bpp <=  54) {
                                                                                return 1;
                                                                            }
                                                                            if (bpp >  54) {
                                                                                if (ackpushSall <=  94) {
                                                                                    return 1;
                                                                                }
                                                                                if (ackpushSall >  94) {
                                                                                    return 0;
                                                                                }
                                                                            }
                                                                        }
                                                                        if (ackpushSall >  98) {
                                                                            return 0;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        if (finSall >  3) {
                                                            return 0;
                                                        }
                                                    }
                                                    if (bpp >  55) {
                                                        if (ppm <=  8) {
                                                            if (ppm <=  1) {
                                                                return 0;
                                                            }
                                                            if (ppm >  1) {
                                                                if (ackpushSall <=  99) {
                                                                    if (ackpushSall <=  94) {
                                                                        if (ppm <=  4) {
                                                                            return 0;
                                                                        }
                                                                        if (ppm >  4) {
                                                                            if (bpp <=  56) {
                                                                                return 1;
                                                                            }
                                                                            if (bpp >  56) {
                                                                                if (ackpushSall <=  89) {
                                                                                    return 1;
                                                                                }
                                                                                if (ackpushSall >  89) {
                                                                                    return 0;
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    if (ackpushSall >  94) {
                                                                        return 0;
                                                                    }
                                                                }
                                                                if (ackpushSall >  99) {
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                        if (ppm >  8) {
                                                            return 0;
                                                        }
                                                    }
                                                }
                                                if (rstSall >  0) {
                                                    if (bpp <=  56) {
                                                        if (ackpushSall <=  96) {
                                                            if (bpp <=  40) {
                                                                return 1;
                                                            }
                                                            if (bpp >  40) {
                                                                if (ppm <=  6) {
                                                                    return 0;
                                                                }
                                                                if (ppm >  6) {
                                                                    return 1;
                                                                }
                                                            }
                                                        }
                                                        if (ackpushSall >  96) {
                                                            return 0;
                                                        }
                                                    }
                                                    if (bpp >  56) {
                                                        return 0;
                                                    }
                                                }
                                            }
                                            if (synSall >  6) {
                                                return 0;
                                            }
                                        }
                                        if (ppf >  2) {
                                            if (ackpushSall <=  99) {
                                                return 0;
                                            }
                                            if (ackpushSall >  99) {
                                                if (ppm <=  5) {
                                                    if (ppm <=  3) {
                                                        return 0;
                                                    }
                                                    if (ppm >  3) {
                                                        return 1;
                                                    }
                                                }
                                                if (ppm >  5) {
                                                    return 0;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            if (bpp >  59) {
                                if (ppf <=  1) {
                                    return 0;
                                }
                                if (ppf >  1) {
                                    if (ppm <=  4) {
                                        if (finSall <=  1) {
                                            if (ppm <=  2) {
                                                return 0;
                                            }
                                            if (ppm >  2) {
                                                if (synSall <=  91) {
                                                    if (ackpushSall <=  99) {
                                                        return 0;
                                                    }
                                                    if (ackpushSall >  99) {
                                                        return 1;
                                                    }
                                                }
                                                if (synSall >  91) {
                                                    return 1;
                                                }
                                            }
                                        }
                                        if (finSall >  1) {
                                            return 0;
                                        }
                                    }
                                    if (ppm >  4) {
                                        return 0;
                                    }
                                }
                            }
                        }
                        if (ppf >  3) {
                            if (ackpushSall <=  99) {
                                return 0;
                            }
                            if (ackpushSall >  99) {
                                if (bpp <=  57) {
                                    return 0;
                                }
                                if (bpp >  57) {
                                    if (ppm <=  6) {
                                        return 0;
                                    }
                                    if (ppm >  6) {
                                        if (ppf <=  10) {
                                            if (ppm <=  10) {
                                                if (bpp <=  67) {
                                                    if (ppf <=  8) {
                                                        if (bpp <=  58) {
                                                            return 1;
                                                        }
                                                        if (bpp >  58) {
                                                            return 0;
                                                        }
                                                    }
                                                    if (ppf >  8) {
                                                        return 1;
                                                    }
                                                }
                                                if (bpp >  67) {
                                                    return 0;
                                                }
                                            }
                                            if (ppm >  10) {
                                                return 0;
                                            }
                                        }
                                        if (ppf >  10) {
                                            return 0;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (finSall >  7) {
                        return 0;
                    }
                }
                if (rstSall >  1) {
                    if (finSall <=  97) {
                        if (synSall <=  2) {
                            if (ppf <=  5) {
                                return 0;
                            }
                            if (ppf >  5) {
                                return 1;
                            }
                        }
                        if (synSall >  2) {
                            return 0;
                        }
                    }
                    if (finSall >  97) {
                        if (ppf <=  6) {
                            return 0;
                        }
                        if (ppf >  6) {
                            return 1;
                        }
                    }
                }
            }
            if (ppm >  12) {
                return 0;
            }
        }
        if (bpp >  70) {
            if (ppm <=  70) {
                if (reqSall <=  75) {
                    return 1;
                }
                if (reqSall >  75) {
                    return 0;
                }
            }
            if (ppm >  70) {
                if (ackpushSall <=  99) {
                    return 0;
                }
                if (ackpushSall >  99) {
                    if (bpp <=  105) {
                        return 0;
                    }
                    if (bpp >  105) {
                        return 1;
                    }
                }
            }
        }
    }
    if (ppm >  135) {
        if (bpp <=  103) {
            return 0;
        }
        if (bpp >  103) {
            if (bpp <=  108) {
                if (ppf <=  230) {
                    return 1;
                }
                if (ppf >  230) {
                    return 0;
                }
            }
            if (bpp >  108) {
                return 0;
            }
        }
    }



    return 0;
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
                                //DEBUG_PRINT("Item was kicked out from table :(\n");
                                break;
        case FHT_INSERT_FAILED: // Item with same key is already in the table, this can not happen or can?
                                //DEBUG_PRINT("Item already in the table!!!\n");
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

        if (fht_get_data(BLACKLIST_DB, &check_key) || lost_suspect.flagged) {
            // Is blacklisted -> report
            SENDER->send(miner_ip, pool_ip, port, lost_suspect.first_seen, lost_suspect.last_seen, lost_suspect.packets);
        }
    }
}

/**
 * \brief Store current W/B list database in file for use in next run.
 * \param db Database from which the data will be read.
 * \param fname File name to which the data will be written.
 */
 void store_list_db(fht_table_t *db, const char *fname)
 {
    char buff[128];
    ofstream myfile;
    if (!fname) {
        // Store file was not set, do not store databases
        DEBUG_PRINT("No store file specified!\n");
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
            SENDER->send(*miner_ip, *pool_ip, port, ((suspect_item_t*)iter->data_ptr)->first_seen, ((suspect_item_t*)iter->data_ptr)->last_seen, ((suspect_item_t*)iter->data_ptr)->packets);
        }
    }
    fht_destroy_iter(iter);
}


/**
 * \brief Thread for checking expired items in blacklist/whitelist DB.
 * \param data Nothing, null
 * \return Nothing, null.
 */
void *list_timeout_thread(void *data)
{
    fht_iter_t *black_iter = fht_init_iter(BLACKLIST_DB);
    fht_iter_t *white_iter = fht_init_iter(WHITELIST_DB);

    while(!STOP) {
        uint32_t white_expired_sum = 0;
        uint32_t black_expired_sum = 0;
        time_t timestamp = CURRENT_TIME;
        struct tm *tmp = localtime(&timestamp);
        char timestr[200];
        strftime(timestr, 200, "%Y-%m-%dT%H:%M:%S", tmp);

        DEBUG_PRINT("[%s] New round of checking black/white list\n", timestr);

        // Check blacklist DB
        fht_reinit_iter(black_iter);

        // Cycle through every item in blacklist DB
        while (fht_get_next_iter(black_iter) == FHT_ITER_RET_OK) {
            if (STOP) {
                DEBUG_PRINT("STOP signal detected\n");
                break;
            }

            // Check timestamp if it is permanent
            if (*((uint32_t*)black_iter->data_ptr) == BWL_PERMANENT_RECORD) {
                continue; // Permanent records do not expire
            }

            // Check timestamp if it expired
            if (CURRENT_TIME - *((uint32_t*)black_iter->data_ptr) >= BL_ITEM_EXPIRE_TIME) {
                black_expired_sum++;
                fht_remove_iter(black_iter); // Record has expired
                continue;
            }
        }

        // Check whitelist DB
        fht_reinit_iter(white_iter);

        // Cycle through every item in blacklist DB
        while (fht_get_next_iter(white_iter) == FHT_ITER_RET_OK) {
            if (STOP) {
                DEBUG_PRINT("STOP signal detected\n");
                break;
            }

            // Check timestamp if it is permanent
            if (*((uint32_t*)white_iter->data_ptr) == BWL_PERMANENT_RECORD) {
                continue; // Permanent records do not expire
            }

            // Check timestamp if it expired
            if (CURRENT_TIME - *((uint32_t*)white_iter->data_ptr) >= WL_ITEM_EXPIRE_TIME) {
                white_expired_sum++;
                fht_remove_iter(white_iter); // Record has expired
                continue;
            }
        }


        DEBUG_PRINT("Expired items in lists: black = %u, white = %u\n", black_expired_sum, white_expired_sum);

        // Wait for next iteration
        if (!STOP) {
            sleep(BWL_LIST_EXPIRE_SLEEP_DURATION);
        }
    }


    DEBUG_PRINT("Terminating list timeout thread\n");
    return NULL;
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
    fht_iter_t *iter = fht_init_iter(SUSPECT_DB);

    // Cycle through suspect database and check for suspects with high score
    while(!STOP) {
        fht_reinit_iter(iter);

   
        time_t timestamp = CURRENT_TIME;
        struct tm *tmp = localtime(&timestamp);
        char timestr[200];
        strftime(timestr, 200, "%Y-%m-%dT%H:%M:%S", tmp);

        DEBUG_PRINT("[%s] New round of passive testing\n", timestr);

        // Cycle through every suspect in DB
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
                ((suspect_item_t*)iter->data_ptr)->flagged = true;
            } // Check if pool IP is in the whitelist database
            else if (fht_get_data(WHITELIST_DB, &key)) {
                // Remove suspect from database
                fht_remove_iter(iter);
                continue;
            } else {
                // Check score
                uint32_t score = compute_suspect_score(*(suspect_item_t*)iter->data_ptr);
                uint8_t weka_flag = compute_weka_tree(*(suspect_item_t*)iter->data_ptr);
                if (score >= SUSPECT_SCORE_THRESHOLD && weka_flag) {
                    int ret;
                    uint32_t timestamp = CURRENT_TIME;
                    uint8_t pool_id;
                    if (CHECK_STRATUM_FLAG) {
                        // Check pool IP if it support stratum protocol
                        ip_to_str(pool_ip, buff);
                        if ((ret = stratum_check_server(buff, port, &pool_id)) == STRATUM_MATCH) {
                            // Add pool IP to blacklist
                            DEBUG_PRINT("Stratum detected(%s), blacklisting!\n", stratum_mpool_string(pool_id));
                            ret = fht_insert(BLACKLIST_DB, &key, &timestamp, NULL, NULL);
                            blacklisted_flag = true;
                            ((suspect_item_t*)iter->data_ptr)->pool_id = pool_id;
                            ((suspect_item_t*)iter->data_ptr)->flagged = true;
                        } else {
                            // Add pool IP to whitelist
                            DEBUG_PRINT("Stratum not detected(%s), whitelisting!\n", stratum_error_string(ret));
                            ret = fht_insert(WHITELIST_DB, &key, &timestamp, NULL, NULL);
                            fht_remove_iter(iter);
                            continue;
                        }
                    } else {
                        // DEBUG
                        /*if (fht_get_data(BLACKLIST_DB, &key)) {
                            DEBUG_PRINT("Stratum detected(-), blacklisting!\n");
                            blacklisted_flag = true;
                            ((suspect_item_t*)iter->data_ptr)->flagged = true;
                            ret = FHT_INSERT_OK;
                        } else {
                            //DEBUG_PRINT("Stratum not detected(-), whitelisting!\n");
                            ret = fht_insert(WHITELIST_DB, &key, &timestamp, NULL, NULL);
                            fht_remove_iter(iter);
                            continue;
                        }*/
                        // Not checking for stratum, rely only on score
                        ret = STRATUM_NOT_USED; //FHT_INSERT_OK;//ret = fht_insert(BLACKLIST_DB, &key, &value, NULL, NULL);
                    }
                    // Check insert to DB
                    switch (ret) {
                        case STRATUM_NOT_USED:  // Not using stratum checker
                                                break;
                        case FHT_INSERT_OK:     // Insert was successfull
                                                break;
                        case FHT_INSERT_LOST:   // Insert kicked out item
                                                DEBUG_PRINT("Some item was kicked out from W/BList DB due to inserting new one.\n");
                                                break;
                        case FHT_INSERT_FAILED: // Item with same key is already in the table, this can not happen or can?
                                                DEBUG_PRINT("Inserting failed!\n");
                                                break;
                    }
                }
            }

            // For every item in suspect db, check if expired (INACTIVE TIMEOUT)
            if (CURRENT_TIME - ((suspect_item_t*)iter->data_ptr)->last_seen >= TIMEOUT_INACTIVE) {
                // Inactive timeout expired
                if (blacklisted_flag) {
                    SENDER->send(*miner_ip, *pool_ip, port, ((suspect_item_t*)iter->data_ptr)->first_seen,((suspect_item_t*)iter->data_ptr)->last_seen, ((suspect_item_t*)iter->data_ptr)->packets);
                }
                fht_remove_iter(iter);
                continue;
            }

            // Check flow last seen timestamp (ACTIVE TIMEOUT)
            if (CURRENT_TIME - ((suspect_item_t*)iter->data_ptr)->last_exported >= TIMEOUT_EXPORT) {
                // Export timeout expired, send data to output
                if (blacklisted_flag) {
                    SENDER->send(*miner_ip, *pool_ip, port, ((suspect_item_t*)iter->data_ptr)->first_seen, ((suspect_item_t*)iter->data_ptr)->last_seen, ((suspect_item_t*)iter->data_ptr)->packets);
                    // Reset last exported time
                    ((suspect_item_t*)iter->data_ptr)->last_exported = CURRENT_TIME;
                } else {
                    fht_remove_iter(iter);
                    continue;
                }
            }
        }

        if (!STOP) {
            sleep(CHECK_THREAD_SLEEP_PERIOD);
        }
    }

    // Free iterator
    fht_destroy_iter(iter);

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
 * \param config Config structure containing all configuration needed.
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

    DEBUG_PRINT("SuspectDB size = %u\nWhitelistDB size = %u\nBlacklistDB size = %u\n", SUSPECT_DB_SIZE, WHITELIST_DB_SIZE, BLACKLIST_DB_SIZE);

    // Create DBs
    if (!initialize_suspect_db() || !initialize_whitelist_db() || !initialize_blacklist_db()) {
        fprintf(stderr, "Error initializing databases!\n");
        return false;
    }


    if (strcmp(config->blacklist_file, "-") != 0) {
        // Create blacklist DB
        create_db_from_file(BLACKLIST_DB, config->blacklist_file);
    }

    if (strcmp(config->whitelist_file, "-") != 0) {
         // Create whitelist DB
        create_db_from_file(WHITELIST_DB, config->whitelist_file);
    }

    if (strcmp(config->store_blacklist_file, "-") != 0) {
        // Set store file for blacklistlist
        BL_STORE_FILE = config->store_blacklist_file;
    }

    if (strcmp(config->store_whitelist_file, "-") != 0) {
        // Set store file for whitelist
        WL_STORE_FILE = config->store_whitelist_file;
    }

    if (strcmp(config->stratum_check, "true") == 0) {
        CHECK_STRATUM_FLAG = true;
    } else  {
        CHECK_STRATUM_FLAG = false;
    }

    // Set stratum checker timeouts
    stratum_set_timeout(STRATUM_CONN_TIMEOUT, config->conn_timeout);
    stratum_set_timeout(STRATUM_READ_TIMEOUT, config->read_timeout);


    // Create checking thread
    pthread_create(&MINER_DETECTOR_CHECK_THREAD_ID, NULL, check_thread, NULL);

    // Create whitelist/blacklist timeout thread
    pthread_create(&MINER_DETECTOR_LISTTIMEOUT_THREAD_ID, NULL, list_timeout_thread, NULL);

    return true;
}



/**
 * \brief Processes flow data, finds suspicious flows and updates suspect database.
 * \param tmplt Template of given Unirec data.
 * \param data  Flow data.
 */
void miner_detector_process_data(ur_template_t *tmplt, const void *data)
{
    bool blacklist_dst_flag = false;
    bool suspect_flag = false;
    bool only_ack_flow_flag = false;
    bool only_ackpush_flow_flag = false;
    bool syn_flow_flag = false;
    bool rst_flow_flag = false;
    bool fin_flow_flag = false;
    int8_t *lock = NULL;

    // Update global timestamp
    uint32_t actual_time = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));
    if (actual_time > CURRENT_TIME) {
        if (actual_time - CURRENT_TIME > 300) {
            DEBUG_PRINT("WARNING: TIMEJUMP by %u\n", actual_time - CURRENT_TIME);
        }
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
    // If destination is blacklisted, tag flow as suspect
    if (fht_get_data(BLACKLIST_DB, &key)) {
        blacklist_dst_flag = suspect_flag = true;
    }

    // If destination is whitelisted, do not add suspect to databse
    if (fht_get_data(WHITELIST_DB, &key)) {
        return;
    }


    memset(&key, 0, sizeof(list_key_t));
    key.ip = src_ip;
    key.port = src_port;
    // If source is blacklisted, do nothing for now
    if (fht_get_data(BLACKLIST_DB, &key)) {
        return;
    }

    // Check if flow is TCP and check TCP flags
    if (ur_get(tmplt, data, F_PROTOCOL) == PROTO_TCP) {
        uint8_t tcp_flags = ur_get(tmplt, data, F_TCP_FLAGS);

        only_ack_flow_flag = tcp_flags == TCP_ACK;
        only_ackpush_flow_flag = tcp_flags == (TCP_ACK | TCP_PSH);
        if (only_ack_flow_flag || only_ackpush_flow_flag) {
            suspect_flag = true;
        }
        syn_flow_flag = tcp_flags & TCP_SYN;
        rst_flow_flag = tcp_flags & TCP_RST;
        fin_flow_flag = tcp_flags & TCP_FIN;
    }

    // Check if IP addresses are already suspects
    suspect_item_key_t suspect_key = create_suspect_key(src_ip, dst_ip, dst_port);
    suspect_item_t *suspect = (suspect_item_t*) fht_get_data_locked(SUSPECT_DB, &suspect_key, &lock);
    if (suspect) {
        // Update suspect
        suspect->flagged += blacklist_dst_flag;
        suspect->ack_flows += (int) only_ack_flow_flag;
        suspect->ackpush_flows += (int) only_ackpush_flow_flag;
        suspect->syn_flows += (int) syn_flow_flag;
        suspect->rst_flows += (int) rst_flow_flag;
        suspect->fin_flows += (int) fin_flow_flag;
        suspect->other_flows += (int) (!only_ack_flow_flag && !only_ackpush_flow_flag);
        suspect->req_flows += (int) (ur_get(tmplt, data, F_SRC_PORT) > ur_get(tmplt, data, F_DST_PORT));
        suspect->packets += ur_get(tmplt, data, F_PACKETS);
        suspect->bytes += ur_get(tmplt, data, F_BYTES);
        suspect->last_seen = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));

        suspect_flag = false;
        fht_unlock_data(lock);
    }



    // Add Flow as suspect
    if (suspect_flag) {
        suspect_item_t suspect;
        memset(&suspect, 0, sizeof(suspect_item_t));

        // Miner to pool communication
        suspect.flagged = blacklist_dst_flag;
        suspect.pool_id = 0xff;
        suspect.ack_flows = (int) only_ack_flow_flag;
        suspect.ackpush_flows = (int) only_ackpush_flow_flag;
        suspect.syn_flows = (int) syn_flow_flag;
        suspect.rst_flows = (int) rst_flow_flag;
        suspect.fin_flows = (int) fin_flow_flag;
        suspect.other_flows = (int) (!only_ack_flow_flag && !only_ackpush_flow_flag);
        suspect.req_flows = (int) (ur_get(tmplt, data, F_SRC_PORT) > ur_get(tmplt, data, F_DST_PORT));
        suspect.packets = ur_get(tmplt, data, F_PACKETS);
        suspect.bytes = ur_get(tmplt, data, F_BYTES);
        suspect.first_seen = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));
        suspect.last_seen = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));
        suspect.last_exported = ur_time_get_sec(ur_get(tmplt, data, F_TIME_LAST));

        // Insert suspect to database
        insert_suspect_to_db(suspect_key, suspect);
    }

}


