/**
 * \file configuration.h
 * \brief VoIP fraud detection module - configuration
 * \author Lukas Truxa <truxaluk@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 CESNET
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

#ifndef VOIP_FRAUD_DETECTION_CONFIGURATION_H
#define VOIP_FRAUD_DETECTION_CONFIGURATION_H

/** \brief GeoIP IPv4 database path. */
#define GEOIP_DATABASE_IPV4_PATH "/usr/share/GeoIP/GeoIP.dat"

/** \brief GeoIP IPv6 database path. */
#define GEOIP_DATABASE_IPV6_PATH "/usr/share/GeoIP/GeoIPv6.dat"

/** \brief Default name of event_id file. */
#define DEFAULT_EVENT_ID_FILE "/data/voip_fraud_detection/event_id.txt"

/** \brief Default name of countries file (module store of countries). */
#define DEFAULT_COUNTRIES_FILE "countries.dat"

/** \brief Maximum number of countries item in storage. */
#define COUNTRY_STORAGE_SIZE 20

/** \brief UniRec input template definition. */
#define UNIREC_INPUT_TEMPLATE "SIP_REQUEST_URI,SIP_CALLING_PARTY,SIP_CALLED_PARTY,SIP_CALL_ID,SIP_USER_AGENT,SIP_MSG_TYPE,SIP_STATUS_CODE,SIP_CSEQ,SRC_IP,DST_IP,LINK_BIT_FIELD,TIME_FIRST"

/** \brief UniRec output template definition. */
#define UNIREC_OUTPUT_TEMPLATE "EVENT_ID,EVENT_TYPE,SRC_IP,DST_IP,DETECTION_TIME,TIME_FIRST,VOIP_FRAUD_SIP_TO,VOIP_FRAUD_SIP_FROM,VOIP_FRAUD_PREFIX_LENGTH,VOIP_FRAUD_PREFIX_EXAMINATION_COUNT,VOIP_FRAUD_SUCCESSFUL_CALL_COUNT,VOIP_FRAUD_USER_AGENT,VOIP_FRAUD_INVITE_COUNT,VOIP_FRAUD_COUNTRY_CODE"

/** \brief Timeout in microseconds - waiting for data (trap_recv() function) in TRAP library. */
#define TRAP_TIMEOUT_MICROSECONDS 2000000

#ifdef FOR_DOCUMENTATION
/** \brief If is define this macro, successful call is considered after SIP ACK request sended by calling party.
 * If is not defined it enough OK response sended by called party. */
#define CONSIDER_SUCCESSFUL_CALL_AFTER_SIPACK
#endif

/** \brief If is define this macro, enable comparison of SIP To header and Request-URI. */
//#define CHECK_DIFFERENT_REQUEST_URI

/** \brief Interval defined in seconds for running check_and_clear_module_memory() function. */
#define CHECK_MEMORY_INTERVAL 60

/** \brief Interval defined in seconds for saving countries to defined countries file (0 = disable autosaving = save only when module exits). */
#define COUNTRIES_FILE_SAVING_INTERVAL 3600

/** \brief Default value of max_prefix_length.
 * If parameter max_prefix_length is not set at startup of module then this default value is used. */
#define DEFAULT_MAX_PREFIX_LENGTH 10

/** \brief Default value of min_length_called_number.
 * If parameter min_length_called_number is not set at startup of module then this default value is used. */
#define DEFAULT_MIN_LENGTH_CALLED_NUMBER 9

/** \brief Default value of prefix_examination_detection_threshold.
 * If parameter prefix_examination_detection_threshold is not set at startup of module then this default value is used. */
#define DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD 10

/** \brief Default value of detection_interval.
 * If parameter detection_interval is not set at startup of module then this default value is used. */
#define DEFAULT_DETECTION_INTERVAL 10

/** \brief Default value of detection_pause_after_attack.
 * If parameter detection_pause_after_attack is not set at startup of module then this default value is used. */
#define DEFAULT_DETECTION_PAUSE_AFTER_ATTACK 30

/** \brief Default value of max_item_prefix_tree.
 * If parameter max_item_prefix_tree is not set at startup of module then this default value is used. */
#define DEFAULT_MAX_ITEM_PREFIX_TREE 100000

/** \brief Default value of time_clear_data_no_communication (1209600 seconds = 14days, 604800 seconds = 7 days).
 * If parameter time_clear_data_no_communication is not set at startup of module then this default value is used. */
#define DEFAULT_CLEAR_DATA_NO_COMMUNICATION_AFTER 1209600

/** \brief Default value of learning_countries_period (0 = disable learning mode, 1209600 seconds = 14days, 604800 seconds = 7 days).
 * If parameter learning_countries_period is not set at startup of module then this default value is used. */
#define DEFAULT_LEARNING_COUNTRIES_PERIOD 1209600

/** \brief Default size of hashing table for storing IP addresses. */
#define HASH_TABLE_IP_SIZE 100000

/** \brief Default size of hashing table for storing User-Agent headers. */
#define HASH_TABLE_USER_AGENT_SIZE 1000

/** \brief Maximum length of SIP_FROM. */
#define MAX_LENGTH_SIP_FROM 100

/** \brief Maximum length of SIP_TO and Request-URI. */
#define MAX_LENGTH_SIP_TO 100

/** \brief Maximum length of Call-ID. */
#define MAX_LENGTH_CALL_ID 80

/** \brief Maximum length of CSeq. */
#define MAX_LENGTH_SIP_CSEQ 80

/** \brief Maximum length of User-Agent. */
#define MAX_LENGTH_USER_AGENT 80

/** \brief Maximum number of Call-ID item in storage. */
#define MAX_CALL_ID_STORAGE_SIZE 100

/** \brief Maximum string length of node in prefix tree. */
#define MAX_STRING_PREFIX_TREE_NODE 100

/** \brief Maximum size of cache_no_attack. */
#define MAX_CACHE_NO_ATTACK_SIZE 100

/** \brief Maximum length of line ALLOWED_COUNTRIES in countries file. */
#define MAX_LENGTH_ALLOWED_COUNTRIES_LINE 300

/** \brief Definition of datetime format. */
#define FORMAT_DATETIME "%Y-%m-%d %H:%M:%S"

/** \brief Length of defined datetime format (FORMAT_DATETIME). */
#define FORMAT_DATETIME_LENGTH 20

/** \brief Return code of process in case of error. */
#define RETURN_ERROR -1

/** \brief Return code of process in case of module successfully exits. */
#define RETURN_OK 0

/** \brief Enable debug mode. */
//#define DEBUG

/** \brief Enable printing detail information about invalid SIP URI. */
//#define PRINT_DETAIL_INVALID_SIPURI

#endif	/* VOIP_FRAUD_DETECTION_CONFIGURATION_H */
