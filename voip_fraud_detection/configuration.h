/**
 * \file configuration.h
 * \brief VoIP fraud detection module - configuration - header file
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

/** \brief UniRec input template definition. */
#define UNIREC_INPUT_TEMPLATE "<COLLECTOR_FLOW>,<VOIP>"

/** \brief UniRec output template definition. */
#define UNIREC_OUTPUT_TEMPLATE "<VOIP_FRAUD_ALERT>"

/** \brief Default value of max_prefix_length.
 * If parameter max_prefix_length not set at startup of module, then this default value is used. */
#define DEFAULT_MAX_PREFIX_LENGTH 10

/** \brief Default value of min_lenght_called_number.
 * If parameter min_lenght_called_number not set at startup of module, then this default value is used. */
#define DEFAULT_MIN_LENGTH_CALLED_NUMBER 0

/** \brief Default value of prefix_examination_detection_threshold.
 * If parameter prefix_examination_detection_threshold not set at startup of module, then this default value is used. */
#define DEFAULT_PREFIX_EXAMINATION_DETECTION_THRESHOLD 10

/** \brief Default value of detection_interval.
 * If parameter detection_interval not set at startup of module, then this default value is used. */
#define DEFAULT_DETECTION_INTERVAL 10

/** \brief Default value of detection_pause_after_attack.
 * If parameter detection_pause_after_attack not set at startup of module, then this default value is used. */
#define DEFAULT_DETECTION_PAUSE_AFTER_ATTACK 30

/** \brief Default value of max_item_prefix_tree.
 * If parameter max_item_prefix_tree not set at startup of module, then this default value is used. */
#define DEFAULT_MAX_ITEM_PREFIX_TREE 100000

/** \brief Default value of time_clear_data_no_communication (1209600 seconds = 14days, 604800 seconds = 7 days).
 * If parameter time_clear_data_no_communication not set at startup of module, then this default value is used. */
#define DEFAULT_CLEAR_DATA_NO_COMMUNICATION_AFTER 1209600

/** \brief Default name of event_id file. */
#define DEFAULT_EVENT_ID_FILE "event_id"

/** \brief Interval defined in seconds for running check_and_clear_module_memory() function. */
#define CHECK_MEMORY_INTERVAL 60

/** \brief Default size of hashing table for storing IP addresses. */
#define HASH_TABLE_IP_SIZE 100000

/** \brief Maximum length of SIP_FROM. */
#define MAX_LENGTH_SIP_FROM 100

/** \brief Maximum length of SIP_TO. */
#define MAX_LENGTH_SIP_TO 100

/** \brief Maximum length of Call-ID. */
#define MAX_LENGTH_CALL_ID 80

/** \brief Maximum number of Call-ID item in storage. */
#define CALL_ID_STORAGE_SIZE 20

/** \brief Maximum string length of node in prefix tree. */
#define MAX_STRING_PREFIX_TREE_NODE 100

/** \brief Maximum size of cache_no_attack. */
#define MAX_CACHE_NO_ATTACK_SIZE 100

/** \brief Definition of datetime format. */
#define FORMAT_DATETIME "%Y-%m-%d %H:%M:%S"

/** \brief Return code of process in case of error. */
#define RETURN_ERROR -1

/** \brief Return code of process in case of module successfully exits. */
#define RETURN_OK 0

/** \brief Enable debug mode. */
#define DEBUG

/** \brief Enable testing debug mode. */
#define TEST_DEBUG

/** \brief Enable printing detail information about invalid SIP URI. */
#define PRINT_DETAIL_INVALID_SIPURI

/** \brief Modul_configuration structure.
 * It is used for saving modul configuration.
 */
struct modul_configuration_struct {
   unsigned int max_prefix_length;
   unsigned int min_length_called_number;
   unsigned int prefix_examination_detection_threshold;
   unsigned int detection_interval;
   unsigned int detection_pause_after_attack;
   unsigned int max_item_prefix_tree;
   unsigned int clear_data_no_communication_after;
   char * log_file;
   char * event_id_file;
};

/** \brief Definition of modul_configuration (modul_configuration_struct).
 */
struct modul_configuration_struct modul_configuration;

#endif	/* VOIP_FRAUD_DETECTION_CONFIGURATION_H */
