/**
 * \file country.h
 * \brief VoIP fraud detection module - country - header file
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

#ifndef VOIP_FRAUD_DETECTION_COUNTRY_H
#define VOIP_FRAUD_DETECTION_COUNTRY_H

#include <cuckoo_hash_v2.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "data_structure.h"
#include "output.h"

#ifdef ENABLE_GEOIP

#include <GeoIP.h>

/** \brief GeoIP database pointers. */
GeoIP *geo_ipv4, *geo_ipv6;

/** \brief GeoIP temp variable (for finding in GeoIP database). */
GeoIPLookup geoip_lookup;

/** \brief Time of the last saving countries from memory to the defined countries file. */
time_t time_last_countries_file_saved;

/** \brief Last used Event ID of attack detection (extern). */
extern uint32_t last_event_id;

/** \brief Load GeoIP databases to memory. */
void geoip_databases_load();

/** \brief Free GeoIP databases from memory. */
void geoip_databases_free();

/** \brief Save country to storage of the IP address.
 * \param[in] ip Definition of hash table item.
 * \param[in] country Char array to country definition.
 * \param[in] hash_table_ip Pointer to hash table of IP addresses.
 */
void country_ip_save(ip_item_t * ip, const char * country, cc_hash_table_v2_t * hash_table_ip);

/** \brief Check if country exists in storage of the IP address.
 * \param[in] ip Definition of hash table item.
 * \param[in] country Char array to country definition.
 * \return Return 1 if country exists, 0 otherwise.
 */
int country_ip_exists(ip_item_t * ip, const char * country);

/** \brief Power off learning countries mode and start detection of calling to different countries.
 * \param[in] signum not used.
 */
void countries_power_off_learning_mode(int signum);

/** \brief Load all countries from defined file to memory.
 * \param[in] file Definition of file path.
 * \param[in] hash_table_ip Pointer to hash table of IP addresses.
 * \return Return 0 if all countries are successfully loaded from file, -1 if error occurs.
 */
int countries_load_all_from_file(char * file, cc_hash_table_v2_t * hash_table_ip);

/** \brief Save all countries from memory to defined file.
 * \param[in] file Definition of file path.
 * \param[in] hash_table_ip Pointer to hash table of IP addresses.
 */
void countries_save_all_to_file(char * file, cc_hash_table_v2_t * hash_table_ip);

/** \brief Get domain name or IP adrress from input URI.
 * \param[in] str Input string (URI).
 * \param[in] str_len Integer - length of input string.
 * \return Return pointer to static char array with result.
 */
char * get_domain(char * str, int str_len);

/** \brief Detection of calling to different countries and write/send information about it.
 * \param[in] hash_table Pointer to hash table of IP addresses.
 * \param[in] hash_table_item Pointer to item of IP address (detection is performed for this IP).
 * \param[in] sip_to SIP To header.
 * \param[in] sip_to_len Length of SIP To header.
 * \param[in] sip_from SIP From header.
 * \param[in] user_agent SIP User-Agent header.
 * \param[in] ip_src Source IP address.
 * \param[in] ip_dst Destination IP address.
 * \return ID that indicates results of detection (STATE_NO_ATTACK or STATE_ATTACK_DETECTED).
 */
int country_different_call_detection(cc_hash_table_v2_t * hash_table, ip_item_t * hash_table_item, char *sip_to, int sip_to_len, char *sip_from, char *user_agent, ip_addr_t * ip_src, ip_addr_t * ip_dst);

/** \brief Free all memory allocated for countries. */
void countries_free();

#endif

#endif	/* VOIP_FRAUD_DETECTION_COUNTRY_H */
