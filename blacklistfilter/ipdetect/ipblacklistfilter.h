/**
 * \file ipblacklistfilter.h
 * \brief  Module for detecting blacklisted IP addresses, header file.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 * \date 2014
 * \date 2015
 */

/*
 * Copyright (C) 2013, 2014, 2015 CESNET
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
#include <unirec/unirec.h>
#include <nemea-common/nemea-common.h>

#ifndef BLACKLISTFILTER_H
#define BLACKLISTFILTER_H

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Mutex for synchronization.
 */
pthread_mutex_t BLD_SYNC_MUTEX;

/**
 * Return value for matching function when address is blacklisted.
 */
#define BLACKLISTED 1

/**
 * Return value for matching function  when the address is clear.
 */
#define ADDR_CLEAR 0

/**
 * Return value when file with blacklisted addresses cannot be loaded
 * due the I/O error, wrong format or anything else.
 */
#define BLIST_FILE_ERROR 1

/**
 * Return value if everything goes well. :-)
 */
#define ALL_OK 0

/**
 * Return value for binary search when the item is not found.
 */
#define IP_NOT_FOUND -1

/**
 * Default prefix length for ip address without prefix specification (IPv4)
 */
#define PREFIX_V4_DEFAULT 32

/**
 * Default prefix length for ip address without prefix specification (IPv6)
 */
#define PREFIX_V6_DEFAULT 128

/**
 * Regular expression to parse IP address from blacklist. (only IPv4 for now).
 */
char BLACKLIST_REG_PATTERN[] = "\\b((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)((/(3[012]|[12]?[0-9]))?)\\b";


/**
 * Structure for blacklisted addresses and prefixes
 */
typedef struct {
    /*@{*/
    ip_addr_t ip; /**< Blacklisted IP or prefix */
    uint8_t pref_length; /**< Length of the prefix. (set to 32/128 if missing) */
    uint8_t blacklist_type; /** Index of the type of blacklist (spam, tor, ..) */
    uint64_t in_blacklist; /**< Bit field of blacklists for the address. */
    /*@}*/
} ip_blist_t;


/**
 * Configuration structure.
 */
typedef struct __attribute__ ((__packed__)) {
    char blacklist_file[256];
    char watch_blacklists[8];
} config_t;

/**
 * @typedef std::vector<ip_blist_t> black_list_t;
 * Vector of blacklisted prefixes.
 */
typedef std::vector<ip_blist_t> black_list_t;

/**
 * @typedef uint32_t ipv4_mask_map_t[33];
 * Array of IPv4 netmasks.
 */
typedef uint32_t ipv4_mask_map_t[33];

/**
 * @typedef uint64_t ipv6_mask_map_t[129][2];
 * Array of IPv6 netmasks.
 */
typedef uint64_t ipv6_mask_map_t[129][2];


#ifdef __cplusplus
}
#endif

#endif /* BLACKLISTFILTER_H */
