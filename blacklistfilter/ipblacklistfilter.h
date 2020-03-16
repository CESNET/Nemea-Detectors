/**
 * \file ipblacklistfilter.h
 * \brief  Module for detecting blacklisted IP addresses, header file.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Filip Suster, sustefil@fit.cvut.cz
 * \date 2013-2018
 */

/*
 * Copyright (C) 2013, 2014, 2015, 2018 CESNET
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

#ifndef BLACKLISTFILTER_H
#define BLACKLISTFILTER_H

#include <vector>
#include <string>
#include <unirec/unirec.h>

/**
 * Special value of a blacklist index indicating adaptive blacklist
 */
#define ADAPTIVE_BLACKLIST_INDEX 999

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
 * Allocation size for variable sized UniRec output template
 */
#define IP_DETECTION_ALLOC_LEN 32768

/**
 * Structure for blacklisted addresses and prefixes
 */
typedef struct {
    ip_addr_t ip; /**< Blacklisted IP or prefix */
    uint8_t prefix_len; /**< Length of the prefix. (set to 32/128 if missing) */
    uint64_t in_blacklist; /**< Bit field of blacklists for the address. */
    std::string adaptive_ids; /**< IDs for adaptive filter events */
} ip_bl_entry_t;


/**
 * Configuration structure.
 */
typedef struct __attribute__ ((__packed__)) {
    char ipv4_blacklist_file[256];
    char ipv6_blacklist_file[256];
    char watch_blacklists[8];
} ip_config_t;

/**
 * @typedef vector<ip_bl_entry_t> black_list_t;
 * Vector of blacklisted prefixes.
 */
typedef std::vector<ip_bl_entry_t> black_list_t;

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

#endif /* BLACKLISTFILTER_H */
