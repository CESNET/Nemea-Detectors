/**
 * \file blacklistfilter.h 
 * \brief IP blacklist detector for Nemea -- header file
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

/*
 * Copyright (C) 2013 CESNET
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
#include "../../unirec/unirec.h"
#include "../../common/cuckoo_hash/cuckoo_hash.h"

#ifndef BLACKLISTFILTER_H
#define BLACKLISTFILTER_H

#ifdef __cplusplus
extern "C" {
#endif

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
 * Constant returned by update function for prefixes when an existing item was 
 * updated.
 */
#define BL_ENTRY_UPDATED -1

/**
 * Inital size for the hash table of addresses.
 */
#define BL_HASH_SIZE 100000

// structure definitions

/**
 * Structure for blacklisted addresses and prefixes
 */
typedef struct {
    /*@{*/
    ip_addr_t ip;
    uint8_t pref_length; /**< Length of the prefix. (set to 32/128 if missing) */  
    uint8_t in_blacklist; /**< ID number of blacklist for the address. */
    /*@}*/
} ip_blist_t;

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

// function prototypes

/*
 * Procedures for creating an array of masks.
 * Procedure gets a reference for array and fills it with every netmask
 * possible for the ip protocol. (33 for IPv4 and 129 for IPv6).
 */
void create_v4_mask_map(ipv4_mask_map_t& m);
void create_v6_mask_map(ipv6_mask_map_t& m);

/*
 */
//int load_ip (black_list_t& black_list_v4, black_list_t& black_list_v6, const char *source_dir);

/*
 */ 
//int v4_blacklist_check(ur_template_t* ur_tmp, const void *record, black_list_t& black_list, ipv4_mask_map_t& v4mm);
//int v6_blacklist_check(ur_template_t* ur_tmp, const void *record, black_list_t& black_list, ipv6_mask_map_t& v6mm);

/*
 * Functions/procedures for updating blacklists.
 */
int update_add(cc_hash_table_t& bl_hash, black_list_t& bl_v4, black_list_t& bl_v6, black_list_t& add_upd, ipv4_mask_map_t& m4, ipv6_mask_map_t& m6);
void update_remove(cc_hash_table_t& bl_hash, black_list_t& bl_v4, black_list_t& bl_v6, black_list_t& rm_upd, ipv4_mask_map_t& m4, ipv6_mask_map_t& m6);




#ifdef __cplusplus
}
#endif

#endif /* BLACKLISTFILTER_H */
