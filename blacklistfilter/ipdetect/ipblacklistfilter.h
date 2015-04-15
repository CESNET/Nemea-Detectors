/**
 * \file ipblacklistfilter.h
 * \brief IP blacklist detector for Nemea -- header file
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \date 2013
 * \date 2014
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

#include <vector>
#include <unirec/unirec.h>
#include <cuckoo_hash_v2.h>
#include <nemea-common.h>

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
 * Static mode ID.
 */
#define BL_STATIC_MODE 1

/**
 * Dynamic mode ID.
 */
#define BL_DYNAMIC_MODE 2

/**
 * Inital size for the hash table of addresses.
 */
#define BL_HASH_SIZE 100000

/**
 * Time to wait between blacklist updates.
 */
#define BLACKLIST_UPDATE_DELAY_TIME 600

/**
 * Maximum length of one line to parse from blacklist website.
 */
#define BLACKLIST_LINE_MAX_LENGTH 1024

/**
 * Maximum length of one element (in this case, it is maximum length of IP address).
 */
#define BLACKLIST_EL_MAX_LENGTH 64

/**
 * Maximum count of elements in one update (in this case, it is maximum IP addresses per update)
 */
#define BLACKLIST_EL_MAX_COUNT 100000

/**
 * Blacklist update mode. Do NOT change it unless you know what you are doing.
 */
#define BLACKLIST_UPDATE_MODE DIFF_UPDATE_MODE

/**
 * Default inactive timeout in seconds.
 */
#define DEFAULT_TIMEOUT_INACTIVE 30

/**
 * Default active timeout in seconds.
 */
#define DEFAULT_TIMEOUT_ACTIVE 300

/**
 * Default aggregation hash table size.
 */
#define DEFAULT_HASH_TABLE_SIZE 500000


// global definitions

/**
 * Comments character for every blacklist website.
 */
char *BLACKLIST_COMMENT_AR = (char*)"#####";

/**
 * Regular expression to parse IP address from blacklist. (only IPv4 for now).
 */

char *BLACKLIST_REG_PATTERN = (char*)"\\b((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)((/(3[012]|[12]?[0-9]))?)\\b";

// structure definitions

/**
 * Structure for data aggregation
 */
typedef struct {
   uint32_t time_first;
   uint32_t time_last;
   char data[1];
} aggr_data_t;

/**
 * Structure for data aggregation
 */
typedef struct {
   ip_addr_t srcip;
   ip_addr_t dstip;
   uint8_t proto;
} aggr_data_key_t;


/**
 * Structure for blacklisted addresses and prefixes
 */
typedef struct {
    /*@{*/
    ip_addr_t ip;
    uint8_t pref_length; /**< Length of the prefix. (set to 32/128 if missing) */
    uint64_t in_blacklist; /**< Bit field of blacklists for the address. */
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
