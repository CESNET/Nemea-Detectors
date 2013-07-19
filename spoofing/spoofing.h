/**
 * \file spoofing.h 
 * \brief IP spoofing detector module for Nemea -- header file
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
 */

#include <vector>
#include <map>
#include "../../unirec/unirec.h"
#include "BloomFilter.hpp"

#ifndef SPOOFING_H
#define SPOOFING_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Return value for filters when spoofing is found.
 */
#define SPOOF_POSITIVE 1

/**
 * Return value for filters when the flow is clear.
 */
#define SPOOF_NEGATIVE 0

/**
 * Return value when file with prefixes cannot be loaded 
 * due the I/O error, wrong format or anything else.
 */
#define PREFIX_FILE_ERROR 1

/**
 * Return value if everything goes well. :-)
 */
#define ALL_OK 0

/**
 * Return value for binary search when the item is not found.
 */
#define IP_NOT_FOUND -1

/**
 * Default value for update time of records in symetric routing map in seconds.
 */
#define SYM_RW_DEFAULT 45

/**
 * Default threshold for new flow counter used for warning.
 */
#define NEW_FLOW_DEFAULT 100000000

/**
 * Time setting for swapping the Bloom filters in seconds.
 */
#define BF_SWAP_TIME 300

// structure definitions

/**
 * Structure for bogon prefixes
 */
typedef struct {
    /*@{*/
    ip_addr_t ip; /**< IP address of the prefix. */
    uint8_t pref_length; /**< Length of the prefix. */
    /*@}*/
} ip_prefix_t;

/**
 * Structure for keeping the source addresses in symetric filter.
 */
typedef struct {
    /*@{*/
    uint64_t link; /**< Bitmap of the links used by the sources */
    uint64_t timestamp; /**< Timestamp of the structure being added to the filter */
//    uint8_t ttl; // TTL of the packet going over this link
    /*@}*/
} sym_src_t;


/**
 * @typedef std::vector<ip_prefix_t> pref_list_t
 * Vector used as a container of all prefixes.
 */
typedef std::vector<ip_prefix_t> pref_list_t;

/**
 * @typedef std::map<unsigned, sym_src_t> v4_sym_sources_t;
 * Map of links associated to source ip addresses (IPv4).
 */
typedef std::map<unsigned, sym_src_t> v4_sym_sources_t;

/**
 * @typedef std::map<uint64_t, sym_src_t> v6_sym_sources_t;
 * Map of links associated to source ip addresses (IPv6).
 */
typedef std::map<uint64_t, sym_src_t> v6_sym_sources_t;

/**
 * Structure for new flow counter with bloom filter and counter
 */
typedef struct {
    /*@{*/
    bloom_filter* sources; /**< Pointer to bloom filter for the watched network */
    unsigned long count; /**< Number of currently used flows */
    /*@}*/
} flow_count_t;


/**
 * Structure with set of bloom filters for the new flow counter.
 */
typedef struct {
    /*@{*/
    std::vector<flow_count_t> flows; /**< Vector with filters */
    uint64_t timestamp; /**< Timestamp of activation of the set */
    /*@}*/
} flow_filter_t;

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
 * Function for loading prefix file.
 * Function reads file with network prefixes and creates a vector for use
 * filters. This function should be called only once, since loading 
 * prefixes is needed only on "cold start of the detector" or if we want to 
 * teach the detector new file. (Possile changes to get signal for loading).
 */
int load_pref (pref_list_t& prefix_list_v4, pref_list_t& prefix_list_v6, const char *bogon_file);


/*
 * Functions for checking the ip address for bogon prefixes.
 * Function gets ip address, list of prefixes loaded from file
 * and correct mask array. Then the function tries to match the ip address
 * to any of the bogon prefixes. If it succeeds the it reports the address
 * as positive spoofing and returns appropriate constant. Otherwise it
 * flags the address as negative.
 */ 
int v4_bogon_filter(ur_template_t* ur_tmp, const void *checked, pref_list_t& prefix_list, ipv4_mask_map_t& v4mm);
int v6_bogon_filter(ur_template_t* ur_tmp, const void *checked, pref_list_t& prefix_list, ipv6_mask_map_t& v6mm);

/*
 * Functions for checking routing symetry.
 * Functions get records and their respective maps of the links used for 
 * communication by devices in record (src and dst). If the flow keeps 
 * using the same link for the communication then it considered legit.
 * Otherwise it is flagged as possible spoofing.
 */
int check_symetry_v4(ur_template_t* ur_tmp, const void *record, v4_sym_sources_t& src, unsigned rw_time);
int check_symetry_v6(ur_template_t* ur_tmp, const void *record, v6_sym_sources_t& src, unsigned rw_time);

/*
 * Functions for recording new incomming data flows.
 * Functions get their respective sets of Bloom filters and lists of checked IP 
 * prefixes and then it records all inbound traffic with these netwroks as 
 * destinations. If any network has exceeded the threshold of flows then 
 * all source addresses that want to communicate are reported as potentially spoofed.
 */
int check_new_flows_v4(ur_template_t* ur_tmp, const void *record, unsigned threshold, flow_filter_t* filter, ipv4_mask_map_t& mm, pref_list_t& prefix_list);
int check_new_flows_v6(ur_template_t* ur_tmp, const void *record, unsigned threshold, flow_filter_t* filter, ipv6_mask_map_t& mm, pref_list_t& prefix_list);

#ifdef __cplusplus
}
#endif

#endif /* SPOOFING_H */
