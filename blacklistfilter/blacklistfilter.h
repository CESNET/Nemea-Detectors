/**
 * \file blacklist_main.h 
 * \brief IP blacklist detector for Nemea -- header file
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <vector>
#include "../../unirec/unirec.h"

#ifndef BLACKLIST_MAIN_H
#define BLACKLIST_MAIN_H

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

#define PREFIX_V4_DEFAULT 32
#define PREFIX_V6_DEFAULT 128

#define BL_ENTRY_UPDATED 1


// structure definitions

/**
 * Structure for bogon prefixes
 */
typedef struct {
    /*@{*/
    ip_addr_t ip;
    uint8_t pref_length; /**< Length of the prefix. (set to 32/128 if missing) */  
    unsigned in_blacklist; /**< ID number of blacklist for the address. */
    /*@}*/
} ip_blist_t;

/**
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
int load_ip (black_list_t& black_list_v4, black_list_t& black_list_v6, const char *source_dir);

/*
 */ 
int v4_blacklist_check(ur_template_t* ur_tmp, const void *record, black_list_t& black_list, ipv4_mask_map_t& v4mm);
int v6_blacklist_check(ur_template_t* ur_tmp, const void *record, black_list_t& black_list, ipv6_mask_map_t& v6mm);

#ifdef __cplusplus
}
#endif

#endif /* SPOOFING_H */
