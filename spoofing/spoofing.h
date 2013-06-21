/**
 * \file spoofing.h 
 * \brief IP spoofing detector module for Nemea -- header file
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <vector>

#ifndef SPOOFING_H
#define SPOOFING_H

#ifdef __cplusplus
extern "C" {
#endif

#define SPOOF_POSITIVE 1
#define SPOOF_NEGATIVE 0
#define BOGON_FILE_ERROR 1
#define ALL_OK 0

// structure definitions

/*
 * structure for holding bogon prefixes 
 */
typedef struct bogon_prefix {
    ip_addr_t ip;
    uint8_t pref_length;
} ip_prefix_t;

// vector used as a container of all prefixes
typedef std::vector<ip_prefix_t*> pref_list_t;

// Array of ipv4 netmasks
typedef uint32_t ipv4_mask_map_t[33];

// Array of ipv6 netmasks
typedef uint64_t ipv6_mask_map_t[129][2];

// function prototypes

/**
 * Procedures for creating an array of masks.
 * Procedure gets a reference for array and fills it with every netmask
 * possible for the ip protocol. (33 for IPv4 and 129 for IPv6).
 *
 * @param m Array to be filled
 */
void create_v4_mask_map(ipv4_mask_map_t& m);
void create_v6_mask_map(ipv6_mask_map_t& m);

/**
 * Function for loading prefix file.
 * Function reads file with network prefixes and creates a vector for use
 * filters. This function should be called only once, since loading 
 * prefixes is needed only on "cold start of the detector" or if we want to 
 * teach the detector new file. (Possile changes to get signal for loading).
 *
 * @param prefix_list Reference to a structure for containing all prefixes
 * @return 0 if everything goes smoothly else 1
 */
int load_pref (pref_list_t& prefix_list);

/**
 * Functions for checking the ip address for bogon prefixes.
 * Function gets ip address, list of prefixes loaded from file
 * and correct mask array. Then the function tries to match the ip address
 * to any of the bogon prefixes. If it succeeds the it reports the address
 * as positive spoofing and returns appropriate constant. Otherwise it
 * flags the address as negative.
 */ 
int v4_bogon_filter(ip_addr_t *checked, pref_list_t& prefix_list, ipv4_mask_map_t& v4mm);
int v6_bogon_filter(ip_addr_t *checked, pref_list_t& prefix_list, ipv6_mask_map_t& v6mm);

/**
 * Procedure for freeing memory used by bogon prefixes.
 * Procedure gets the prefix list and frees all the memory used by
 * every item in the list and then it removes all items from the list.
 */
void clear_bogon_filter(pref_list_t& prefix_list);

#ifdef __cplusplus
}
#endif

#endif /* SPOOFING_H */
