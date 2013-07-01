/**
 * \file spoofing.h 
 * \brief IP spoofing detector module for Nemea -- header file
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <vector>
#include <map>
#include <set>
#include "../unirec.h"

#ifndef SPOOFING_H
#define SPOOFING_H

#ifdef __cplusplus
extern "C" {
#endif

#define SPOOF_POSITIVE 1
#define SPOOF_NEGATIVE 0
#define BOGON_FILE_ERROR 1
#define ALL_OK 0
#define SYM_RW_DEFAULT 45
#define NEW_FLOW_DEFAULT 100

// structure definitions

/*
 * structure for holding bogon prefixes 
 */
typedef struct bogon_prefix {
    ip_addr_t ip;
    uint8_t pref_length;
} ip_prefix_t;

/*
 * structure for keeping the source addresses in symetric filter
 */
typedef struct symetric_src {
    uint64_t link;
    uint64_t timestamp;
} sym_src_t;

// vector used as a container of all prefixes
typedef std::vector<ip_prefix_t> pref_list_t;

// map of link associated to source ip addresses
typedef std::map<unsigned, sym_src_t> v4_sym_sources_t;
typedef std::map<uint64_t, sym_src_t> v6_sym_sources_t;

// set for keeping destinations of the flows
typedef std::set<unsigned> v4_flow_dst_t;
typedef std::set<uint64_t> v6_flow_dst_t;

//
typedef struct flow_count_v4_s {
    v4_flow_dst_t v4_src;
    unsigned count;
//    uint64_t add_timestamp;
} flow_count_v4_t;

typedef struct flow_count_v6_s {
    v6_flow_dst_t v6_src;
    unsigned count;
//    uint64_t add_timestamp;
} flow_count_v6_t;

//
typedef std::map<unsigned, flow_count_v4_t> v4_flows_t;
typedef std::map<uint64_t, flow_count_v6_t> v6_flows_t;


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
int load_pref (pref_list_t& prefix_list_v4, pref_list_t& prefix_list_v6, const char *bogon_file);


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

/**
 * Functions for checking routing symetry.
 * Functions get records and their respective maps of the links used for 
 * communication by devices in record (src and dst). If the flow keeps 
 * using the same link for the communication then it considered legit.
 * Otherwise it is flagged as possible spoofing.
 */
int check_symetry_v4(ur_basic_flow_t *record, v4_sym_sources_t& src, unsigned rw_time);
int check_symetry_v6(ur_basic_flow_t *record, v6_sym_sources_t& src, unsigned rw_time);


//
int check_new_flows_v4(ur_basic_flow_t *record, v4_flows_t& flow_map, unsigned threshold);
int check_new_flows_v6(ur_basic_flow_t *record, v6_flows_t& flow_map, unsigned threshold);

#ifdef __cplusplus
}
#endif

#endif /* SPOOFING_H */
