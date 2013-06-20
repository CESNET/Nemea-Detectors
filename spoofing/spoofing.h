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

// structure definitions

typedef struct bogon_prefix {
    ip_addr_t ip;
    uint8_t pref_length;
} ip_prefix_t;

typedef std::vector<ip_prefix_t*> pref_list_t;
typedef uint32_t ipv4_mask_map_t[33];
typedef uint64_t ipv6_mask_map_t[129][2];

// function prototypes
 
void create_v4_mask_map(ipv4_mask_map_t& m);
void create_v6_mask_map(ipv6_mask_map_t& m);
int load_pref (pref_list_t& prefix_list);
int v4_bogon_filter(ur_basic_flow_t *analyzed, pref_list_t& prefix_list, ipv4_mask_map_t& v4mm);
void clear_bogon_filter(pref_list_t& prefix_list);

#ifdef __cplusplus
}
#endif

#endif /* SPOOFING_H */
