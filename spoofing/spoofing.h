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

typedef vector<ip_addr_t> preflist pref_list_t; 

// function prototypes
int load_pref (&pref_list_t prefix_list);
int bogon_filter(ur_basic_flow_t *analyzed);

#ifdef __cplusplus
}
#endif

#endif /* SPOOFING_H */
