/**
 * \file sip_ip_entry.h
 * \brief Defines structure sip_ip_entry_t which represents an IP address with SIP statistics.
 * \author Nikolas Jíša <jisaniko@fit.cvut.cz>
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

#ifndef _SIP_IP_ENTRY_H
#define	_SIP_IP_ENTRY_H

#include <stdio.h>

#include <regex.h>
#include <unirec/unirec.h>

#include "sip_constants.h"
#include "sip_circle_array.h"
#include "sip_stats.h"

/**
 * \brief Structure representing an entry identified by IP address with SIP statistics.
 */
typedef struct sip_ip_entry {
   ip_addr_t ip; ///< IP address
   sip_circle_array_ips_t dst_ips_circle_array; ///< Circle array with different destination IP addresses to which this IP address sent a SIP message
   sip_circle_array_ips_t src_ips_circle_array; ///< Circle array with different source IP addresses from which this IP address received a SIP messages
   sip_circle_array_names_t as_src_from_names_circle_array; ///< Circle array with different source names (FROM/REQUEST_URI) with which this IP address sent a SIP message
   sip_circle_array_names_t as_src_to_names_circle_array; ///< Circle array with different destination names (TO) with which this IP address sent a SIP message
   sip_circle_array_names_t as_dst_from_names_circle_array; ///< Circle array with different source names (FROM/REQUEST_URI) with which this IP address received a SIP message
   sip_circle_array_names_t as_dst_to_names_circle_array; ///< Circle array with different destination names (TO) with which this IP address received a SIP message
   sip_circle_array_calls_t in_calls_circle_array; ///< Circle array with inward calls
   sip_circle_array_calls_t out_calls_circle_array; ///< Circle array with outward calls
   uint32_t as_proxy; ///< Counter of how many times this IP address acted as proxy
   uint32_t as_ep_from; ///< Counter of how many times this IP address acted as source IP address
   uint32_t as_ep_to; ///< Counter of how many times this IP address acted as destination IP address
} sip_ip_entry_t;

void sip_ip_entry_update_diff_ips(sip_ip_entry_t* src_ip_entry_ptr, sip_ip_entry_t* dst_ip_entry_ptr, ur_template_t* tmplt, const void* data);
void sip_ip_entry_update_diff_names(sip_ip_entry_t* src_ip_entry_ptr, sip_ip_entry_t* dst_ip_entry_ptr, ur_template_t* tmplt, const void* data);
void sip_ip_entry_update_calls(sip_ip_entry_t* src_ip_entry_ptr, sip_ip_entry_t* dst_ip_entry_ptr, ur_template_t* tmplt, const void* data);

// Method to print statistics of an ip_entry_ptr to an opened file.
void sip_ip_entry_print(FILE* file, sip_ip_entry_t* ip_entry_ptr);

#endif

