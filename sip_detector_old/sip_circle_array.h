/**
 * \file sip_circle_array.h
 * \brief Defines circle_array structures 
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
#ifndef _SIP_CIRCLE_ARRAY_H
#define _SIP_CIRCLE_ARRAY_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <time.h>
#include <stdio.h>
#include <string.h>

#include <unirec/unirec.h>

#include "sip_call.h"
#include "sip_constants.h"

/**
 * \brief Circle array of different ip addresses.
 */
typedef struct sip_circle_array_ips {
   ip_addr_t items[SIP_MAX_DIFF_IPS]; ///< Items (IP addresses) of the array
   time_t times[SIP_MAX_DIFF_IPS]; ///< Times of last updates coresponding to items
   double time_windows[SIP_MAX_DIFF_IPS];
   int index;
   int count;
} sip_circle_array_ips_t;

void sip_circle_array_ips_update(sip_circle_array_ips_t* circle_array_ptr, ip_addr_t* ip_ptr);

typedef struct sip_circle_array_names {
   char items[SIP_MAX_DIFF_NAMES][SIP_NAME_MAX_LEN];
   int items_lens[SIP_MAX_DIFF_NAMES];
   time_t times[SIP_MAX_DIFF_NAMES];
   double time_windows[SIP_MAX_DIFF_NAMES];
   int index;
   int count;
} sip_circle_array_names_t;

void sip_circle_array_names_update(sip_circle_array_names_t* circle_array_ptr, const char* name_ptr, int name_size);

typedef struct sip_circle_array_calls {
   sip_call_t items[SIP_MAX_DIFF_CALLS];
   time_t times[SIP_MAX_DIFF_CALLS];
   int index;
   int count;
   int max_sim_calls;

   int ring_count;
   double ring_len_avg;
   double ring_len_var;
   int talk_count;
   double talk_len_avg;
   double talk_len_var;
} sip_circle_array_calls_t;

void sip_circle_array_calls_update(sip_circle_array_calls_t* circle_array_ptr, const char* call_id_ptr, int call_id_size, uint64_t invite_time, uint64_t ring_time, uint64_t ok_time, uint64_t bye_time);

#ifdef	__cplusplus
}
#endif

#endif
