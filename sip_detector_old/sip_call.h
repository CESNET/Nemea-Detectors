/**
 * \file sip_call.h
 * \brief Defines structure sip_call
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

#ifndef _SIP_CALL_H
#define	_SIP_CALL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <time.h>

#include <unirec/unirec.h>

#include "sip_constants.h"

/**
 * \brief State of values.
 */
typedef enum sip_call_value_state {
   SIP_VALUE_STATE_UNDEF = 0, ///< Undefined value
   SIP_VALUE_STATE_DEF = 1, ///< Defined value
   SIP_VALUE_STATE_PROCESSED = 2 ///< Processed value
} sip_call_value_state_t;

/**
 * \brief Structure representing a sip call.
 */
typedef struct sip_call {
   char call_id[SIP_CALL_ID_MAX_LEN]; ///< Call id
   int call_id_len; ///< Length of call id
   time_t invite_time; ///< Time of the first INVITE message
   time_t ring_time; ///< Time of the first 180 Ringing message
   time_t ok_time; ///< Time of the first OK message
   time_t bye_time; ///< Time of the first BYE message

   double ring_len; ///< Length of ringing
   sip_call_value_state_t ring_len_state; ///< State of talk_len
   double talk_len; ///< Length of talk
   sip_call_value_state_t talk_len_state; ///< State of talk_len
} sip_call_t;

/**
 * \brief Set invite_time unless invite_time is 0.
 */
void sip_call_set_invite_time(sip_call_t* call_ptr, uint64_t invite_time);

/**
 * \brief Set ring_time unless ring_time is 0.
 */
void sip_call_set_ring_time(sip_call_t* call_ptr, uint64_t ring_time);

/**
 * \brief Set ok_time unless ok_time is 0. Also update ring_len and ring_len_state.
 */
void sip_call_set_ok_time(sip_call_t* call_ptr, uint64_t ok_time);

/**
 * \brief Set bye_time unless bye_time is 0. Also update talk_len and talk_len_state.
 */
void sip_call_set_bye_time(sip_call_t* call_ptr, uint64_t bye_time);

#ifdef	__cplusplus
}
#endif

#endif	/* _SIP_CALL_H */
