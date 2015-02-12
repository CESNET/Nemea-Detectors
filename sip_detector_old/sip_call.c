/**
 * \file sip_call.c
 * \brief Defines sip_call_t structure representing a sip call.
 * \author Nikolas Jisa <jisaniko@fit.cvut.cz>
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

#include "sip_call.h"

void sip_call_set_invite_time(sip_call_t* call_ptr, uint64_t invite_time) {
   if (invite_time == 0) {
      return;
   }
   call_ptr->invite_time = (time_t) invite_time/1000;
}

void sip_call_set_ring_time(sip_call_t* call_ptr, uint64_t ring_time) {
   if (call_ptr->ring_len_state != SIP_VALUE_STATE_UNDEF || ring_time == 0) {
      return;
   }
   call_ptr->ring_time = (time_t) ring_time/1000;
}

void sip_call_set_ok_time(sip_call_t* call_ptr, uint64_t ok_time) {
   if (call_ptr->ring_len_state != SIP_VALUE_STATE_UNDEF || call_ptr->talk_len_state != SIP_VALUE_STATE_UNDEF || ok_time == 0) {
      return;
   }
   call_ptr->ok_time = (time_t) ok_time/1000;
   if (call_ptr->ok_time > call_ptr->ring_time) {
      call_ptr->ring_len = difftime(call_ptr->ok_time, call_ptr->ring_time);
   } else {
      call_ptr->ring_len = 0;
   }
   call_ptr->ring_len_state = SIP_VALUE_STATE_DEF;
}

void sip_call_set_bye_time(sip_call_t* call_ptr, uint64_t bye_time) {
   if (call_ptr->talk_len_state != SIP_VALUE_STATE_UNDEF || bye_time == 0) {
      return;
   }
   call_ptr->bye_time = (time_t) bye_time/1000;
   if (call_ptr->bye_time > call_ptr->ok_time) {
      call_ptr->talk_len = difftime(call_ptr->bye_time, call_ptr->ok_time);
   } else {
      call_ptr->talk_len = 0;
   }
   call_ptr->talk_len_state = SIP_VALUE_STATE_DEF;
}
