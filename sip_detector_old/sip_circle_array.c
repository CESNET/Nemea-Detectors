/**
 * \file sip_circle_array.c
 * \brief Defines circle_array structures 
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

#include "sip_circle_array.h"

void sip_circle_array_ips_update(sip_circle_array_ips_t* circle_array_ptr, ip_addr_t* ip_ptr) {
   int index = -1;
   for (int i = 0, j = (circle_array_ptr->index + SIP_MAX_DIFF_IPS - 1) % SIP_MAX_DIFF_IPS; i < circle_array_ptr->count; i++, j = (j + SIP_MAX_DIFF_IPS - 1) % SIP_MAX_DIFF_IPS) {
      if (ip_cmp(&circle_array_ptr->items[j], ip_ptr) == 0) {
         index = j;
         break;
      }
   }
   
   if (index == -1) {
      index = circle_array_ptr->index;
      circle_array_ptr->items[index] = *ip_ptr;
      if (circle_array_ptr->count != SIP_MAX_DIFF_IPS) {
         circle_array_ptr->count++;
      }
      circle_array_ptr->index = (index + 1) % SIP_MAX_DIFF_IPS;
   }
   else {
      int index2;
      while ((index2 = ((index + 1) % SIP_MAX_DIFF_IPS)) != (circle_array_ptr->index)) {
         circle_array_ptr->times[index] = circle_array_ptr->times[index2];
         circle_array_ptr->items[index] = circle_array_ptr->items[index2];
         index = index2;
      }
      circle_array_ptr->items[index] = *ip_ptr;
   }
   time(&circle_array_ptr->times[index]);
   double tmp_time_window;
   for (int i = 0, j = index; i < circle_array_ptr->count; i++, j = (j + SIP_MAX_DIFF_IPS - 1) % SIP_MAX_DIFF_IPS) {
         tmp_time_window = difftime(circle_array_ptr->times[index], circle_array_ptr->times[j]);
         if (tmp_time_window < circle_array_ptr->time_windows[i] || circle_array_ptr->time_windows[i] == 0.0) {
            circle_array_ptr->time_windows[i] = tmp_time_window;
         }
   }
}

void sip_circle_array_names_update(sip_circle_array_names_t* circle_array_ptr, const char* name_ptr, int name_size) {
   int index = -1;
   int len = name_size > SIP_NAME_MAX_LEN ? SIP_NAME_MAX_LEN : name_size;
   for (int i = 0, j = (circle_array_ptr->index + SIP_MAX_DIFF_NAMES - 1) % SIP_MAX_DIFF_NAMES; i < circle_array_ptr->count; i++, j = (j + SIP_MAX_DIFF_NAMES - 1) % SIP_MAX_DIFF_NAMES) {
      if (len == circle_array_ptr->items_lens[j] && strncmp(circle_array_ptr->items[j], name_ptr, len) == 0) {
         index = j;
         break;
      }
   }
   
   if (index == -1) {
      index = circle_array_ptr->index;
      memcpy(circle_array_ptr->items[index], name_ptr, len);
      circle_array_ptr->items_lens[index] = len;
      if (circle_array_ptr->count != SIP_MAX_DIFF_NAMES) {
         circle_array_ptr->count++;
      }
      circle_array_ptr->index = (index + 1) % SIP_MAX_DIFF_NAMES;
   }
   else {
      int index2;
      while ((index2 = ((index + 1) % SIP_MAX_DIFF_NAMES)) != (circle_array_ptr->index)) {
         circle_array_ptr->times[index] = circle_array_ptr->times[index2];
         memcpy(circle_array_ptr->items[index], circle_array_ptr->items[index2], circle_array_ptr->items_lens[index2]);
         circle_array_ptr->items_lens[index] = circle_array_ptr->items_lens[index2];
         index = index2;
      }
      memcpy(circle_array_ptr->items[index], name_ptr, len);
      circle_array_ptr->items_lens[index] = len;
   }
   time(&circle_array_ptr->times[index]);
   double tmp_time_window;
   for (int i = 0, j = index; i < circle_array_ptr->count; i++, j = (j + SIP_MAX_DIFF_NAMES - 1) % SIP_MAX_DIFF_NAMES) {
         tmp_time_window = difftime(circle_array_ptr->times[index], circle_array_ptr->times[j]);
         if (tmp_time_window < circle_array_ptr->time_windows[i] || circle_array_ptr->time_windows[i] == 0.0) {
            circle_array_ptr->time_windows[i] = tmp_time_window;
         }
   }
}

static void sip_circle_array_calls_update_ring_len(sip_circle_array_calls_t* circle_array_ptr, sip_call_t* call_ptr) {
   if (call_ptr->ring_len_state == SIP_VALUE_STATE_DEF) {
      int* count_ptr = &circle_array_ptr->ring_count;
      double* avg_ptr = &circle_array_ptr->ring_len_avg;
      double old_avg = *avg_ptr;
      double* var_ptr = &circle_array_ptr->ring_len_var;

      *avg_ptr = (*avg_ptr * *count_ptr + call_ptr->ring_len)/(*count_ptr + 1);
      *var_ptr = (*count_ptr * (*var_ptr + old_avg * old_avg) + call_ptr->ring_len * call_ptr->ring_len) / (*count_ptr + 1) - *avg_ptr * *avg_ptr;
      *count_ptr = *count_ptr + 1;
      call_ptr->ring_len_state = SIP_VALUE_STATE_PROCESSED;
   }
}

static void sip_circle_array_calls_update_talk_len(sip_circle_array_calls_t* circle_array_ptr, sip_call_t* call_ptr) {
   if (call_ptr->talk_len_state == SIP_VALUE_STATE_DEF) {
      int* count_ptr = &circle_array_ptr->talk_count;
      double* avg_ptr = &circle_array_ptr->talk_len_avg;
      double old_avg = *avg_ptr;
      double* var_ptr = &circle_array_ptr->talk_len_var;

      *avg_ptr = (*avg_ptr * *count_ptr + call_ptr->talk_len)/(*count_ptr + 1);
      if(*count_ptr == 1) {
         *var_ptr = 0;
      } else {
         *var_ptr = (*count_ptr * (*var_ptr + old_avg * old_avg) + call_ptr->talk_len * call_ptr->talk_len) / (*count_ptr + 1) - *avg_ptr * *avg_ptr;
      *count_ptr = *count_ptr + 1;
      }
      call_ptr->talk_len_state = SIP_VALUE_STATE_PROCESSED;
   }
}

void sip_circle_array_calls_update(sip_circle_array_calls_t* circle_array_ptr, const char* call_id_ptr, int call_id_size, uint64_t invite_time, uint64_t ring_time, uint64_t ok_time, uint64_t bye_time) {
   int index = -1;
   int len = call_id_size > SIP_CALL_ID_MAX_LEN ? SIP_CALL_ID_MAX_LEN : call_id_size;
   for (int i = 0, j = (circle_array_ptr->index + SIP_MAX_DIFF_CALLS - 1) % SIP_MAX_DIFF_CALLS; i < circle_array_ptr->count; i++, j = (j + SIP_MAX_DIFF_CALLS - 1) % SIP_MAX_DIFF_CALLS) {
      if (len == circle_array_ptr->items[j].call_id_len && strncmp(circle_array_ptr->items[j].call_id, call_id_ptr, len) == 0) {
         index = j;
         break;
      }
   }
   sip_call_t* call_ptr;
   if (index == -1) {
      index = circle_array_ptr->index;
      if (circle_array_ptr->count != SIP_MAX_DIFF_CALLS) {
         circle_array_ptr->count++;
         if (circle_array_ptr->count > circle_array_ptr->max_sim_calls) {
            circle_array_ptr->max_sim_calls = circle_array_ptr->count;
         }
      }
      circle_array_ptr->index = (index + 1) % SIP_MAX_DIFF_CALLS;
      call_ptr = &circle_array_ptr->items[index];
      memset(call_ptr, 0, sizeof(sip_call_t));
      memcpy(call_ptr->call_id, call_id_ptr, len);
      
      time_t t = time(NULL);
      call_ptr->invite_time = t;
      call_ptr->ring_time = t;
      call_ptr->ok_time = t;

      call_ptr->call_id_len = len;
   }
   else {
      sip_call_t tmp_call = circle_array_ptr->items[index];
      int index2;
      while ((index2 = ((index + 1) % SIP_MAX_DIFF_CALLS)) != (circle_array_ptr->index)) {
         circle_array_ptr->times[index] = circle_array_ptr->times[index2];
         circle_array_ptr->items[index] = circle_array_ptr->items[index2];
         index = index2;
      }
      circle_array_ptr->items[index] = tmp_call;
   }
   call_ptr = &circle_array_ptr->items[index];
   
   sip_call_set_invite_time(call_ptr, invite_time);
   sip_call_set_ring_time(call_ptr, ring_time);
   sip_call_set_ok_time(call_ptr, ok_time);
   sip_call_set_bye_time(call_ptr, bye_time);
   
   sip_circle_array_calls_update_ring_len(circle_array_ptr, call_ptr);
   sip_circle_array_calls_update_talk_len(circle_array_ptr, call_ptr);
   
   time(&circle_array_ptr->times[index]);
   
   if (bye_time != 0) {
      circle_array_ptr->count--;
      circle_array_ptr->index = index;
      memset(call_ptr, 0, sizeof(sip_call_t));
   }
}
