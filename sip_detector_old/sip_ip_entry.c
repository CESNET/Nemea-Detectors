/**
 * \file sip_ip_entry.c
 * \brief Defines structure sip_ip_entry_t which represents an IP address with SIP statistics.
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

#include "sip_ip_entry.h"

void sip_ip_entry_update_diff_ips(sip_ip_entry_t* src_ip_entry_ptr, sip_ip_entry_t* dst_ip_entry_ptr, ur_template_t* tmplt, const void* data) {
   ip_addr_t* src_ip_ptr = ur_get_ptr(tmplt, data, UR_SRC_IP);
   ip_addr_t* dst_ip_ptr = ur_get_ptr(tmplt, data, UR_DST_IP);
   if (src_ip_entry_ptr != NULL) {
      sip_circle_array_ips_update(&src_ip_entry_ptr->dst_ips_circle_array, dst_ip_ptr);
   }
   if (dst_ip_entry_ptr != NULL) {
      sip_circle_array_ips_update(&dst_ip_entry_ptr->src_ips_circle_array, src_ip_ptr);
   }
}

void sip_ip_entry_update_diff_names(sip_ip_entry_t* src_ip_entry_ptr, sip_ip_entry_t* dst_ip_entry_ptr, ur_template_t* tmplt, const void* data) {
   char* from_ptr = ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALLING_PARTY);
   uint16_t from_len = (uint16_t) ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALLING_PARTY);
   char* to_ptr = ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALLED_PARTY);
   uint16_t to_len = (uint16_t) ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALLED_PARTY);
   
   if (src_ip_entry_ptr != NULL) {
      sip_circle_array_names_update(&src_ip_entry_ptr->as_src_from_names_circle_array, from_ptr, from_len);
      sip_circle_array_names_update(&src_ip_entry_ptr->as_src_to_names_circle_array, to_ptr, to_len);
   }
   if (dst_ip_entry_ptr != NULL) {
      sip_circle_array_names_update(&dst_ip_entry_ptr->as_dst_from_names_circle_array, from_ptr, from_len);
      sip_circle_array_names_update(&dst_ip_entry_ptr->as_dst_to_names_circle_array, to_ptr, to_len);
   }
}

void sip_ip_entry_update_calls(sip_ip_entry_t* src_ip_entry_ptr, sip_ip_entry_t* dst_ip_entry_ptr, ur_template_t* tmplt, const void* data) {
   uint8_t voip_packet_type = (uint8_t)ur_get(tmplt, data, UR_INVEA_VOIP_PACKET_TYPE);
   uint64_t invite_time = voip_packet_type == CALL_SIP_REQUEST ? (uint64_t)ur_get(tmplt, data, UR_INVEA_SIP_INVITE_RINGING_TIME) : 0;
   uint64_t ring_time = voip_packet_type == CALL_SIP_RESPONSE ? (uint64_t)ur_get(tmplt, data, UR_INVEA_SIP_INVITE_RINGING_TIME) : 0;
   uint64_t ok_time = voip_packet_type == CALL_SIP_RESPONSE ? (uint64_t)ur_get(tmplt, data, UR_INVEA_SIP_OK_TIME) : 0;
   uint64_t bye_time = voip_packet_type == CALL_SIP_REQUEST ? (uint64_t)ur_get(tmplt, data, UR_INVEA_SIP_BYE_TIME) : 0;
   
   if (src_ip_entry_ptr != NULL) {
      sip_circle_array_calls_update(&src_ip_entry_ptr->out_calls_circle_array, ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALL_ID), ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALL_ID), invite_time, ring_time, ok_time, bye_time);
   }
   if (dst_ip_entry_ptr != NULL) {
      sip_circle_array_calls_update(&dst_ip_entry_ptr->in_calls_circle_array, ur_get_dyn(tmplt, data, UR_INVEA_SIP_CALL_ID), ur_get_dyn_size(tmplt, data, UR_INVEA_SIP_CALL_ID), invite_time, ring_time, ok_time, bye_time);
   }
}

void sip_ip_entry_print_header(FILE* file) {
   fprintf(file, "ip");
   for (int i = 1; i < SIP_MAX_DIFF_IPS; i++) {
      fprintf(file, ",diff_src_%d_ips_min_time", i + 1);
   }
   for (int i = 1; i < SIP_MAX_DIFF_IPS; i++) {
      fprintf(file, ",diff_dst_%d_ips_min_time", i + 1);
   }
   for (int i = 1; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",diff_as_src_from_%d_names_min_time", i + 1);
   }
   for (int i = 1; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",diff_as_src_to_%d_names_min_time", i + 1);
   }
   for (int i = 1; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",diff_as_dst_from_%d_names_min_time", i + 1);
   }
   for (int i = 1; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",diff_as_dst_to_%d_names_min_time", i + 1);
   }
   fprintf(file,
      ",max_in_sim_calls"
      ",max_out_sim_calls"
      ",in_ring_count"
      ",in_ring_len_avg"
      ",in_ring_len_var"
      ",out_ring_count"
      ",out_ring_len_avg"
      ",out_ring_len_var"
      ",in_talk_count"
      ",in_talk_len_avg"
      ",in_talk_len_var"
      ",out_talk_count"
      ",out_talk_len_avg"
      ",out_talk_len_var"
      ",as_ep_from"
      ",as_ep_to"
      ",as_proxy\n"
   );
   if (ferror(file)) {
      fprintf(stderr, "ERROR: Cannot write to file.\n");
   }
}

void sip_ip_entry_print(FILE* file, sip_ip_entry_t* ip_entry_ptr) {
   char ip_str[SIP_IP_STR_MAX_LEN];
   ip_to_str(&ip_entry_ptr->ip, ip_str);
   fprintf(file, "%s", ip_str);
   int i;
   /* Diff src ips */
   for (i = 1; i < ip_entry_ptr->src_ips_circle_array.count; i++) {
      fprintf(file, ",%0.lf", ip_entry_ptr->src_ips_circle_array.time_windows[i]);
   }
   for (; i < SIP_MAX_DIFF_IPS; i++) {
      fprintf(file, ",");
   }
   /* Diff dst ips */
   for (i = 1; i < ip_entry_ptr->dst_ips_circle_array.count; i++) {
      fprintf(file, ",%0.lf", ip_entry_ptr->dst_ips_circle_array.time_windows[i]);
   }
   for (; i < SIP_MAX_DIFF_IPS; i++) {
      fprintf(file, ",");
   }
   /* Diff as_src from names */
   for (i = 1; i < ip_entry_ptr->as_src_from_names_circle_array.count; i++) {
      fprintf(file, ",%0.lf", ip_entry_ptr->as_src_from_names_circle_array.time_windows[i]);
   }
   for (; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",");
   }
   /* Diff as_src to names */
   for (i = 1; i < ip_entry_ptr->as_src_to_names_circle_array.count; i++) {
      fprintf(file, ",%0.lf", ip_entry_ptr->as_src_to_names_circle_array.time_windows[i]);
   }
   for (; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",");
   }
   /* Diff as_dst from names */
   for (i = 1; i < ip_entry_ptr->as_dst_from_names_circle_array.count; i++) {
      fprintf(file, ",%0.lf", ip_entry_ptr->as_dst_from_names_circle_array.time_windows[i]);
   }
   for (; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",");
   }
   /* Diff as_dst to names */
   for (i = 1; i < ip_entry_ptr->as_dst_to_names_circle_array.count; i++) {
      fprintf(file, ",%0.lf", ip_entry_ptr->as_dst_to_names_circle_array.time_windows[i]);
   }
   for (; i < SIP_MAX_DIFF_NAMES; i++) {
      fprintf(file, ",");
   }
   /* Max sim calls */
   fprintf(file, ",%d,%d",
      ip_entry_ptr->in_calls_circle_array.max_sim_calls,
      ip_entry_ptr->out_calls_circle_array.max_sim_calls
   );
   /* Calls statistics */
   int count;

   count = ip_entry_ptr->in_calls_circle_array.ring_count;
   if (count > 0) {
      fprintf(file, ",%d,%0.lf",
         count,
         ip_entry_ptr->in_calls_circle_array.ring_len_avg
      );
      if (count > 1) {
         fprintf(file, ",%0.lf", ip_entry_ptr->in_calls_circle_array.ring_len_var);
      } else {
         fprintf(file, ",");
      }
   } else {
      fprintf(file, ",,,");
   }

   count = ip_entry_ptr->out_calls_circle_array.ring_count;
   if (count > 0) {
      fprintf(file, ",%d,%0.lf",
         count,
         ip_entry_ptr->out_calls_circle_array.ring_len_avg
      );
      if (count > 1) {
         fprintf(file, ",%0.lf", ip_entry_ptr->out_calls_circle_array.ring_len_var);
      } else {
         fprintf(file, ",");
      }
   } else {
      fprintf(file, ",,,");
   }

   count = ip_entry_ptr->in_calls_circle_array.talk_count;
   if (count > 0) {
      fprintf(file, ",%d,%0.lf",
         count,
         ip_entry_ptr->in_calls_circle_array.talk_len_avg
      );
      if (count > 1) {
         fprintf(file, ",%0.lf", ip_entry_ptr->in_calls_circle_array.talk_len_var);
      } else {
         fprintf(file, ",");
      }
   } else {
      fprintf(file, ",,,");
   }

   count = ip_entry_ptr->out_calls_circle_array.talk_count;
   if (count > 0) {
      fprintf(file, ",%d,%0.lf",
         count,
         ip_entry_ptr->out_calls_circle_array.talk_len_avg
      );
      if (count > 1) {
         fprintf(file, ",%0.lf", ip_entry_ptr->out_calls_circle_array.talk_len_var);
      } else {
         fprintf(file, ",");
      }
   } else {
      fprintf(file, ",,,");
   }
   fprintf(file,
      ",%u,%u,%u"
      "\n",
      ip_entry_ptr->as_ep_from,
      ip_entry_ptr->as_ep_to,
      ip_entry_ptr->as_proxy
   );
   if (ferror(file)) {
      fprintf(stderr, "ERROR: Cannot write to file.\n");
   }
}
