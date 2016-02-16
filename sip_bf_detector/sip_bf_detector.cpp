/**
 * \file sip_bf_detector.cpp
 * \brief Module for detecting brute-force attacks on Session Initiation Protocol.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#include "sip_bf_detector.h"
#include "fields.h"

UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   time TIME_FIRST,
   uint16 SIP_MSG_TYPE,
   uint16 SIP_STATUS_CODE,
   string SIP_CSEQ,
   string SIP_CALLING_PARTY
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("SIP Brute-Force Detector","Module for detecting brute-force attacks on Session Initiation Protocol.",1,1)

#define MODULE_PARAMS(PARAM)

static int stop = 0;
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

void print_statistics(void *tree)
{
   int is_there_next;
   b_plus_tree_item *b_item;

   b_item = b_plus_tree_create_list_item(tree);
   is_there_next = b_plus_tree_get_list(tree, b_item);
   while (is_there_next == 1) {
      AttackedServer *server = (AttackedServer*)(b_item->value);
      printf("IP: %s, count: %"PRIu32"\n", server->m_ip_addr, server->m_count);
      is_there_next = b_plus_tree_get_next_item_from_list(tree, b_item);
   }

   b_plus_tree_destroy_list_item(b_item);
}

int insert_attack_attempt(void *tree, ip_addr_t *ip_src, ip_addr_t *ip_dst, char *user, size_t user_length, uint16_t status_code)
{
   uint32_t src_ip = ip_get_v4_as_int(ip_src);
   int key_exists = b_plus_tree_is_item_in_tree(tree, &src_ip);
   AttackedServer *server = (AttackedServer*)b_plus_tree_insert_or_find_item(tree, &src_ip);
   if (!server)
      return -1;

   if (!key_exists)
      server->initialize(ip_src);

   server->m_count++;
   return 0;
}
// Cut first 4 chars ("sip:") or 5 chars ("sips:") from input string and ignore ';' or '?' + string after it

int cut_sip_identifier(char ** output_str, char * input_str, int * str_len)
{
   if ((*str_len >= 4) && (strncmp(input_str, "sip:", 4) == 0)) {

      // input string beginning with "sip:"

      *output_str = input_str + 4 * sizeof (char);
      *str_len -= 4;

   } else {
      if ((*str_len >= 5) && (strncmp(input_str, "sips:", 5) == 0)) {

         // input string beginning with "sips:"

         *output_str = input_str + 5 * sizeof (char);
         *str_len -= 5;

      } else {
         return -1;
      }
   }

   // ignore ';' or '?' + string after it
   int i = 0;
   while (i < *str_len) {
      if (((*output_str)[i] == ';') || ((*output_str)[i] == '?')) {
         *str_len = i;
         break;
      }
      i++;
   }

   // set terminating null character
   (*output_str)[*str_len] = '\0';

   return 0;
}

int compare_ipv4(void *a, void *b)
{
   uint32_t *h1, *h2;
   h1 = (uint32_t*)a;
   h2 = (uint32_t*)b;

   if (*h1 == *h2) {
      return EQUAL;
   }
   else if (*h1 < *h2) {
      return LESS;
   }
   return MORE;
}

int compare_ipv6(void * a, void * b)
{
   int ret;
   ret = memcmp(a, b, IP_VERSION_6_BYTES * 2);
   if (ret == 0) {
      return EQUAL;
   } else if (ret < 0) {
      return LESS;
   }
   return MORE;
}

void get_string_from_unirec(char *string_output, int *string_len, int unirec_field_id, int max_length, const void *in_rec, ur_template_t *in_tmplt)
{
   *string_len = ur_get_var_len(in_tmplt, in_rec, unirec_field_id);
   if (*string_len > max_length) 
      *string_len = max_length;

   memcpy(string_output, ur_get_ptr_by_id(in_tmplt, in_rec, unirec_field_id), *string_len);
   string_output[*string_len] = '\0';
}

int main(int argc, char **argv)
{
   int ret;
   uint16_t msg_type, status_code;
   ip_addr_t *ip_src, *ip_dst;
   char sip_from_orig[MAX_LENGTH_SIP_FROM + 1], sip_cseq[MAX_LENGTH_CSEQ + 1];
   char *sip_from;
   int sip_from_len, sip_cseq_len;
   void *tree_ipv4, *tree_ipv6;

   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   ur_template_t *in_tmplt = ur_create_input_template(0, UNIREC_INPUT_TEMPLATE, NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }
   ur_template_t *out_tmplt = ur_create_output_template(0, UNIREC_OUTPUT_TEMPLATE, NULL);
   if (out_tmplt == NULL){
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      return -1;
   }

   void *out_rec = ur_create_record(out_tmplt, 0);
   if (out_rec == NULL){
      ur_free_template(in_tmplt);
      ur_free_template(out_tmplt);
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      return -1;
   }

   tree_ipv4 = b_plus_tree_initialize(5, &compare_ipv4, sizeof(AttackedServer), 4);
   tree_ipv6 = b_plus_tree_initialize(5, &compare_ipv6, sizeof(AttackedServer), 64);

   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; 
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      get_string_from_unirec(sip_cseq, &sip_cseq_len, F_SIP_CSEQ, MAX_LENGTH_CSEQ, in_rec, in_tmplt);
      if (!(sip_cseq_len > 2 && strncmp(sip_cseq, CSEQ_EXPECTED, 3) == 0))
         continue;

      msg_type = ur_get(in_tmplt, in_rec, F_SIP_MSG_TYPE);
      status_code = ur_get(in_tmplt, in_rec, F_SIP_STATUS_CODE);
      if (!(msg_type == SIP_MSG_TYPE_STATUS && (status_code == SIP_STATUS_FORBIDDEN || status_code == SIP_STATUS_OK)))
         continue;

      get_string_from_unirec(sip_from_orig, &sip_from_len, F_SIP_CALLING_PARTY, MAX_LENGTH_SIP_FROM, in_rec, in_tmplt);
      int invalid_sipfrom = cut_sip_identifier(&sip_from, sip_from_orig, &sip_from_len);
      if (invalid_sipfrom)
         continue;

      ip_src = &ur_get(in_tmplt, in_rec, F_SRC_IP);
      ip_dst = &ur_get(in_tmplt, in_rec, F_DST_IP);
      if (ip_is_null(ip_src) || ip_is_null(ip_dst))
         continue;

      void *tree = ip_is4(ip_src) ? tree_ipv4 : tree_ipv6;
      int retval = insert_attack_attempt(tree, ip_src, ip_dst, sip_from, sip_from_len, status_code);
      if (retval != 0)
         continue;

      ur_copy_fields(out_tmplt, out_rec, in_tmplt, in_rec);
      ur_set(out_tmplt, out_rec, F_SIP_MSG_TYPE, msg_type);

      ret = trap_send(0, out_rec, ur_rec_fixlen_size(out_tmplt));
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
   }
   
   print_statistics(tree_ipv4);

   b_plus_tree_destroy(tree_ipv4);
   b_plus_tree_destroy(tree_ipv6);
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_finalize();

   return 0;
}

