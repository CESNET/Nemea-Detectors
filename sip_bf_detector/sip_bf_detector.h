/**
 * \file sip_bf_detector.h
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
extern "C" {
#include <b_plus_tree.h>
}

#define SIP_MSG_TYPE_STATUS      99
#define SIP_STATUS_FORBIDDEN     403
#define SIP_STATUS_OK            200
#define MAX_LENGTH_SIP_FROM      100
#define MAX_LENGTH_CSEQ          100
#define IP_VERSION_4_BYTES       4
#define IP_VERSION_6_BYTES       32
#define DEFAULT_ALERT_THRESHOLD  20
#define CHECK_MEMORY_INTERVAL    120
#define FREE_MEMORY_INTERVAL     2400

/** \brief UniRec input template definition. */
#define UNIREC_INPUT_TEMPLATE "DST_IP,SRC_IP,LINK_BIT_FIELD,PROTOCOL,TIME_FIRST,SIP_MSG_TYPE,SIP_STATUS_CODE,SIP_CSEQ,SIP_CALLING_PARTY"

struct attacked_server_t;

struct sip_dataholder_t{
   bool ipv4;
   int sip_from_len;
   int tree_key_length;
   int (*comp_func)(void *, void *);
   char *sip_from;
   void *tree;
   uint16_t msg_type;
   uint16_t status_code;
   ur_time_t time_stamp;
   ip_addr_t *ip_src;
   ip_addr_t *ip_dst;
};

struct attacker_t{
   void initialize(ip_addr_t *ip_addr, ur_time_t start_time);
   void destroy();

   char *m_ip_addr;
   uint64_t m_count;
   ur_time_t m_start;
};

struct attacked_user_t{
   void initialize(const sip_dataholder_t *sip_data);
   int addAttack(const sip_dataholder_t *sip_data, attacked_server_t *server);
   void destroy();

   char *m_user_name;
   void *m_attackers_tree;
   char *m_breacher;
   bool m_breached;
   bool m_reported;
   bool m_ipv4;
   ur_time_t m_first_action;
   ur_time_t m_breach_time;
   ur_time_t m_last_action;
   uint64_t m_attack_total_count;
};

struct attacked_server_t{
   void initialize(ip_addr_t *ip_addr);
   void freeUnusedUsers(time_t time_actual);
   void destroy();

   void *m_user_tree;
   char *m_ip_addr;
};

struct items_to_remove{
   void init(int count, int item_length);
   void addItem(const void *item);
   void destroy();
   void **items_arr;
   int size;
   int items_len;
};

