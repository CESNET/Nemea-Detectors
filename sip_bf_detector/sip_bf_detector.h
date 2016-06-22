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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <sstream>
#include <string>
extern "C" {
#include <b_plus_tree.h>
}

using namespace std;

#define SIP_MSG_TYPE_STATUS      99
#define SIP_STATUS_UNAUTHORIZED  401
#define SIP_STATUS_OK            200
#define MAX_LENGTH_SIP_FROM      100
#define MAX_LENGTH_CSEQ          100
#define IP_VERSION_4_BYTES       4
#define IP_VERSION_6_BYTES       32

#define PROTOCOL_TCP   0x6
#define PROTOCOL_UDP   0x11

/** \brief Default value of unsuccessful authentication attempts to consider this behaviour as an attack. */
#define DEFAULT_ALERT_THRESHOLD  20

/** \brief Default time in seconds between checks for ceased attacks. */
#define CHECK_MEMORY_INTERVAL    300

/** \brief Default number of seconds since last action to consider an attack as ceased. */
#define FREE_MEMORY_INTERVAL     1800

/** \brief UniRec input template definition. */
#define UNIREC_INPUT_TEMPLATE "DST_IP,SRC_IP,LINK_BIT_FIELD,PROTOCOL,TIME_FIRST,SIP_MSG_TYPE,SIP_STATUS_CODE,SIP_CSEQ,SIP_CALLING_PARTY"

#define VERBOSE(...) if (verbose >= 0) { \
   printf(__VA_ARGS__); \
}

struct AttackedServer;

/**
 * Structure designed to hold all important information
 * about currently processed message.
 */
struct SipDataholder {
   bool ipv4;                             ///< flag signalizing whether used protocol is IPv4 or IPv6
   int sip_from_len;                      ///< length of user name
   int tree_key_length;                   ///< length of key used in b+ trees (depends on IP version)
   int (*comp_func)(void *, void *);      ///< pointer to comparing function used in b+ trees (depends on IP version)
   char *sip_from;                        ///< pointer to user name
   bpt_t *tree;                            ///< pointer to b+ tree of servers (depends on IP version)
   uint16_t msg_type;                     ///< sip message type
   uint16_t status_code;                  ///< sip status code
   uint8_t link_bit_field;                ///< indicator of particular monitoring probe
   uint8_t protocol;                      ///< sip protocol used for data transfer
   ur_time_t time_stamp;                  ///< time when the message was received
   ip_addr_t *ip_src;                     ///< IP address of the server
   ip_addr_t *ip_dst;                     ///< IP address of the attacker
};

/**
 * Structure representing an attacker trying to
 * brute-force password of a certain user.
 */
struct Attacker {
   /**
    * Initialize data in the structure to default values.
    *
    * \param[in] ip_addr IP address of the attacker
    * \param[in] start_time time of first attack message sent by the attacker
    * \return true - initialization was successful, false - error occurred
    */
   bool initialize(const ip_addr_t *ip_addr, ur_time_t start_time);

   /**
    * Free allocated memory.
    */
   void destroy(void);

   char *m_ip_addr;        ///< IP address of the attacker in human readable format
   uint64_t m_count;       ///< count of attack messages generated by the attacker
   ur_time_t m_start;      ///< time of first attack message
};

/**
 * Structure representing a user that is under
 * ongoing brute-force attack.
 */
struct AttackedUser {
   /**
    * Initialize data in the structure to default values.
    *
    * \param[in] sip_data pointer to SipDataholder structure 
                          with information about currently processed message
    * \return true - initialization was successful, false - error occurred
    */
   bool initialize(const SipDataholder *sip_data);

   /**
    * Insert attack attempt to the b+ tree of attackers.
    * Generate alert if security was breached or the count of attack messages
    * exceeded the threshold.
    *
    * \param[in] sip_data pointer to SipDataholder structure
                          with information about currently processed message
    * \param[in] server pointer to a server on which current user can be found
    * \return 0 - attack was added successfully, 1 - error occurred
    */
   int add_attack(const SipDataholder *sip_data, const AttackedServer *server);

   /**
    * \brief Generate alert string in JSON format and send it to the output interface.
    *
    * \param[in] server pointer to the server structure where the user exists
    * \return true - alert generated successfully, false - error occurred
    */
   bool generate_alert(const AttackedServer *server);
   /**
    * Free allocated memory.
    *
    * \return true - deallocation ended successfully, false - error occurred
    */
   bool destroy(void);
   /**
    * Generate event ID from timestamp of first action. Also set obsolete ID.
    *
    * \return true - deallocation ended successfully, false - error occurred
    */
   void create_event_id();

   char *m_user_name;               ///< user name
   bpt_t *m_attackers_tree;          ///< pointer to a b+ tree containing Attacker structures
   char *m_breacher;                ///< IP address of breacher
   bool m_breached;                 ///< flag signalizing whether password is breached
   bool m_reported;                 ///< flag signalizing whether this attack has already been reported
   bool m_ipv4;                     ///< flag signalizing whether used protocol is IPv4 or IPv6
   ur_time_t m_first_action;        ///< time of first attack message
   ur_time_t m_breach_time;         ///< time of attack message that breached user's password
   ur_time_t m_last_action;         ///< time of last attack message
   uint64_t m_attack_total_count;   ///< total count of attack messages across all attackers
   uint64_t m_event_id;             ///< ID of current event in case of generating report
   uint64_t m_obsolete_id;          ///< event ID in last generated report of this attack
};

/**
 * Structure representing a server with users which are under
 * ongoing brute-force attack.
 */
struct AttackedServer {
   /**
    * Initialize data in the structure to default values.
    *
    * \param[in] ip_addr IP address of the server
    * \return true - initialization was successful, false - error occurred
    */
   bool initialize(const ip_addr_t *ip_addr, uint8_t link_bit_field, uint8_t protocol);

   /**
    * Remove all users from b+ tree of users who are no longer under attack.
    * Generate alerts for users with count of attack messages above the threshold.
    *
    * \param[in] time_actual time-stamp of currently processed message
    * \return true - removal was successful, false - error occurred
    */
   bool free_unused_users(time_t time_actual);

   /**
    * Free allocated memory.
    * Generate alerts for users with count of attack messages above the threshold.
    *
    * \return true - deallocation ended successfully, false - error occurred
    */
   bool destroy(void);

   bpt_t *m_user_tree;        ///< pointer to a b+ tree containing AttackedUser structures
   char *m_ip_addr;          ///< IP address of the server in human readable format
   uint8_t m_link_bit_field; ///< indicator of particular monitoring probe
   uint8_t m_protocol;       ///< sip protocol used for data transfer
};

