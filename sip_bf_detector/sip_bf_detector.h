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
#define MAX_LENGTH_USER_NAME     50
#define MAX_LENGTH_CSEQ          50
#define IP_VERSION_4_BYTES       4
#define IP_VERSION_6_BYTES       32
#define DEFAULT_SCAN_LIMIT       25
#define DEFAULT_DBF_LIMIT        3
#define DEFAULT_SCAN_START_SIZE  5
#define DEFAULT_DBF_START_SIZE   1

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

/** \brief UniRec input template definition. */
#define UNIREC_ALERT_TEMPLATE "SBFD_TARGET,SBFD_SOURCE,SBFD_LINK_BIT_FIELD,SBFD_PROTOCOL,SBFD_EVENT_TIME,SBFD_CEASE_TIME,SBFD_BREACH_TIME,SBFD_EVENT_TYPE,SBFD_EVENT_ID,SBFD_ATTEMPTS,SBFD_AVG_ATTEMPTS,SBFD_USER"

#define VERBOSE(...) if (verbose >= 0) { \
   printf(__VA_ARGS__); \
}

class Client;
class User;
class Server;

enum event_type_t {
   BF,
   DBF,
   SCAN
};

struct stats_t {
   ur_time_t m_time_first;
   uint8_t m_protocol;
   uint8_t m_link_bit_field;
   uint32_t m_avg_count;
   uint32_t m_total_count;
   Client *m_clt;
};

struct data_t {
   bool ipv4;                             ///< flag signalizing whether used protocol is IPv4 or IPv6
   char *user;                            ///< pointer to user name
   char *name_suffix;
   uint16_t status_code;                  ///< sip status code
   uint8_t link_bit_field;                ///< indicator of particular monitoring probe
   uint8_t protocol;                      ///< sip protocol used for data transfer
   ur_time_t time_stamp;                  ///< time when the message was received
   ip_addr_t *ip_src;                     ///< IP address of the server
   ip_addr_t *ip_dst;                     ///< IP address of the attacker
};

struct scan_t {
   scan_t(const data_t *flow);
   uint32_t m_other_attempts;
   ur_time_t m_time_last;
   bool m_destroy;
};

struct dbf_t {
   dbf_t(const data_t *flow);
   ~dbf_t();
   bool addBreacher(const ip_addr_t *breacher);
   ip_addr_t *m_breacher;
   ur_time_t m_time_breach;
   ur_time_t m_time_last;
   uint32_t m_other_attempts;
};

struct bf_t {
   bf_t(const data_t *flow, Client *clt);
   bool isReportable() const;
   Client *m_source;
   uint32_t m_attempts;
   ur_time_t m_time_first;
   ur_time_t m_time_last;
   ur_time_t m_time_breach;
   uint8_t m_protocol;
   uint8_t m_link_bit_field;
};

class User {
public:
   void destroy(Server *srv);
   bool init(char *name);
   int addSource(const data_t *flow, Client *clt, bf_t *bf);
   dbf_t* getDBF() const;
   bf_t* findClient(const Client *clt) const;
   void removeBF(bf_t *bf);
   void getDBFStats(stats_t *stats) const;
   int evaluateFlows(ur_time_t current_time, Server *srv);

   char *m_name;
private:
   bool extendSources();
   dbf_t *m_dbf;
   int m_index;
   int m_size;
   bf_t **m_sources;
};

class Client {
public:
   void destroy();
   bool init(ip_addr_t *ip);
   bool addTarget(const data_t *flow, User *usr);
   User* findUser(User *usr) const;
   scan_t* getScan() const;
   void removeUser(User *usr);
   void getScanStats(stats_t *stats) const;
   int getSize() const;

   ip_addr_t *m_ip;
private:
   bool extendUsers();
   int m_index;
   int m_size;
   User **m_names;
   scan_t *m_scan;
};

class Server {
public:
   void destroy();
   void cleanStructures();
   bool init(const data_t *flow);
   bool insertFlow(const data_t *flow);
   bool isEmpty() const;
   bool evaluateFlows(const ur_time_t current_time);
   void reportAlert(bf_t *bf, User *usr, Client *clt, event_type_t event);

   ip_addr_t *m_ip;
private:
   Client* createClientNode(void *tree_key, ip_addr_t *ip);
   User* createUserNode(char *name);
   bool insertSourceAndTarget(const data_t *flow, User *user, Client *clt);
   void updateScan(const data_t *flow, Client *clt, User *usr);
   void updateDBF(const data_t *flow, Client *clt, User *usr);
   uint64_t createId(ur_time_t time_first);
   bool m_ipv4;
   char *m_name_suffix;
   bpt_t *m_users;
   bpt_t *m_clients;
};

class Detector {
public:
   void destroy();
   bool init();
   bool insertFlow(const data_t *flow);
   bool evaluateFlows(const ur_time_t current_time);
private:
   bpt_t *m_ipv4tree;
   bpt_t *m_ipv6tree;
};
