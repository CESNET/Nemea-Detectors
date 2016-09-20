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
   ipaddr DST_IP,                // IP address of attack source
   ipaddr SRC_IP,                // IP address of attack target
   uint64 LINK_BIT_FIELD,        // number of link
   uint8 PROTOCOL,               // TCP or UDP protocol
   time TIME_FIRST,              // time of the message
   uint16 SIP_MSG_TYPE,          // type of SIP message
   uint16 SIP_STATUS_CODE,       // status code of SIP response
   string SIP_CSEQ,              // CSEQ field in SIP message
   string SIP_CALLING_PARTY,     // targeted user name
   ipaddr SBFD_TARGET,
   ipaddr SBFD_SOURCE,
   uint64 SBFD_LINK_BIT_FIELD,
   uint8 SBFD_PROTOCOL,
   time SBFD_EVENT_TIME,
   time SBFD_CEASE_TIME,
   time SBFD_BREACH_TIME,,
   uint8 SBFD_EVENT_TYPE,
   uint64 SBFD_EVENT_ID,
   uint32 SBFD_ATTEMPTS,
   uint32 SBFD_AVG_ATTEMPTS,
   string SBFD_USER
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("SIP Brute-Force Detector","Module for detecting brute-force attacks on Session Initiation Protocol.",1,1)

#define MODULE_PARAMS(PARAM) \
   PARAM('a', "alert_threshold", "Number of unsuccessful authentication attempts for considering this behaviour as an attack (20 by default).", required_argument, "uint64") \
   PARAM('c', "check_mem_int", "Number of seconds between the checks on ceased attacks (300 by default).", required_argument, "uint64") \
   PARAM('f', "free_mem_delay", "Number of seconds after the last action to consider attack as ceased (1800 by default).", required_argument, "uint64")

static int stop = 0;
int verbose;
uint64_t g_alert_threshold = DEFAULT_ALERT_THRESHOLD;
uint64_t g_check_mem_interval = CHECK_MEMORY_INTERVAL;
uint64_t g_free_mem_interval = FREE_MEMORY_INTERVAL;
uint16_t g_min_sec = 0;
uint16_t g_event_row = 0;
ur_template_t *alert_tmplt;
void *alert_rec;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

/* *********************** */

/**
 * Comparing function used in b+ tree of users. 
 * Compares two strings representing keys in b+ tree.
 *
 * \param[in] a pointer to the first key
 * \param[in] b pointer to the second key
 * \return <0 (a < b), 0 (a == b), >0 (a > b)
 */
int compare_user_name(void *a, void *b)
{
   return strncmp((const char *) a, (const char *) b, MAX_LENGTH_USER_NAME);
}

/**
 * Comparing function used in b+ tree of servers and attackers. 
 * Compares two integer representations of IPv4 keys.
 *
 * \param[in] a pointer to the first key
 * \param[in] b pointer to the second key
 * \return <0 (a < b), 0 (a == b), >0 (a > b)
 */
int compare_ipv4(void *a, void *b)
{
   uint32_t *h1, *h2;
   h1 = (uint32_t *) a;
   h2 = (uint32_t *) b;
   if (*h1 == *h2) {
      return EQUAL;
   }
   else if (*h1 < *h2) {
      return LESS;
   }

   return MORE;
}

/**
 * Comparing function used in b+ tree of servers and attackers. 
 * Compares two IPv6 keys.
 *
 * \param[in] a pointer to the first key
 * \param[in] b pointer to the second key
 * \return <0 (a < b), 0 (a == b), >0 (a > b)
 */
int compare_ipv6(void *a, void *b)
{
   int ret;
   ret = memcmp(a, b, IP_VERSION_6_BYTES);
   if (ret == 0) {
      return EQUAL;
   } else if (ret < 0) {
      return LESS;
   }

   return MORE;
}

dbf_t::dbf_t(const data_t *flow)
{
   m_breacher = NULL;
   m_time_breach = 0;
   m_time_last = flow->time_stamp;
   m_other_attempts = 0;
}

dbf_t::~dbf_t()
{
   free(m_breacher);
}

bool dbf_t::addBreacher(const ip_addr_t *breacher)
{
   m_breacher = (ip_addr_t *) malloc(sizeof(ip_addr_t));
   if (!m_breacher) {
      fprintf(stderr, "ERROR: dbf_t::addBreach - malloc failed.\n");
      return false;
   }

   memcpy(m_breacher, breacher, sizeof(ip_addr_t));
   return true;
}

bf_t::bf_t(const data_t *flow, Client *clt)
{
   m_source = clt;
   m_attempts = 1;
   m_time_first = flow->time_stamp;
   m_time_last = flow->time_stamp;
   m_time_breach = 0;
   m_protocol = flow->protocol;
   m_link_bit_field = flow->link_bit_field;
}

bool bf_t::isReportable() const
{
   if (m_attempts >= g_alert_threshold && m_source->getScan() == NULL) {
      return true;
   }

   return false;
}

scan_t::scan_t(const data_t *flow)
{
   m_other_attempts = 0;
   m_time_last = flow->time_stamp;
   m_destroy = false;
}

bool User::init(char *name) 
{
   size_t length = strlen(name);
   m_name = NULL;
   m_sources = NULL;
   m_dbf = NULL;
   m_index = 0;
   m_size = DEFAULT_DBF_START_SIZE;
   m_name = (char *) malloc((length + 1) * sizeof(char));
   m_sources = (bf_t **) malloc(m_size * sizeof(bf_t *));
   if (!m_name || !m_sources) {
      fprintf(stderr, "ERROR: User::init - malloc failed.\n");
      if (m_name) {
         free(m_name);
      }

      if (m_sources) {
         free(m_sources);
      }

      return false;
   }

   strncpy(m_name, name, length);
   m_name[length] = '\0';   

   return true;
}

int User::addSource(const data_t *flow, Client *clt, bf_t *bf)
{
   if (bf) {
      bf->m_time_last = flow->time_stamp;
      bf->m_attempts++;
      if (bf->m_attempts == g_alert_threshold) {
         return 1;
      }

      return 0;
   }

   if (m_index + 1 == DEFAULT_DBF_LIMIT) {
      m_dbf = new dbf_t(flow);
      if (!m_dbf) {
         fprintf(stderr, "ERROR: User::addSource - new failed when creating DBF structure.\n");
         return -1;
      }

      return 0;
   }

   if (m_index + 1 == m_size) {
      if (!extendSources()) {
         return -1;
      }
   }

   m_sources[m_index] = new bf_t(flow, clt);
   if (!m_sources[m_index]) {
      fprintf(stderr, "ERROR: User::addSource - new failed when creating BF structure.\n");
      return -1;
   }

   clt->addTarget(flow, this);
   m_index++;
   return 0;
}

bf_t* User::findClient(const Client* clt) const
{
   for (int i = 0; i < m_index; i++) {
      if (clt == m_sources[i]->m_source) {
         return m_sources[i];
      }
   }

   return NULL;
}

dbf_t* User::getDBF() const
{
   return m_dbf;
}

int User::evaluateFlows(ur_time_t current_time, Server *srv)
{
   if (m_dbf && (current_time > m_dbf->m_time_last) && ((current_time - m_dbf->m_time_last) > g_free_mem_interval)) {
      srv->reportAlert(NULL, this, NULL, DBF);
      for (int i = 0; i < m_index; i++) {
         m_sources[i]->m_source->removeUser(this);
         delete m_sources[i];
      }

      delete m_dbf;
      free(m_sources);
      free(m_name);
      return 1;
   }

   for (int i = 0; i < m_index; i++) {
      bf_t *bf = m_sources[i];
      scan_t *scan = bf->m_source->getScan();
      if (scan && scan->m_destroy) {
         removeBF(bf);
      } else if ((current_time > bf->m_time_last) && ((current_time - bf->m_time_last) > g_free_mem_interval)) {
         if (bf->m_attempts >= g_alert_threshold) {
            srv->reportAlert(bf, this, NULL, BF);   
         }
         
         bf->m_source->removeUser(this);
         removeBF(bf);
      }
   }

   if (m_index == 0) {
      delete m_dbf;
      free(m_sources);
      free(m_name);
      return 1;      
   }

   return 0;
}

bool User::extendSources()
{
   bf_t **tmp = NULL;
   m_size *= 2;
   if (m_size > DEFAULT_DBF_LIMIT) {
      m_size = DEFAULT_DBF_LIMIT;
   }

   tmp = (bf_t **) realloc(m_sources, m_size * sizeof(bf_t *));
   if (!tmp) {
      fprintf(stderr, "ERROR: User::extendSources - realloc failed.\n");
      return false;
   }

   m_sources = tmp;
   return true;
}

void User::destroy(Server *srv)
{
   if (m_dbf) {
      srv->reportAlert(NULL, this, NULL, DBF);
      for (int i = 0; i < m_index; i++) {
         delete m_sources[i];
      }

   } else {
      for (int i = 0; i < m_index; i++) {
         bf_t *bf = m_sources[i];
         if (bf->isReportable()) {
            srv->reportAlert(bf, this, NULL, BF);
         }

         delete bf;
      }
   }

   delete m_dbf;
   free(m_sources);
   free(m_name);
}

void User::removeBF(bf_t *bf) {
   for (int i = 0; i < m_index; i++) {
      if (m_sources[i] == bf) {
         delete m_sources[i];
         if (i + 1 == m_index) {
            m_sources[i] = NULL;
         } else {
            m_sources[i] = m_sources[m_index - 1];
            m_sources[m_index - 1] = NULL;
         }

         m_index--;
         return;
      }
   }
}

void User::getDBFStats(stats_t *stats) const
{
   bf_t *bf = NULL;
   for (int i = 0; i < m_index; i++) {
      bf = m_sources[i];
      if (i == 0) {
         stats->m_protocol = bf->m_protocol;
         stats->m_link_bit_field = bf->m_link_bit_field;
         stats->m_time_first = bf->m_time_first;
         stats->m_total_count = bf->m_attempts;
         stats->m_clt = bf->m_source;
      } else {
         if (stats->m_time_first > bf->m_time_first) {
            stats->m_time_first = bf->m_time_first;
         }

         stats->m_total_count += bf->m_attempts;
      }
   }

   stats->m_avg_count = stats->m_total_count / m_index;
   stats->m_total_count += m_dbf->m_other_attempts;   
}

bool Client::init(ip_addr_t *ip)
{
   m_names = NULL;
   m_ip = NULL;
   m_scan = NULL;
   m_index = 0;
   m_size = DEFAULT_SCAN_START_SIZE;
   m_names = (User **) malloc(m_size * sizeof(User *));
   m_ip = (ip_addr_t *) malloc(sizeof(ip_addr_t));
   if (!m_names || !m_ip) {
      fprintf(stderr, "ERROR: Client::init - malloc failed.\n");
      if (m_names) {
         free(m_names);
      }

      if (m_ip) {
         free(m_ip);
      }

      return false;
   }
   
   memcpy(m_ip, ip, sizeof(ip_addr_t));
   return true;
}

scan_t* Client::getScan() const
{
   return m_scan;
}

bool Client::addTarget(const data_t *flow, User *usr)
{
   if (findUser(usr)) {
      return true;
   }

   if (m_index + 1 == DEFAULT_SCAN_LIMIT) {
      m_scan = new scan_t(flow);
      if (!m_scan) {
         fprintf(stderr, "ERROR: Client::addTarget - new failed.\n");
         return false;
      }

      return true;
   } 

   if (m_index + 1 == m_size) {
      if (!extendUsers()) {
         return false;
      }
   }

   m_names[m_index] = usr;
   m_index++;

   return true;
}

int Client::getSize() const 
{
   return m_index;
}

User* Client::findUser(User *usr) const
{
   for (int i = 0; i < m_index; i++) {
      if (m_names[i] == usr) {
         return usr;
      }
   }

   return NULL;
}

void Client::removeUser(User *usr)
{
   for (int i = 0; i < m_index; i++) {
      if (m_names[i] == usr) {
         if (i + 1 == m_index) {
            m_names[i] = NULL;
         } else {
            m_names[i] = m_names[m_index - 1];
            m_names[m_index - 1] = NULL;
         }

         m_index--;
         return;
      }
   }
}

bool Client::extendUsers()
{
   User **tmp = NULL;
   m_size *= 2;
   if (m_size > DEFAULT_SCAN_LIMIT) {
      m_size = DEFAULT_SCAN_LIMIT;
   }

   tmp = (User **) realloc(m_names, m_size * sizeof(User *));
   if (!tmp) {
      fprintf(stderr, "ERROR: Client::extendTargets - realloc failed.\n");
      return false;
   }

   m_names = tmp;
   return true;
}

void Client::destroy()
{
   free(m_ip);
   delete m_scan;
   free(m_names);
}

void Client::getScanStats(stats_t *stats) const
{
   bf_t *bf = NULL;
   for (int i = 0; i < m_index; i++) {
      bf = m_names[i]->findClient(this);
      if (i == 0) {
         stats->m_protocol = bf->m_protocol;
         stats->m_link_bit_field = bf->m_link_bit_field;
         stats->m_time_first = bf->m_time_first;
         stats->m_total_count = bf->m_attempts;
      } else {
         if (stats->m_time_first > bf->m_time_first) {
            stats->m_time_first = bf->m_time_first;
         }

         stats->m_total_count += bf->m_attempts;
      }
   }

   stats->m_avg_count = stats->m_total_count / m_index;
   stats->m_total_count += m_scan->m_other_attempts;
}

bool Server::init(const data_t *flow)
{
   int (*comp_func)(void *, void *);
   uint8_t ip_bytes;
   size_t length;
   m_users = m_clients = NULL;
   m_name_suffix = NULL;
   m_ip = NULL;

   length = strlen(flow->name_suffix);
   m_ipv4 = flow->ipv4;
   m_name_suffix = (char *) malloc(length + 1);
   m_ip = (ip_addr_t *) malloc(sizeof(ip_addr_t));
   if (!m_name_suffix || !m_ip) {
      fprintf(stderr, "ERROR: Server::init - malloc failed.\n");
      goto cleanup;
   }

   strncpy(m_name_suffix, flow->name_suffix, length);
   m_name_suffix[length] = '\0';
   memcpy(m_ip, flow->ip_src, sizeof(ip_addr_t));

   if (m_ipv4) {
      comp_func = &compare_ipv4;
      ip_bytes = IP_VERSION_4_BYTES;
   } else {
      comp_func = &compare_ipv6;
      ip_bytes = IP_VERSION_6_BYTES;
   }

   m_users = bpt_init(5, &compare_user_name, sizeof(User), MAX_LENGTH_USER_NAME);
   m_clients = bpt_init(5, comp_func, sizeof(Client), ip_bytes);
   if (!m_users || !m_clients) {
      fprintf(stderr, "ERROR: Server::init - bpt_init returned NULL.\n");
      goto cleanup;
   }

   return true;

cleanup:
   if (m_name_suffix) {
      free(m_name_suffix);
      m_name_suffix = NULL;
   }

   if (m_ip) {
      free(m_ip);
      m_ip = NULL;
   }

   if (m_users) {
      bpt_clean(m_users);
      m_users = NULL;
   }

   if (m_clients) {
      bpt_clean(m_clients);
      m_clients = NULL;
   }

   return false;
}

uint64_t Server::createId(ur_time_t time_first)
{
   uint64_t event_id = 0;
   char ptr[32];
   const time_t time = time_first;
   uint16_t min_sec = 0;
   strftime(ptr, 31, "%F %T", gmtime(&time));
   ptr[4] = ptr[7] = ptr[10] = ptr[13] = ptr[16] = ptr[19] = '\0';
   event_id = (uint64_t) atoi(ptr);
   event_id *= 100;
   event_id += (uint64_t) atoi(ptr + 5);
   event_id *= 100;
   event_id += (uint64_t) atoi(ptr + 8);
   event_id *= 100;
   event_id += (uint64_t) atoi(ptr + 11);
   event_id *= 100;
   event_id += (uint64_t) atoi(ptr + 14);
   event_id *= 100;
   min_sec = ((uint16_t) (atoi(ptr + 14) * 100));
   event_id += (uint64_t) atoi(ptr + 17);
   event_id *= 10000;
   min_sec += (uint16_t) atoi(ptr + 17);
   if (min_sec == g_min_sec) {
      g_event_row++;
      event_id += g_event_row;
   } else {
      g_event_row = 0;
      g_min_sec = min_sec;
   }

   return event_id;
}

void Server::reportAlert(bf_t *bf, User *usr, Client *clt, event_type_t event)
{
   ostringstream ss;
   ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_TYPE, event);
   ur_set(alert_tmplt, alert_rec, F_SBFD_TARGET, *m_ip);

   if (event == BF) {
      if (!bf || !usr) {
         fprintf(stderr, "ERROR: Server::reportAlert - method received NULL pointer when reporting BF.\n");
         return;
      }

      ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_ID, createId(bf->m_time_first));
      ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_TIME, ur_time_from_sec_msec(bf->m_time_first, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_BREACH_TIME, ur_time_from_sec_msec(bf->m_time_breach, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_CEASE_TIME, ur_time_from_sec_msec(bf->m_time_last, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_ATTEMPTS, bf->m_attempts);
      ur_set(alert_tmplt, alert_rec, F_SBFD_AVG_ATTEMPTS, bf->m_attempts);
      ur_set(alert_tmplt, alert_rec, F_SBFD_SOURCE, *(bf->m_source->m_ip));
      ur_set(alert_tmplt, alert_rec, F_SBFD_PROTOCOL, bf->m_protocol);
      ur_set(alert_tmplt, alert_rec, F_SBFD_LINK_BIT_FIELD, bf->m_link_bit_field);
      ss << usr->m_name << '@' << m_name_suffix;
      ur_set_var(alert_tmplt, alert_rec, F_SBFD_USER, ss.str().c_str(), ss.str().length());
   } else if (event == DBF) {
      if (!usr) {
         fprintf(stderr, "ERROR: Server::reportAlert - method received NULL pointer when reporting DBF.\n");
         return;
      }

      stats_t *stats = new stats_t();
      if (!stats) {
         fprintf(stderr, "ERROR: Server::reportAlert - new failed when reporting DBF.\n");
         return;
      }

      usr->getDBFStats(stats);
      dbf_t *dbf = usr->getDBF();

      if (!dbf->m_breacher) {
         ur_set(alert_tmplt, alert_rec, F_SBFD_SOURCE, *(stats->m_clt->m_ip));
         ur_set(alert_tmplt, alert_rec, F_SBFD_BREACH_TIME, 0);
      } else {
         ur_set(alert_tmplt, alert_rec, F_SBFD_SOURCE, *(dbf->m_breacher));
         ur_set(alert_tmplt, alert_rec, F_SBFD_BREACH_TIME, ur_time_from_sec_msec(dbf->m_time_breach, 0));
      }

      ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_ID, createId(bf->m_time_first));
      ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_TIME, ur_time_from_sec_msec(stats->m_time_first, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_CEASE_TIME, ur_time_from_sec_msec(dbf->m_time_last, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_ATTEMPTS, stats->m_total_count);
      ur_set(alert_tmplt, alert_rec, F_SBFD_AVG_ATTEMPTS, stats->m_avg_count);
      
      ur_set(alert_tmplt, alert_rec, F_SBFD_PROTOCOL, stats->m_protocol);
      ur_set(alert_tmplt, alert_rec, F_SBFD_LINK_BIT_FIELD, stats->m_link_bit_field);      
      ss << usr->m_name << '@' << m_name_suffix;
      ur_set_var(alert_tmplt, alert_rec, F_SBFD_USER, ss.str().c_str(), ss.str().length());

      delete stats;
   } else if (event == SCAN) {
      if (!clt) {
         fprintf(stderr, "ERROR: Server::reportAlert - method received NULL pointer when reporting SCAN.\n");
         return;
      }

      stats_t *stats = new stats_t();
      if (!stats) {
         fprintf(stderr, "ERROR: Server::reportAlert - new failed when reporting SCAN.\n");
         return;
      }

      clt->getScanStats(stats);
      scan_t *scan = clt->getScan();

      ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_ID, createId(stats->m_time_first));
      ur_set(alert_tmplt, alert_rec, F_SBFD_EVENT_TIME, ur_time_from_sec_msec(stats->m_time_first, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_BREACH_TIME, 0);
      ur_set(alert_tmplt, alert_rec, F_SBFD_CEASE_TIME, ur_time_from_sec_msec(scan->m_time_last, 0));
      ur_set(alert_tmplt, alert_rec, F_SBFD_ATTEMPTS, stats->m_total_count);
      ur_set(alert_tmplt, alert_rec, F_SBFD_AVG_ATTEMPTS, stats->m_avg_count);
      ur_set(alert_tmplt, alert_rec, F_SBFD_SOURCE, *(clt->m_ip));
      ur_set(alert_tmplt, alert_rec, F_SBFD_PROTOCOL, stats->m_protocol);
      ur_set(alert_tmplt, alert_rec, F_SBFD_LINK_BIT_FIELD, stats->m_link_bit_field);      
      ur_set_var(alert_tmplt, alert_rec, F_SBFD_USER, "", 0);
      
      delete stats;
   } else {
      return;
   }

   int ret = trap_send(0, alert_rec, ur_rec_size(alert_tmplt, alert_rec));

   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR: Server::reportAlert - trap_send returned error value.\n");
   }
}

bool Server::insertSourceAndTarget(const data_t *flow, User *usr, Client *clt)
{
   bf_t *bf = usr->findClient(clt);
   if (flow->status_code == SIP_STATUS_OK) {
      if (!bf) {
         return true;
      }
      
      if (bf->m_time_breach != 0) {
         bf->m_time_last = flow->time_stamp;
         bf->m_attempts++;
      } else if (bf->m_attempts >= g_alert_threshold) {
         bf->m_attempts++;
         bf->m_time_breach = flow->time_stamp;
         bf->m_time_last = flow->time_stamp;
      } else {
         usr->removeBF(bf);
         clt->removeUser(usr);
      }

      return true;
   }
   
   int ret = usr->addSource(flow, clt, bf);
   switch (ret) {
      case 1:
      case 0:
         break;
      case -1:
         return false;
   }

   return true;
}

bool Server::insertFlow(const data_t *flow)
{
   int dst_ip = ip_get_v4_as_int(flow->ip_dst);
   void *tree_key = flow->ipv4 ? (void *) (&dst_ip) : (void *) flow->ip_dst;
   User *usr = (User *) bpt_search(m_users, flow->user);
   Client *clt = (Client *) bpt_search(m_clients, tree_key);

   if (usr && clt) {
      if (clt->getScan()) {
         updateScan(flow, clt, usr);
      }

      if(usr->getDBF()) {
         updateDBF(flow, clt, usr);
      }

      if(!clt->getScan() && !usr->getDBF()) {
         insertSourceAndTarget(flow, usr, clt);
      }
   } else if (!usr && clt) {
      if (clt->getScan()) {
         updateScan(flow, clt, usr);
      } else {
         usr = createUserNode(flow->user);
         if (!usr) {
            return false;
         }
         
         insertSourceAndTarget(flow, usr, clt);        
      }      
   } else if (usr && !clt) {
      if(usr->getDBF()) {
         updateDBF(flow, clt, usr);
      } else {
         clt = createClientNode(tree_key, flow->ip_dst);
         if (!clt) {
            return false;
         }
         
         insertSourceAndTarget(flow, usr, clt);         
      }
   } else {
      usr = createUserNode(flow->user);
      if (!usr) {
         return false;
      }

      clt = createClientNode(tree_key, flow->ip_dst);
      if (!clt) {
         usr->destroy(this);
         bpt_item_del(m_users, flow->user);
         return false;
      }

      insertSourceAndTarget(flow, usr, clt); 
   }

   return true;
}

void Server::updateDBF(const data_t *flow, Client *clt, User *usr)
{
   dbf_t *dbf = usr->getDBF();
   if (flow->status_code == SIP_STATUS_OK && !dbf->m_breacher) {
      dbf->addBreacher(flow->ip_dst);
      dbf->m_time_breach = flow->time_stamp;
   }

   if (!clt) {
      dbf->m_other_attempts++;
   } else {
      bf_t *bf = usr->findClient(clt);
      if (bf) {
         bf->m_time_last = flow->time_stamp;
         bf->m_attempts++;            
      } else {
         dbf->m_other_attempts++;
      }
   }

   dbf->m_time_last = flow->time_stamp;
}

void Server::updateScan(const data_t *flow, Client *clt, User *usr)
{
   scan_t *scan = clt->getScan();

   if (!usr) {
      scan->m_other_attempts++;
   } else {
      bf_t *bf = usr->findClient(clt);
      if (bf) {
         if (flow->status_code == SIP_STATUS_OK) {
            bf->m_time_breach = flow->time_stamp;
         }

         bf->m_time_last = flow->time_stamp;
         bf->m_attempts++;            
      } else {
         scan->m_other_attempts++;
      }
   }

   scan->m_time_last = flow->time_stamp;
}

Client* Server::createClientNode(void *tree_key, ip_addr_t *ip)
{
   Client *clt = (Client *) bpt_insert(m_clients, tree_key);
   if (clt) {
      if (!clt->init(ip)) {
         bpt_item_del(m_clients, tree_key);
         clt = NULL;
      }
   } else {
      fprintf(stderr, "ERROR: Server::createClientNode - bpt_insert returned NULL.\n");
   }

   return clt;
}

User* Server::createUserNode(char *name)
{
   User *usr = (User *) bpt_insert(m_users, name);
   if (usr) {
      if (!usr->init(name)) {
         bpt_item_del(m_users, name);
         usr = NULL;
      }
   } else {
      fprintf(stderr, "ERROR: Server::createUserNode - bpt_insert returned NULL.\n");
   }      

   return usr;
}

bool Server::isEmpty() const
{
   if (bpt_item_cnt(m_users) == 0 && bpt_item_cnt(m_clients) == 0) {
      return true;
   }

   return false;
}

bool Server::evaluateFlows(const ur_time_t current_time)
{
   int is_there_next;
   bpt_list_item_t *b_item;

   b_item = bpt_list_init(m_clients);
   if (!b_item) {
      fprintf(stderr, "ERROR: Server::evaluateFlows - bpt_list_init returned NULL.\n");
      return false;
   }

   is_there_next = bpt_list_start(m_clients, b_item);
   while (is_there_next == 1) {
      Client *clt = (Client *) (b_item->value);
      scan_t *scan = (scan_t *) clt->getScan();

      if (scan && (current_time > scan->m_time_last) && ((current_time - scan->m_time_last) > g_free_mem_interval)) {
         reportAlert(NULL, NULL, clt, SCAN);
         scan->m_destroy = true;
      }

      is_there_next = bpt_list_item_next(m_clients, b_item);
   }

   bpt_list_clean(b_item);

   // create a list of items in the tree and iterate through it
   b_item = bpt_list_init(m_users);
   if (!b_item) {
      fprintf(stderr, "ERROR: Server::evaluateFlows - bpt_list_init returned NULL.\n");
      return false;
   }

   is_there_next = bpt_list_start(m_users, b_item);
   while (is_there_next == 1) {
      User *usr = (User *) (b_item->value);
      int ret = usr->evaluateFlows(current_time, this);
      if (ret == 1) {
         is_there_next = bpt_list_item_del(m_users, b_item);   
      } else {
         is_there_next = bpt_list_item_next(m_users, b_item);
      }
      
   }

   bpt_list_clean(b_item);

   b_item = bpt_list_init(m_clients);
   if (!b_item) {
      fprintf(stderr, "ERROR: Server::evaluateFlows - bpt_list_init returned NULL.\n");
      return false;
   }

   is_there_next = bpt_list_start(m_clients, b_item);
   while (is_there_next == 1) {
      Client *clt = (Client *) (b_item->value);
      scan_t *scan = (scan_t *) clt->getScan();

      if ((scan && scan->m_destroy) || (clt->getSize() == 0)) {
         clt->destroy();
         is_there_next = bpt_list_item_del(m_clients, b_item);
      } else {
         is_there_next = bpt_list_item_next(m_clients, b_item);
      }
   }

   bpt_list_clean(b_item);

   return true;
}

void Server::cleanStructures()
{
   int is_there_next;
   bpt_list_item_t *b_item;

   b_item = bpt_list_init(m_clients);
   if (!b_item) {
      fprintf(stderr, "ERROR: Server::destroy - bpt_list_init returned NULL.\n");
      return;
   }

   is_there_next = bpt_list_start(m_clients, b_item);
   while (is_there_next == 1) {
      Client *clt = (Client *) (b_item->value);
      if (clt->getScan()) {
         reportAlert(NULL, NULL, clt, SCAN);
      }

      is_there_next = bpt_list_item_next(m_clients, b_item);
   }

   bpt_list_clean(b_item);

   // create a list of items in the tree and iterate through it
   b_item = bpt_list_init(m_users);
   if (!b_item) {
      fprintf(stderr, "ERROR: Server::destroy - bpt_list_init returned NULL.\n");
      return;
   }

   is_there_next = bpt_list_start(m_users, b_item);
   while (is_there_next == 1) {
      User *usr = (User *) (b_item->value);
      usr->destroy(this);
      is_there_next = bpt_list_item_del(m_users, b_item);
   }

   bpt_list_clean(b_item);

   b_item = bpt_list_init(m_clients);
   if (!b_item) {
      fprintf(stderr, "ERROR: Server::destroy - bpt_list_init returned NULL.\n");
      return;
   }

   is_there_next = bpt_list_start(m_clients, b_item);
   while (is_there_next == 1) {
      Client *clt = (Client *) (b_item->value);
      clt->destroy();
      is_there_next = bpt_list_item_del(m_clients, b_item);
   }

   bpt_list_clean(b_item);
}

void Server::destroy()
{
   bpt_clean(m_users);
   bpt_clean(m_clients);
   free(m_ip);
   free(m_name_suffix);
}

bool Detector::init()
{
   m_ipv4tree = bpt_init(5, &compare_ipv4, sizeof(Server), IP_VERSION_4_BYTES);
   m_ipv6tree = bpt_init(5, &compare_ipv6, sizeof(Server), IP_VERSION_6_BYTES);
   if (!m_ipv4tree || !m_ipv6tree) {
      fprintf(stderr, "ERROR: Detector::init - bpt_init returned NULL.\n");
      if (m_ipv4tree) {
         bpt_clean(m_ipv4tree);
      }

      if (m_ipv6tree) {
         bpt_clean(m_ipv6tree);
      }

      return false;
   }

   return true;
}

bool Detector::insertFlow(const data_t *flow)
{
   if (!flow) {
      fprintf(stderr, "ERROR: Detector::insertFlow - received NULL pointer.\n");
      return false;
   }

   bpt_t *server_tree;
   void *tree_key;
   int src_ip;

   if (flow->ipv4) {
      src_ip = ip_get_v4_as_int(flow->ip_src);
      tree_key = &src_ip;
      server_tree = m_ipv4tree;
   } else {
      tree_key = flow->ip_src;
      server_tree = m_ipv6tree;
   }

   Server *srv = (Server *) bpt_search(server_tree, tree_key);
   if (!srv) {
      if (flow->status_code == SIP_STATUS_OK) {
         return true;
      }

      srv = (Server *) bpt_insert(server_tree, tree_key);
      if (srv) {
         if (!srv->init(flow)) {
            bpt_item_del(server_tree, tree_key);
            return false;
         }
      } else {
         fprintf(stderr, "ERROR: Detector::insertFlow - bpt_insert returned NULL.\n");
         return false;
      }
   }

   return srv->insertFlow(flow);
}

bool Detector::evaluateFlows(const ur_time_t current_time)
{
   static ur_time_t time_last_check = 0;

   // Check whether it is time for another memory sweep
   if (current_time >= time_last_check && ((current_time - time_last_check) > g_check_mem_interval)) {
      int is_there_next;
      bpt_list_item_t *b_item;

      // create a list of items in the tree and iterate through it
      b_item = bpt_list_init(m_ipv4tree);
      if (!b_item) {
         fprintf(stderr, "ERROR: Detector::evaluateFlows - bpt_list_init returned NULL.\n");
         return false;
      }

      is_there_next = bpt_list_start(m_ipv4tree, b_item);
      while (is_there_next == 1) {
         Server *srv = (Server *) (b_item->value);
         if (!srv->evaluateFlows(current_time)) {
            bpt_list_clean(b_item);
            return false;
         }

         if (srv->isEmpty()) {
            srv->destroy();
            is_there_next = bpt_list_item_del(m_ipv4tree, b_item);
         } else {
            is_there_next = bpt_list_item_next(m_ipv4tree, b_item);
         }
      }

      bpt_list_clean(b_item);

      b_item = bpt_list_init(m_ipv6tree);
      if (!b_item) {
         fprintf(stderr, "ERROR: Detector::evaluateFlows - bpt_list_init returned NULL.\n");
         return false;
      }

      is_there_next = bpt_list_start(m_ipv6tree, b_item);
      while (is_there_next == 1) {
         Server *srv = (Server *) (b_item->value);
         if (!srv->evaluateFlows(current_time)) {
            bpt_list_clean(b_item);
            return false;
         }

         if (srv->isEmpty()) {
            srv->destroy();
            is_there_next = bpt_list_item_del(m_ipv6tree, b_item);
         } else {
            is_there_next = bpt_list_item_next(m_ipv6tree, b_item);
         }
      }

      bpt_list_clean(b_item);
      time_last_check = current_time;
   }

   return true;
}

void Detector::destroy()
{
   int is_there_next;
   bpt_list_item_t *b_item;

   // create a list of items in the tree and iterate through it
   b_item = bpt_list_init(m_ipv4tree);
   if (!b_item) {
      fprintf(stderr, "ERROR: Detector::destroy - bpt_list_init returned NULL.\n");
      return;
   }

   is_there_next = bpt_list_start(m_ipv4tree, b_item);
   while (is_there_next == 1) {
      Server *srv = (Server *) (b_item->value);
      srv->cleanStructures();
      srv->destroy();
      is_there_next = bpt_list_item_del(m_ipv4tree, b_item);
   }

   bpt_list_clean(b_item);

   b_item = bpt_list_init(m_ipv6tree);
   if (!b_item) {
      fprintf(stderr, "ERROR: Detector::destroy - bpt_list_init returned NULL.\n");
      return;
   }

   is_there_next = bpt_list_start(m_ipv6tree, b_item);
   while (is_there_next == 1) {
      Server *srv = (Server *) (b_item->value);
      srv->cleanStructures();
      srv->destroy();
      is_there_next = bpt_list_item_del(m_ipv6tree, b_item);
   }

   bpt_list_clean(b_item);
   bpt_clean(m_ipv4tree);
   bpt_clean(m_ipv6tree);
}

/**
 * \brief Cut first 4 characters ("sip:") or 5 characters ("sips:") from an input string and ignore ';' or '?' + string after it.
 *
 * \param[in] input_str pointer to the input string
 * \param[in,out] str_len length of the string
 * \param[out] output_str pointer to the stripped string
 * \return 0 if the input string was stripped, -1 otherwise
 */
int parse_sip_from(char *input_str, int str_len, char **user, char **suffix)
{
   if (str_len >= 4 && (strncmp(input_str, "sip:", 4) == 0)) {

      // input string beginning with "sip:"
      *user = input_str + 4 * sizeof (char);
      str_len -= 4;
   } else {
      if (str_len >= 5 && (strncmp(input_str, "sips:", 5) == 0)) {

         // input string beginning with "sips:"
         *user = input_str + 5 * sizeof (char);
         str_len -= 5;
      } else {
         return -1;
      }
   }

   *suffix = strchr(*user, '@');
   if ((*suffix) == NULL || &((*user)[str_len]) == (*suffix)) {
      return -1;
   }

   (*suffix)[0] = '\0';
   (*suffix) = (*suffix) + 1;
   str_len -= (*suffix) - (*user);

   int i = 0;
   while (i < str_len) {
      if (((*suffix)[i] == ';') || ((*suffix)[i] == '?')) {
         (*suffix)[i] = '\0';
         break;
      }

      i++;
   }

   if(strlen(*user) >= MAX_LENGTH_USER_NAME) {
      (*user)[MAX_LENGTH_USER_NAME] = '\0';
   }

   return 0;
}

/**
 * \brief Recover string from Unirec field with variable length.
 *
 * \param[in] unirec_field_id id of the Unirec field
 * \param[in] max_length maximum possible length of the recovered string
 * \param[in] in_tmplt Unirec input template
 * \param[out] string_output pointer to the recovered string
 * \param[out] string_len length of the recovered string
 */
void get_string_from_unirec(int unirec_field_id, int max_length, const void *in_rec,
                            const ur_template_t *in_tmplt, char *string_output, int *string_len)
{
   // determine length of the string
   *string_len = ur_get_var_len(in_tmplt, in_rec, unirec_field_id);
   if (*string_len > max_length) {
      *string_len = max_length;
   }

   // copy string and set terminating null character
   memcpy(string_output, ur_get_ptr_by_id(in_tmplt, in_rec, unirec_field_id), *string_len);
   string_output[*string_len] = '\0';
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   uint16_t msg_type;
   char sip_from_orig[MAX_LENGTH_SIP_FROM + 1], sip_cseq[MAX_LENGTH_CSEQ + 1];
   int sip_cseq_len;
   Detector *det = NULL;

   // initialize libtrap
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   verbose = trap_get_verbose_level();

   // create Unirec input template
   ur_template_t *in_tmplt = ur_create_input_template(0, UNIREC_INPUT_TEMPLATE, NULL);
   if (in_tmplt == NULL) {
      fprintf(stderr, "Error: input template could not be created.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return -1;
   }

   alert_tmplt = ur_create_output_template(0, UNIREC_ALERT_TEMPLATE, NULL);
   if (alert_tmplt == NULL){
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return -1;
   }

   // Allocate memory for output record
   alert_rec = ur_create_record(alert_tmplt, MAX_LENGTH_SIP_FROM);
   if (alert_rec == NULL){
      ur_free_template(in_tmplt);
      ur_free_template(alert_tmplt);
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return -1;
   }

   // parse additional parameters
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
      case 'a':
         sscanf(optarg,"%" SCNu64"", &g_alert_threshold);
         if (g_alert_threshold < 1) {
            fprintf(stderr, "Error: irrational value of alert threshold.\n");
            goto cleanup;
         }
         break;

      case 'c':
         sscanf(optarg,"%" SCNu64"", &g_check_mem_interval);
         if (g_check_mem_interval < 1) {
            fprintf(stderr, "Error: irrational value of memory check intervals.\n");
            goto cleanup;
         }
         break;

      case 'f':
         sscanf(optarg,"%" SCNu64"", &g_free_mem_interval);
         if (g_free_mem_interval < 1) {
            fprintf(stderr, "Error: irrational value of memory deallocation after last attack action.\n");
            goto cleanup;
         }
         break;

      default:
         fprintf(stderr, "Error: unsupported parameter.\n");
         goto cleanup;
      }
   }

   // initialize IPv4 and IPv6 b+ trees
   det = new Detector();
   if (!det) {
      fprintf(stderr, "ERROR: main - new failed when creating Detector object.\n");
      goto cleanup;
   }
   
   if (!det->init()) {
      goto cleanup;
   }

   // receive and process data until SIGINT is received or error occurs
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      data_t *sip_data;

      // receive data
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break;
         } else {
            fprintf(stderr, "Error: data of wrong size received (expected size: >= %hu, received size: %hu)\n", ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // determine whether this is status message with 401 Unauthorized 403 Forbidden or 200 OK code and CSEQ in format "<number> REGISTER"
      get_string_from_unirec(F_SIP_CSEQ, MAX_LENGTH_CSEQ, in_rec, in_tmplt, sip_cseq, &sip_cseq_len);
      if (!(sip_cseq_len > 2 && strstr(sip_cseq, "REG"))) {
         continue;
      }

      sip_data = (data_t *) malloc(sizeof(data_t));
      if (!sip_data) {
         fprintf(stderr, "Error: malloc failed.\n");
         break;
      }

      msg_type = ur_get(in_tmplt, in_rec, F_SIP_MSG_TYPE);
      sip_data->status_code = ur_get(in_tmplt, in_rec, F_SIP_STATUS_CODE);
      if (!(msg_type == SIP_MSG_TYPE_STATUS && (sip_data->status_code == SIP_STATUS_OK || sip_data->status_code == SIP_STATUS_UNAUTHORIZED))) {
         free(sip_data);
         continue;
      }

      int sip_from_len;
      // receive and store all vital information about this message to SipDataholder structure
      get_string_from_unirec(F_SIP_CALLING_PARTY, MAX_LENGTH_SIP_FROM, in_rec, in_tmplt, sip_from_orig, &sip_from_len);
      int invalid_sipfrom = parse_sip_from(sip_from_orig, sip_from_len, &(sip_data->user), &(sip_data->name_suffix));
      if (invalid_sipfrom) {
         free(sip_data);
         VERBOSE("Warning: invalid value of sip_from field.\n")
         continue;
      }

      sip_data->ip_src = &ur_get(in_tmplt, in_rec, F_SRC_IP);
      sip_data->ip_dst = &ur_get(in_tmplt, in_rec, F_DST_IP);
      if (ip_is_null(sip_data->ip_src) || ip_is_null(sip_data->ip_dst)) {
         free(sip_data);
         VERBOSE("Warning: null value of IP.\n")
         continue;
      }
      sip_data->link_bit_field = ur_get(in_tmplt, in_rec, F_LINK_BIT_FIELD);
      sip_data->protocol = ur_get(in_tmplt, in_rec, F_PROTOCOL);
      sip_data->time_stamp = ur_time_get_sec((ur_time_t *) ur_get(in_tmplt, in_rec, F_TIME_FIRST));
      sip_data->ipv4 = ip_is4(sip_data->ip_src);

      // insert potential attack attempt to the tree, generate alerts of type #1 and #2 (view README.md) if conditions are matched
      bool retval = det->insertFlow(sip_data);
      if (!retval) {
         free(sip_data);
         VERBOSE("Error: unable to insert possible attack attempt.\n")
         break;
      }

      if (!det->evaluateFlows((time_t) sip_data->time_stamp)) {
         free(sip_data);
         break;      
      }

      free(sip_data);
   }

cleanup:
   // free all used memory
   if (det) {
      det->destroy();
   }

   delete det;
   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   ur_free_record(alert_rec);
   ur_free_template(alert_tmplt);
   ur_free_template(in_tmplt);
   ur_finalize();

   return 0;
}