/*
 * Copyright (C) 2013-2015 CESNET
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

#include "eventhandler.h"
#include "hs_config.h"
#include "aux_func.h"
#include "profile.h"

#include <fstream>
extern "C" {
   #include <libtrap/trap.h>
   #include "fields.h"
}
#include <unirec/ipaddr_cpp.h>

using namespace std;

extern ur_template_t *tmpl_out;
extern HostProfile *MainProfile;

string getProtoString(uint8_t proto);
string getTypeString(uint8_t type);
string getTimeString(const uint32_t &timestamp);

void reportEvent(const Event& event)
{
   string first_t = getTimeString(event.time_first);
   string last_t = getTimeString(event.time_last);

   // Print info about event into a string
   stringstream line;
   line << first_t << ';' << last_t << ';';
   line << getTypeString(event.type) << ';';
   for (vector<uint8_t>::const_iterator it = event.proto.begin(); it != event.proto.end(); ++it) {
      if (it != event.proto.begin())
         line << ',';
      line << (int)*it;
   }
   line << ';';
   for (vector<ip_addr_t>::const_iterator it = event.src_addr.begin(); it != event.src_addr.end(); ++it) {
      if (it != event.src_addr.begin())
         line << ',';
      line << IPaddr_cpp(&(*it));
   }
   line << ';';
   for (vector<ip_addr_t>::const_iterator it = event.dst_addr.begin(); it != event.dst_addr.end(); ++it) {
      if (it != event.dst_addr.begin())
         line << ',';
      line << IPaddr_cpp(&(*it));
   }
   line << ';';
   for (vector<uint16_t>::const_iterator it = event.src_port.begin(); it != event.src_port.end(); ++it) {
      if (it != event.src_port.begin())
         line << ',';
      line << *it;
   }
   line << ';';
   for (vector<uint16_t>::const_iterator it = event.dst_port.begin(); it != event.dst_port.end(); ++it) {
      if (it != event.dst_port.begin())
         line << ',';
      line << *it;
   }
   line << ';';
   line << event.scale << ';';
   line << event.note << '\n';

   // Write the line to a log file
   Configuration *config = Configuration::getInstance();
   config->lock();
   string path = config->getValue("detection-log");
   config->unlock();

   string y = first_t.substr(0,4);
   string m = first_t.substr(4,2);
   string d = first_t.substr(6,2);
   string h = first_t.substr(8,2);
   string n = first_t.substr(10,2);

   if (!path.empty()) {
      if (path[path.size()-1] != '/')
         path += '/';
      path += y + m + d + ".log";

      // Open file and append the line
      ofstream logfile(path.c_str(), ios_base::app);
      if (logfile.good()) {
         logfile << line.str();
         logfile.close();
      }
      else {
         log(LOG_ERR, "Can't open log file \"%s\".", path.c_str());
      }
   }

   // Send event report to TRAP output interface (HALF_WAIT)

   // Allocate memory for Warden report
   const uint16_t WT_NOTE_SIZE = 200;
   void *rec = ur_create_record(tmpl_out, WT_NOTE_SIZE);
   if (rec == NULL) {
      log(LOG_ERR, "Failed to allocate new memory for a Warden detection report.");
      return;
   }

   // TIMESTAMPS AND EVENT TYPE
   ur_set(tmpl_out, rec, F_EVENT_TYPE, event.type);
   ur_set(tmpl_out, rec, F_TIME_FIRST, ur_time_from_sec_msec(event.time_first,0));
   ur_set(tmpl_out, rec, F_TIME_LAST, ur_time_from_sec_msec(event.time_last, 0));

   // SRC IP ADDRESS
   if (!event.src_addr.empty()) {
      ur_set(tmpl_out, rec, F_SRC_IP, event.src_addr.front());
   } else {
      ur_set(tmpl_out, rec, F_SRC_IP, ip_from_int(0));
   }

   // DST IP ADDRESS
   if (!event.dst_addr.empty()) {
      ur_set(tmpl_out, rec, F_DST_IP, event.dst_addr.front());
   } else {
      ur_set(tmpl_out, rec, F_DST_IP, ip_from_int(0));
   }

   // SRC PORT
   if (!event.src_port.empty()) {
      ur_set(tmpl_out, rec, F_SRC_PORT, event.src_port.front());
   } else {
      ur_set(tmpl_out, rec, F_SRC_PORT, 0);
   }

   // DST PORT
   if (!event.dst_port.empty()) {
      ur_set(tmpl_out, rec, F_DST_PORT, event.dst_port.front());
   } else {
      ur_set(tmpl_out, rec, F_DST_PORT, 0);
   }

   // PROTOCOL
   if (!event.proto.empty()) {
      ur_set(tmpl_out, rec, F_PROTOCOL, event.proto.front());
   } else {
      ur_set(tmpl_out, rec, F_PROTOCOL, 0);
   }

   // EVENT SCALE
   ur_set(tmpl_out, rec, F_EVENT_SCALE, event.scale);

   // NOTE
   char buffer [WT_NOTE_SIZE];
   int offset = snprintf(buffer, WT_NOTE_SIZE,
      event.note.c_str());
   if (offset > 0) {
      ur_set_string(tmpl_out, rec, F_NOTE, buffer);
   } else {
      log(LOG_ERR, "Failed to create dynamic Unirec item.");
      ur_free_record(rec);
      return;
   }

   int ret = trap_send(0, rec, ur_rec_size(tmpl_out, rec));
   if (ret != TRAP_E_OK) {
      log(LOG_ERR, "Error: trap_send()");
   }

   ur_free_record(rec);
}


string getTypeString(uint8_t type)
{
   switch (type)
   {
      case EVT_T_PORTSCAN:   return "portscan";
      case EVT_T_PORTSCAN_H: return "portscan_h";
      case EVT_T_PORTSCAN_V: return "portscan_v";
      case EVT_T_BRUTEFORCE: return "bruteforce";
      case EVT_T_DOS:        return "dos";
      case EVT_T_DNSAMP:     return "dnsamp";
      case EVT_T_SYNFLOOD:   return "synflood";
      default: return string("type_")+int2str((int)type);
   }
}


string getProtoString(uint8_t proto)
{
   switch (proto)
   {
      case TCP:  return "TCP";
      case UDP:  return "UDP";
      case ICMP: return "ICMP";
      default:   return int2str((int)proto);
   }
}

std::string getTimeString(const uint32_t &timestamp)
{
   const time_t temp = timestamp;
   char buff[13]; //12 signs + '/0'
   strftime(buff, 13, "%4Y%2m%2d%2H%2M", gmtime(&temp));

   return string(buff);
}
