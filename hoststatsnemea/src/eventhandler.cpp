/*
 * Copyright (C) 2013 CESNET
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
#include "config.h"
#include "aux_func.h"
#include "profile.h"

#include <fstream>
extern "C" {
   #include <libtrap/trap.h>
}
//#include <unirec/ipaddr.h>
#include <unirec/ipaddr_cpp.h>

using namespace std;

extern ur_template_t *tmpl_out;
extern HostProfile *MainProfile;

string getProtoString(uint8_t proto);
string getTypeString(EventType type);
string getTimeString(const uint32_t &timestamp);

void reportEvent(const hosts_key_t &ip, const Event& event)
{
   // Check if the event has already been reported -> double detection
   if (MainProfile->old_rec_list_present(ip)) {
      log(LOG_DEBUG, "Event report skipped. It has already been reported");
      return;
   }

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
   void *rec = ur_create(tmpl_out, 0);

   ur_set(tmpl_out, rec, UR_EVENT_TYPE, event.type);
   ur_set(tmpl_out, rec, UR_TIME_FIRST, ur_time_from_sec_msec(event.time_first,0));
   ur_set(tmpl_out, rec, UR_TIME_LAST, ur_time_from_sec_msec(event.time_last, 0));

   // SRC IP ADDRESS
   if (!event.src_addr.empty()) {
      ur_set(tmpl_out, rec, UR_SRC_IP, event.src_addr.front());
   } else {
      ur_set(tmpl_out, rec, UR_SRC_IP, ip_from_int(0));
   }


   // DST IP ADDRESS
   if (!event.dst_addr.empty()) {
      ur_set(tmpl_out, rec, UR_DST_IP, event.dst_addr.front());
   } else {
      ur_set(tmpl_out, rec, UR_DST_IP, ip_from_int(0));
   }

   // SRC PORT
   if (!event.src_port.empty()) {
      ur_set(tmpl_out, rec, UR_SRC_PORT, event.src_port.front());
   } else {
      ur_set(tmpl_out, rec, UR_SRC_PORT, 0);
   }

   // DST PORT
   if (!event.dst_port.empty()) {
      ur_set(tmpl_out, rec, UR_DST_PORT, event.dst_port.front());
   } else {
      ur_set(tmpl_out, rec, UR_DST_PORT, 0);
   }

   // PROTOCOL
   if (!event.proto.empty()) {
      ur_set(tmpl_out, rec, UR_PROTOCOL, event.proto.front());
   } else {
      ur_set(tmpl_out, rec, UR_PROTOCOL, 0);
   }

   ur_set(tmpl_out, rec, UR_EVENT_SCALE, event.scale);

   trap_send_data(0, rec, ur_rec_static_size(tmpl_out), TRAP_NO_WAIT);

   ur_free(rec);
}


string getTypeString(EventType type)
{
   switch (type)
   {
      case PORTSCAN:   return "portscan";
      case PORTSCAN_H: return "portscan_h";
      case PORTSCAN_V: return "portscan_v";
      case BRUTEFORCE: return "bruteforce";
      case DOS:        return "dos";
      case OTHER:      return "other";
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