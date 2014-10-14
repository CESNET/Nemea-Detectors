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
   // Skip victims 
   if (event.src_addr.empty()) {
      return;
   }
   
   // Allocate memory for Warden report
   const uint16_t WT_NOTE_SIZE = 200;
   void *rec = ur_create(tmpl_out, WT_NOTE_SIZE);
   if (rec == NULL) {
      log(LOG_ERR, "Failed to allocate new memory for a Warden detection report.");
      return;
   }
   
   // Convert EVENT_TYPE to WARDEN_TYPE
   uint8_t w_type = UR_WT_OTHER;
   switch(event.type) {
      case UR_EVT_T_PORTSCAN:
      case UR_EVT_T_PORTSCAN_H:
      case UR_EVT_T_PORTSCAN_V:
         w_type = UR_WT_PORTSCAN;
         break;
         
      case UR_EVT_T_DOS:
      case UR_EVT_T_SYNFLOOD:
      case UR_EVT_T_DNSAMP:
         w_type = UR_WT_DOS;
         break;

      case UR_EVT_T_BRUTEFORCE:
         w_type = UR_WT_BRUTEFORCE;
         break;
         
      default:
         w_type = UR_WT_OTHER;
         break;
   }
   
   
   // WARDEN_REPORT = "DETECTION_TIME,WARDEN_TYPE,SRC_IP,PROTOCOL,DST_PORT,EVENT_SCALE,NOTE"
   
   // DETECTION_TIME
   ur_set(tmpl_out, rec, UR_DETECTION_TIME, ur_time_from_sec_msec(event.time_first,0));
   
   // WARDEN_TYPE
   ur_set(tmpl_out, rec, UR_WARDEN_TYPE, w_type);
   
   // SRC_IP
   ur_set(tmpl_out, rec, UR_SRC_IP, event.src_addr.front());
   
   // PROTOCOL
   if (!event.proto.empty()) {
      ur_set(tmpl_out, rec, UR_PROTOCOL, event.proto.front());
   } else {
      // Unknown protocol
      ur_set(tmpl_out, rec, UR_PROTOCOL, 255);
   }
   
   // DST PORT
   if (!event.dst_port.empty()) {
      ur_set(tmpl_out, rec, UR_DST_PORT, event.dst_port.front());
   } else {
      ur_set(tmpl_out, rec, UR_DST_PORT, 0);
   }
   
   // EVENT_SCALE
   ur_set(tmpl_out, rec, UR_EVENT_SCALE, event.scale);
   
   // NOTE
   int offset = snprintf((char *) rec + ur_rec_static_size(tmpl_out), 
      WT_NOTE_SIZE, event.note.c_str());
   if (offset > 0) {
      ur_set_dyn_offset(tmpl_out, rec, UR_NOTE, offset);
   } else {
      log(LOG_ERR, "Failed to create dynamic Unirec item.");
      ur_free(rec);
      return;
   }

   int ret = trap_send_data(0, rec, ur_rec_size(tmpl_out, rec), TRAP_NO_WAIT);
   if (ret != TRAP_E_OK) {
      log(LOG_ERR, "Error: trap_send_data()");
   }
   
   ur_free(rec);
}


string getTypeString(uint8_t type)
{
   switch (type)
   {
      case UR_EVT_T_PORTSCAN:   return "portscan";
      case UR_EVT_T_PORTSCAN_H: return "portscan_h";
      case UR_EVT_T_PORTSCAN_V: return "portscan_v";
      case UR_EVT_T_BRUTEFORCE: return "bruteforce";
      case UR_EVT_T_DOS:        return "dos";
      case UR_EVT_T_DNSAMP:     return "dnsamp";
      case UR_EVT_T_SYNFLOOD:   return "synflood";
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