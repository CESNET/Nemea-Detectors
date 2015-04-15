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

#ifndef _EVENTHANDLER_H_
#define _EVENTHANDLER_H_

#include <string>
#include <vector>
#include <cstdio>
#include <cstdarg>
#include "hoststats.h"

extern "C" {
   #include <unirec/unirec.h>
}

#define ICMP 1
#define TCP 6
#define UDP 17

// Struct containing information about a detected event (attack/incident/anomaly)
class Event
{
public:
   uint8_t type;
   uint32_t time_first, time_last;
   std::vector<ip_addr_t> src_addr, dst_addr;
   std::vector<uint16_t> src_port, dst_port;
   std::vector<uint8_t> proto;
   uint32_t scale;
   std::string note;

   Event(const uint32_t &time_first, const uint32_t &time_last, uint8_t type)
    : type(type), time_first(time_first), time_last(time_last)
   { }

   // Methods to set parameters
   Event& addSrcAddr(const ip_addr_t &addr)
   {
      this->src_addr.push_back(addr);
      return *this;
   }
   Event& addDstAddr(const ip_addr_t &addr)
   {
      this->dst_addr.push_back(addr);
      return *this;
   }
   Event& addSrcPort(uint16_t port)
   {
      this->src_port.push_back(port);
      return *this;
   }
   Event& addDstPort(uint16_t port)
   {
      this->dst_port.push_back(port);
      return *this;
   }
   Event& addProto(uint8_t proto)
   {
      this->proto.push_back(proto);
      return *this;
   }
   Event& setScale(uint32_t scale)
   {
      this->scale = scale;
      return *this;
   }
   Event& setNote(const std::string &note)
   {
      this->note = note;
      return *this;
   }
   Event& setNote(const char* fmt, ...)
   {
      char buf[256];
      va_list args;
      va_start(args, fmt);
      vsnprintf(buf, 256, fmt, args); // TODO podivat se na definici vsnprintf
      va_end(args);
      this->note = std::string(buf);
      return *this;
   }
};

void reportEvent(const Event& event);


#endif
