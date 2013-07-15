#ifndef _EVENTHANDLER_H_
#define _EVENTHANDLER_H_

#include <string>
#include <vector>
#include <cstdio>
#include <cstdarg>

#include "aux_func.h"
#include "../../../unirec/ipaddr_cpp.h"
#include "../../../unirec/unirec.h"

enum EventType {PORTSCAN, PORTSCAN_H, PORTSCAN_V, DOS, DDOS, BRUTEFORCE, OTHER};

#define ICMP 1
#define TCP 6
#define UDP 17

// Struct containing information about a detected event (attack/incident/anomaly)
class Event
{
public:
   EventType type;
   std::string timeslot;
   std::vector<IPaddr_cpp> src_addr, dst_addr;
   std::vector<uint16_t> src_port, dst_port;
   std::vector<uint8_t> proto;
   int scale;
   std::string note;
   
   Event(const std::string &timeslot, EventType type)
    : type(type), timeslot(timeslot)
   { }
   
   // Methods to set parameters
   Event& addSrcAddr(const IPaddr_cpp &addr)
   {
      this->src_addr.push_back(addr);
      return *this;
   }
   Event& addDstAddr(const IPaddr_cpp &addr)
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
   Event& setScale(int scale)
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
