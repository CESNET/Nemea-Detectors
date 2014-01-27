#ifndef PACKETRECEIVER_H
#define PACKETRECEIVER_H

#include <string>
#include "packet.h"

class PacketReceiver
{
public:
   std::string errmsg;
   virtual int get_pkt(Packet &packet) = 0;
};

#endif
