#include "nhtflowcache.h"
#include "flowcache.h"

#include <cstdlib>
#include <iostream>
#include <locale>

using namespace std;

inline bool Flow::isexpired(double current_ts)
{
   if (!isempty() &&
      (current_ts - flowrecord.flowStartTimestamp > active ||
         current_ts - flowrecord.flowEndTimestamp > inactive))
   {
      return true;
   }
   else
      return false;
}

bool Flow::isempty()
{
   return empty_flow;
}

bool Flow::belongs(uint64_t pkt_hash, char *pkt_key, uint8_t key_len)
{
   if (isempty() || (pkt_hash != hash)) {
      return false;
   }
   else {
      return (memcmp(key, pkt_key, key_len) == 0);
   }
}

void Flow::create(Packet pkt, uint64_t pkt_hash, char *pkt_key, uint8_t key_len)
{
   flowrecord.flowFieldIndicator = FLW_FLOWFIELDINDICATOR;
   flowrecord.packetTotalCount = 1;
   flowrecord.flowFieldIndicator |= FLW_PACKETTOTALCOUNT;

   hash = pkt_hash;
   memcpy(key, pkt_key, key_len);

   if ((pkt.packetFieldIndicator & PCKT_INFO_MASK) == PCKT_INFO_MASK)
      flowrecord.flowFieldIndicator |= FLW_HASH;

   if ((pkt.packetFieldIndicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK) {
      flowrecord.flowStartTimestamp = pkt.timestamp;
      flowrecord.flowEndTimestamp = pkt.timestamp;
      flowrecord.flowFieldIndicator |= FLW_TIMESTAMPS_MASK;
   }

   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      flowrecord.ipVersion                = pkt.ipVersion;
      flowrecord.protocolIdentifier       = pkt.protocolIdentifier;
      flowrecord.ipClassOfService         = pkt.ipClassOfService;
      flowrecord.ipTtl                    = pkt.ipTtl;
      flowrecord.sourceIPv4Address        = pkt.sourceIPv4Address;
      flowrecord.destinationIPv4Address   = pkt.destinationIPv4Address;
      flowrecord.octetTotalLength         = pkt.ipLength;
      flowrecord.flowFieldIndicator      |= FLW_IPV4_MASK;
      flowrecord.flowFieldIndicator      |= FLW_IPSTAT_MASK;
   }
   else if ((pkt.packetFieldIndicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      flowrecord.ipVersion                = pkt.ipVersion;
      flowrecord.protocolIdentifier       = pkt.protocolIdentifier;
      flowrecord.ipClassOfService         = pkt.ipClassOfService;
      memcpy(flowrecord.sourceIPv6Address, pkt.sourceIPv6Address, 16);
      memcpy(flowrecord.destinationIPv6Address, pkt.destinationIPv6Address, 16);
      flowrecord.octetTotalLength         = pkt.ipLength;
      flowrecord.flowFieldIndicator      |= FLW_IPV6_MASK;
      flowrecord.flowFieldIndicator      |= FLW_IPSTAT_MASK;
   }

   if ((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) {
      flowrecord.sourceTransportPort      = pkt.sourceTransportPort;
      flowrecord.destinationTransportPort = pkt.destinationTransportPort;
      flowrecord.tcpControlBits           = pkt.tcpControlBits;
      flowrecord.flowFieldIndicator       |= FLW_TCP_MASK;
   }
   else if ((pkt.packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) {
      flowrecord.sourceTransportPort      = pkt.sourceTransportPort;
      flowrecord.destinationTransportPort = pkt.destinationTransportPort;
      flowrecord.flowFieldIndicator       |= FLW_UDP_MASK;
   }

   if (plimit > 0) {
      flowrecord.flowFieldIndicator |= FLW_PAYLOAD_MASK;
      uint64_t oldflowpayloadsize = flowrecord.flowPayloadSize;
      if ((pkt.packetFieldIndicator & PCKT_PAYLOAD_MASK) == PCKT_PAYLOAD_MASK) {
         if ((flowrecord.flowPayloadSize + pkt.transportPayloadPacketSectionSize) > plimit)
            flowrecord.flowPayloadSize = plimit;
         else
            flowrecord.flowPayloadSize = pkt.transportPayloadPacketSectionSize;
      }
      if (oldflowpayloadsize < flowrecord.flowPayloadSize)
         memcpy(payload, pkt.transportPayloadPacketSection, flowrecord.flowPayloadSize - oldflowpayloadsize);
   }
   empty_flow = false;
}

void Flow::update(Packet pkt)
{
   flowrecord.packetTotalCount += 1;
   if ((pkt.packetFieldIndicator & PCKT_PCAP_MASK) == PCKT_PCAP_MASK)
      flowrecord.flowEndTimestamp   = pkt.timestamp;
   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK)
      flowrecord.octetTotalLength       += pkt.ipLength;
   if ((pkt.packetFieldIndicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK)
      flowrecord.octetTotalLength       += pkt.ipLength;
   if ((pkt.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK)
      flowrecord.tcpControlBits         |= pkt.tcpControlBits;
   if (plimit > 0) {
      uint64_t oldflowpayloadsize = flowrecord.flowPayloadSize;
      if ((pkt.packetFieldIndicator & PCKT_PAYLOAD_MASK) == PCKT_PAYLOAD_MASK) {
         if ((flowrecord.flowPayloadSize + pkt.transportPayloadPacketSectionSize) > plimit)
            flowrecord.flowPayloadSize = plimit;
         else
            flowrecord.flowPayloadSize += pkt.transportPayloadPacketSectionSize;
      }
      if (oldflowpayloadsize < flowrecord.flowPayloadSize)
         memcpy(payload, pkt.transportPayloadPacketSection, flowrecord.flowPayloadSize - oldflowpayloadsize);
   }
}

// NHTFlowCache -- PUBLIC *****************************************************

void NHTFlowCache::init()
{
   plugins_init();
   parsereplacementstring();
   insertpos = rpl[0];
   rpl.assign(rpl.begin()+1, rpl.end());
}

void NHTFlowCache::finish()
{
   plugins_finish();
   exportexpired(true); // export whole cache
   if (!statsout)
      endreport();
}

int NHTFlowCache::put_pkt(Packet &pkt)
{
// Support check
   if (((pkt.packetFieldIndicator & PCKT_TCP_MASK) != PCKT_TCP_MASK) &&
       ((pkt.packetFieldIndicator & PCKT_UDP_MASK) != PCKT_UDP_MASK))
      return 2; // Only TCP/UDP packets are supported

   createhashkey(pkt); // saves key value and key length into attributes NHTFlowCache::key and NHTFlowCache::key_len
   uint64_t hashval = calculatehash(); // calculates hash value from key created before

// Find place for packet
   int lineindex = ((hashval%size)/linesize) * linesize;

   bool found = false;
   int flowindex = 0;

   for (flowindex = lineindex; flowindex < (lineindex + linesize); flowindex++) {
      if (flowarray[flowindex]->belongs(hashval, key, key_len)) {
         found = true;
         break;
      }
   }

   if (found) {
      lookups += (flowindex - lineindex + 1);
      lookups2 += (flowindex - lineindex + 1)*(flowindex - lineindex + 1);
      int relpos = flowindex - lineindex;
      int newrel = rpl[relpos];
      int flowindexstart = lineindex + newrel;

      Flow * ptrflow = flowarray[flowindex];
      for (int j = flowindex; j > flowindexstart; j--)
         flowarray[j] = flowarray[j-1];
      flowarray[flowindexstart] = ptrflow;
      flowindex = flowindexstart;
      hits++;
   }
   else {
      for (flowindex = lineindex; flowindex < (lineindex + linesize); flowindex++) {
         if (flowarray[flowindex]->isempty()) {
            found = true;
            break;
         }
      }
      if (!found) {
         flowindex = lineindex + linesize - 1;

// Export flow
         plugins_pre_export(flowarray[flowindex]->flowrecord);
         exporter->export_flow(flowarray[flowindex]->flowrecord);

         expired++;
         int flowindexstart = lineindex + insertpos;
         Flow * ptrflow = flowarray[flowindex];
         ptrflow->erase();
         for (int j = flowindex; j > flowindexstart; j--)
            flowarray[j] = flowarray[j-1];
         flowindex = flowindexstart;
         flowarray[flowindex] = ptrflow;
         notempty++;
      }
      else
         empty++;
   }

   currtimestamp = pkt.timestamp;

   if (flowarray[flowindex]->isempty()) {
      flowarray[flowindex]->create(pkt, hashval, key, key_len);
      plugins_post_create(flowarray[flowindex]->flowrecord, pkt);
   }
   else {
      plugins_pre_update(flowarray[flowindex]->flowrecord, pkt);
      flowarray[flowindex]->update(pkt);
      plugins_post_update(flowarray[flowindex]->flowrecord, pkt);
   }

   if (currtimestamp - lasttimestamp > 5.0) {
      exportexpired(false); // false -- export only expired flows
      lasttimestamp = currtimestamp;
   }

   return 0;
}

// NHTFlowCache -- PROTECTED **************************************************

void NHTFlowCache::parsereplacementstring()
{
   size_t searchpos = 0;
   size_t searchposold = 0;

   while ((searchpos = policy.find(',',searchpos)) != string::npos) {
      rpl.push_back(atoi((char *) policy.substr(searchposold, searchpos-searchposold).c_str()));
      searchpos++;
      searchposold = searchpos;
   }
   rpl.push_back(atoi((char *) policy.substr(searchposold).c_str()));
}

long NHTFlowCache::calculatehash()
{
   locale loc;
   const collate<char>& coll = use_facet<collate<char> >(loc);
   return coll.hash(key,key+key_len);
}

void NHTFlowCache::createhashkey(Packet pkt)
{
   char *k = key;

   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) == PCKT_IPV4_MASK) {
      *(uint8_t *) k = pkt.protocolIdentifier;
      k += sizeof(pkt.protocolIdentifier);
      *(uint32_t *) k = pkt.sourceIPv4Address;
      k += sizeof(pkt.sourceIPv4Address);
      *(uint32_t *) k = pkt.destinationIPv4Address;
      k += sizeof(pkt.destinationIPv4Address);
      *(uint16_t *) k = pkt.sourceTransportPort;
      k += sizeof(pkt.sourceTransportPort);
      *(uint16_t *) k = pkt.destinationTransportPort;
      k += sizeof(pkt.destinationTransportPort);
      *k = '\0';
      key_len = 13;
   }

   if ((pkt.packetFieldIndicator & PCKT_IPV6_MASK) == PCKT_IPV6_MASK) {
      for (int i=0; i<16; i++) {
         *(char *) k = pkt.sourceIPv6Address[i];
         k += sizeof(pkt.sourceIPv6Address[i]);
      }
      for (int i=0; i<16; i++) {
         *(char *) k = pkt.destinationIPv6Address[i];
         k += sizeof(pkt.destinationIPv6Address[i]);
      }
      *(uint16_t *) k = pkt.sourceTransportPort;
      k += sizeof(pkt.sourceTransportPort);
      *(uint16_t *) k = pkt.destinationTransportPort;
      k += sizeof(pkt.destinationTransportPort);
      *k = '\0';
      key_len = 36;
   }
}

int NHTFlowCache::exportexpired(bool exportall)
{
   int exported = 0;
   bool result = false;
   for (int i = 0; i < size; i++) {
      if (exportall && !flowarray[i]->isempty())
         result = true;
      if (!exportall && flowarray[i]->isexpired(currtimestamp))
         result = true;
      if (result) {
         plugins_pre_export(flowarray[i]->flowrecord);
         exporter->export_flow(flowarray[i]->flowrecord);

         flowarray[i]->erase();
         expired++;
         exported++;
         result = false;
      }
   }
   return exported;
}

void NHTFlowCache::endreport()
{
   float a = float(lookups)/hits;

   cout << "Hits: " << hits << endl;
   cout << "Empty: " << empty << endl;
   cout << "Not empty: " << notempty << endl;
   cout << "Expired: " << expired << endl;
   cout << "Average Lookup:  " << a << endl;
   cout << "Variance Lookup: " << float(lookups2)/hits-a*a << endl;
}
