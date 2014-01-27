#include "mapflowcache.h"

using namespace std;

void MapFlowCache::init()
{
   records.clear();
   plugins_init();
}

void MapFlowCache::finish()
{
   // Export all records
   for (CacheArrayIter it = records.begin(); it != records.end(); ++it) {
      plugins_pre_export(it->second);
      exporter->export_flow(it->second);
   }

   plugins_finish();
}


// Put packet into the cache (i.e. update corresponding flow record or create a new one)
int MapFlowCache::put_pkt(Packet &pkt)
{
   if ((pkt.packetFieldIndicator & PCKT_IPV4_MASK) != PCKT_IPV4_MASK)
      return 1; // Only IPv4 packets are supported

   if ((pkt.packetFieldIndicator & PCKT_TCP_MASK) != PCKT_TCP_MASK ||
       (pkt.packetFieldIndicator & PCKT_UDP_MASK) != PCKT_UDP_MASK)
      return 2; // Only TCP/UDP packets are supported

   FlowKey key;
   key.srcip = pkt.sourceIPv4Address;
   key.dstip = pkt.destinationIPv4Address;
   key.srcport = pkt.sourceTransportPort;
   key.dstport = pkt.destinationTransportPort;
   key.proto = pkt.protocolIdentifier;

//    FlowRecord& rec = records[key];
//    update_record(rec, pkt);

   CacheArrayIter rec_it = find_record(key);
   if (rec_it != records.end()) {
      plugins_pre_update(rec_it->second, pkt);
      update_record(rec_it, pkt);
      plugins_post_update(rec_it->second, pkt);
   }
   else {
      rec_it = new_record(key, pkt);
      plugins_post_create(rec_it->second, pkt);
   }

   return 0;
}

// *** Protected methods: ***

CacheArrayIter MapFlowCache::find_record(const FlowKey &key)
{
   return records.find(key);
}

CacheArrayIter MapFlowCache::new_record(const FlowKey &key, const Packet &pkt)
{
   FlowRecord rec;
   rec.flowStartTimestamp = pkt.timestamp;
   rec.flowEndTimestamp   = pkt.timestamp;
   rec.protocolIdentifier = pkt.protocolIdentifier;
   rec.sourceIPv4Address        = pkt.sourceIPv4Address;
   rec.destinationIPv4Address   = pkt.destinationIPv4Address;
   rec.sourceTransportPort      = pkt.sourceTransportPort;
   rec.destinationTransportPort = pkt.destinationTransportPort;
   rec.packetTotalCount = 1;
   rec.octetTotalLength = pkt.ipLength;
   if (pkt.packetFieldIndicator & PCKT_TCPCONTROLBITS)
      rec.tcpControlBits   = pkt.tcpControlBits;
   else
      rec.tcpControlBits   = 0;
   rec.flowFieldIndicator = FLW_TIMESTAMPS_MASK | FLW_IPV4_MASK |
                            FLW_TCP_MASK | FLW_IPSTAT_MASK;

   return records.insert(CacheArray::value_type(key,rec)).first;
}

void MapFlowCache::update_record(CacheArrayIter rec, const Packet &pkt)
{
   FlowRecord & r = (*rec).second;
   r.flowEndTimestamp  = pkt.timestamp;
   r.packetTotalCount += 1;
   r.octetTotalLength += pkt.ipLength;
   if (pkt.packetFieldIndicator & PCKT_TCPCONTROLBITS)
      r.tcpControlBits   |= pkt.tcpControlBits;
}
