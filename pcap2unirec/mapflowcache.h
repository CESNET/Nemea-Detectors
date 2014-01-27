#ifndef MAPFLOWCACHE_H
#define MAPFLOWCACHE_H

#include "flowcache.h"
#include <map>

struct FlowKey {
   uint32_t srcip;
   uint32_t dstip;
   uint16_t srcport;
   uint16_t dstport;
   uint8_t  proto;
};

class KeyComparator {
public:
   bool operator()(const FlowKey &f1, const FlowKey &f2)
   {
      if (f1.srcip != f2.srcip)
         return (f1.srcip < f2.srcip);
      else if (f1.dstip != f2.dstip)
         return (f1.dstip < f2.dstip);
      else if (f1.srcport != f2.srcport)
         return (f1.srcport < f2.srcport);
      else if (f1.dstport != f2.dstport)
         return (f1.dstport < f2.dstport);
      else
         return (f1.proto < f2.proto);
   }
};


typedef std::map<FlowKey, FlowRecord, KeyComparator> CacheArray;
typedef CacheArray::iterator CacheArrayIter;

class MapFlowCache : public FlowCache
{
   CacheArray records;
   
public:
   // Put packet into the cache (i.e. update corresponding flow record or create a new one)
   virtual int put_pkt(Packet &pkt);
   
   virtual void init();
   virtual void finish();
   
protected:
   CacheArrayIter find_record(const FlowKey &key);
   CacheArrayIter new_record(const FlowKey &key, const Packet &pkt);
   void update_record(CacheArrayIter flow, const Packet &pkt);
   
};

#endif

