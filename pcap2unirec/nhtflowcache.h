#ifndef NHTFLOWCACHE_H
#define NHTFLOWCACHE_H

#include "main.h"
#include "flowcache.h"
#include "flowifc.h"
#include <string>

#define MAX_KEYLENGTH 76

class Flow
{
   uint64_t hash;
   uint64_t plimit;
   double inactive;
   double active;
   char key[MAX_KEYLENGTH];
   char *payload;

public:
   bool empty_flow;
   FlowRecord flowrecord;

   void erase()
   {
      flowrecord.flowFieldIndicator = 0x0;
      flowrecord.flowStartTimestamp = 0;
      flowrecord.flowEndTimestamp = 0;
      flowrecord.ipVersion = 0;
      flowrecord.protocolIdentifier = 0;
      flowrecord.ipClassOfService = 0;
      flowrecord.ipTtl = 0;
      flowrecord.sourceIPv4Address = 0;
      flowrecord.destinationIPv4Address = 0;
      flowrecord.sourceTransportPort = 0;
      flowrecord.destinationTransportPort = 0;
      flowrecord.octetTotalLength = 0;
      flowrecord.packetTotalCount = 0;
      flowrecord.tcpControlBits = 0;
      flowrecord.flowPayloadSize = 0;
      flowrecord.flowPayloadStart = 0;
      empty_flow = true;
   }

   Flow(uint64_t payloadlimit, double inactivetimeout, double activetimeout)
   {
      erase();
      this->plimit = payloadlimit;
      this->inactive = inactivetimeout;
      this->active = activetimeout;
      if (plimit > 0) {
         payload = new char(plimit);
      }
   };
   ~Flow()
   {
      if (plimit > 0) {
            delete payload;
      }
   };

   bool isempty();
   inline bool isexpired(double current_ts);
   bool belongs(uint64_t pkt_hash, char *pkt_key, uint8_t key_len);
   void create(Packet pkt, uint64_t pkt_hash, char *pkt_key, uint8_t key_len);
   void update(Packet pkt);
};

typedef std::vector<int> replacementvector_t;
typedef replacementvector_t::iterator replacementvectoriter_t;

typedef std::vector<Flow *> ptrflowvector_t;
typedef ptrflowvector_t::iterator ptrflowvectoriter_t;

class NHTFlowCache : public FlowCache
{
   bool statsout;
   uint8_t key_len;
   int linesize;
   int size;
   int insertpos;
   long empty;
   long notempty;
   long hits;
   long expired;
   long lookups;
   long lookups2;
   double currtimestamp;
   double lasttimestamp;
   char key[MAX_KEYLENGTH];
   std::string policy;
   replacementvector_t rpl;
   ptrflowvector_t flowexportqueue;
   Flow ** flowarray;

public:
   NHTFlowCache(options_t options)
   {
      this->linesize = options.flowlinesize;
      this->empty = 0;
      this->notempty = 0;
      this->hits = 0;
      this->expired = 0;
      this->size = options.flowcachesize;
      this->lookups = 0;
      this->lookups2 = 0;
      this->policy = options.replacementstring;
      this->statsout = options.statsout;
      flowarray = new Flow* [size];
      for (int i = 0; i < size; i++)
         flowarray[i] = new Flow(options.payloadlimit, options.inactivetimeout, options.activetimeout);
   };
   ~NHTFlowCache()
   {
      delete [] flowarray;
      while (!flowexportqueue.empty()) {
         delete flowexportqueue.back();
         flowexportqueue.pop_back();
      }
   };

// Put packet into the cache (i.e. update corresponding flow record or create a new one)
   virtual int put_pkt(Packet &pkt);
   virtual void init();
   virtual void finish();

protected:
   void parsereplacementstring();
   void createhashkey(Packet pkt);
   long calculatehash();
   int flushflows();
   int exportexpired(bool exportall);
   void endreport();
};

#endif
