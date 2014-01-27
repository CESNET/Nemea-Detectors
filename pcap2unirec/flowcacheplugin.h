#ifndef FLOWCACHEPLUGIN_H
#define FLOWCACHEPLUGIN_H

#include "packet.h"
#include "flowifc.h"

class FlowCachePlugin
{
public:
   // Called before the start of processing
   virtual void init() {}
   // Called after a new flow record is created
   virtual void post_create(FlowRecord &rec, const Packet &pkt) {}
   // Called before an existing record is updated
   virtual void pre_update(FlowRecord &rec, Packet &pkt) {}
   // Called after an existing record is updated
   virtual void post_update(FlowRecord &rec, const Packet &pkt) {}
   // Called before a flow record is exported from the cache
   virtual void pre_export(FlowRecord &rec) {}
   // Called when everything is processed
   virtual void finish() {}
};

#endif
