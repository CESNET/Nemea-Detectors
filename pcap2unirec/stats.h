#ifndef STATS_H
#define STATS_H

#include "flowcacheplugin.h"

#include <ostream>

class StatsPlugin : public FlowCachePlugin
{
   unsigned long packets;
   unsigned long new_flows;
   unsigned long cache_hits;
   unsigned long flows_in_cache;

   double interval;
   double last_ts;
   std::ostream &out;

   FILE *create_keys;
   FILE *export_keys;

   void check_timestamp(const Packet &pkt);
   void print_header() const;
   void print_stats(double ts) const;

public:
   StatsPlugin(double interval, std::ostream &out);

   void init();
   void post_create(FlowRecord &rec, const Packet &pkt);
   void post_update(FlowRecord &rec, const Packet &pkt);
   void pre_export(FlowRecord &rec);
   void finish();

};

#endif
