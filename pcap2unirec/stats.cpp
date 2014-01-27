#include "stats.h"

#include <iostream>
#include <iomanip>

using namespace std;

// Constructor
StatsPlugin::StatsPlugin(double interval, ostream &out)
 : interval(interval), out(out)
{}

void StatsPlugin::init()
{
   packets = new_flows = cache_hits = flows_in_cache = 0;
   last_ts = -1;
   print_header();
}

void StatsPlugin::post_create(FlowRecord &rec, const Packet &pkt)
{
   packets += 1;
   new_flows += 1;
   flows_in_cache += 1;
   check_timestamp(pkt);
}

void StatsPlugin::post_update(FlowRecord &rec, const Packet &pkt)
{
   packets += 1;
   cache_hits += 1;
   check_timestamp(pkt);
}

void StatsPlugin::pre_export(FlowRecord &rec)
{

   flows_in_cache -= 1;
}

void StatsPlugin::finish()
{
   print_stats(last_ts);
}

void StatsPlugin::check_timestamp(const Packet &pkt)
{
   if (last_ts == -1.0) {
      last_ts = pkt.timestamp;
      return;
   }
   if (pkt.timestamp >= last_ts + interval) {
      print_stats(last_ts);
      last_ts += interval;
      packets = new_flows = cache_hits = 0;
   }
}

void StatsPlugin::print_header() const
{
   out << "#timestamp packets hits newflows incache" << endl;
}

void StatsPlugin::print_stats(double ts) const
{
   out << fixed << setprecision(3) << ts << " ";
   out << packets << " " << cache_hits << " " << new_flows << " " << flows_in_cache << endl;
}
