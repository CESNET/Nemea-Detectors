#ifndef FLOWCACHE_H
#define FLOWCACHE_H

#include "packet.h"
#include "flowifc.h"
#include "flowcacheplugin.h"

#include <vector>
#include <cstring>

class FlowCache
{
protected:
   FlowExporter *exporter; // Instance of FlowExporter used to export flows
private:
   std::vector<FlowCachePlugin*> plugins; // Array of plugins

public:
   // Put packet into the cache (i.e. update corresponding flow record or create a new one)
   virtual int put_pkt(Packet &pkt) = 0;

   // Should be called before first call of recv_pkt, after all plugins are added
   virtual void init() {
      plugins_init();
   }

   // Should be called after last call of recv_pkt
   virtual void finish() {
      plugins_finish();
   }

   // Set an instance of FlowExporter used to export flows
   void set_exporter(FlowExporter *exp) {
      exporter = exp;
   }

   // Add plugin to internal list of plugins (plugins are always called in the
   // same order, as they were added)
   void add_plugin(FlowCachePlugin* plugin) {
      plugins.push_back(plugin);
   }

protected:
   // Every FlowCache implementation should call these functions at appropriate places
   void plugins_init() {
      for (unsigned int i = 0; i < plugins.size(); i++)
         plugins[i]->init();
   }
   void plugins_post_create(FlowRecord &rec, const Packet &pkt) {
      for (unsigned int i = 0; i < plugins.size(); i++)
         plugins[i]->post_create(rec, pkt);
   }
   void plugins_pre_update(FlowRecord &rec, Packet &pkt) {
      for (unsigned int i = 0; i < plugins.size(); i++)
         plugins[i]->pre_update(rec, pkt);
   }
   void plugins_post_update(FlowRecord &rec, const Packet &pkt) {
      for (unsigned int i = 0; i < plugins.size(); i++)
         plugins[i]->post_update(rec, pkt);
   }
   void plugins_pre_export(FlowRecord &rec) {
      for (unsigned int i = 0; i < plugins.size(); i++)
         plugins[i]->pre_export(rec);
   }
   void plugins_finish() {
      for (unsigned int i = 0; i < plugins.size(); i++)
         plugins[i]->finish();
   }
};

#endif
