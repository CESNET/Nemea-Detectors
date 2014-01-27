#ifndef MAIN_H
#define MAIN_H

#include <stdint.h>
#include <string>

const unsigned int DEFAULT_FLOW_CACHE_SIZE = 8192;
const unsigned int DEFAULT_FLOW_LINE_SIZE = 32;
const double DEFAULT_INACTIVE_TIMEOUT = 5.0;
const double DEFAULT_ACTIVE_TIMEOUT = 30.0;
const uint64_t DEFAULT_PAYLOAD_LIMIT = 0;
const std::string DEFAULT_REPLACEMENT_STRING = \
   "13,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0";

struct options_t {
   bool statsout;
   bool verbose;
   uint32_t flowcachesize;
   uint32_t flowlinesize;
   uint64_t payloadlimit;
   double inactivetimeout;
   double activetimeout;
   double statstime;
   std::string infilename;
   std::string outfilename;
   std::string replacementstring;
};

void print_help();

#endif
