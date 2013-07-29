#ifndef _FILTER_H_
#define _FILTER_H_

#ifdef STREAM_VERSION
#include "stream_version/hoststats.h"
#else
#include "timeslot_version/hoststats.h"
#endif

// Filter is not implemented yet, match() returns always true
class Filter {
public:
   Filter(const std::string &str)
   {
      // nothing
   }
   
   bool match(const hosts_record_t &rec) const
   {
      return true;
   }
};

#endif
