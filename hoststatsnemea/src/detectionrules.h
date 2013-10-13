#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#ifdef STREAM_VERSION
#include "stream_version/hoststats.h"
#else
#include "timeslot_version/hoststats.h"
#endif

const std::string get_rec_time(const hosts_record_t &rec); 

void check_rules(const hosts_key_t &addr, const hosts_record_t &rec);

void check_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec);

#endif
