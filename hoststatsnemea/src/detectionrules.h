#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#include "hoststats.h"

const std::string get_rec_time(const hosts_record_t &rec); 

void check_rules(const hosts_key_t &addr, const hosts_record_t &rec);

void check_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec);

#endif
