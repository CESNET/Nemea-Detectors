#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#ifdef STREAM_VERSION
#include "stream_version/hoststats.h"
#include "stream_version/profile.h"
#else
#include "timeslot_version/hoststats.h"
#include "timeslot_version/profile.h"
#endif

#ifndef STREAM_VERSION
void check_rules(const Profile* profile);
#endif

void check_rules(const hosts_key_t &addr, const hosts_record_t &rec, const std::string &timeslot);

#ifndef STREAM_VERSION
void check_rules_ssh(const Profile* profile);
#endif

void check_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec, const std::string &timeslot);

#endif
