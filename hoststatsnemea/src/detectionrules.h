#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#ifdef STREAM_VERSION
#include "stream_version/hoststats.h"
#include "stream_version/profile.h"
#else
#include "timeslot_version/hoststats.h"
#include "timeslot_version/profile.h"
#endif

void check_rules(Profile *profile);
void check_rules_ssh(Profile* profile);

#endif
