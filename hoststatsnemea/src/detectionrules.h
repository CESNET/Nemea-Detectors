#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#include "hoststats.h"
#include "profile.h"

void check_rules(const Profile *profile);
void check_rules_ssh(const Profile* profile);

#endif
