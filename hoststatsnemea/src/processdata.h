#ifndef _PROCESS_DATA_H
#define _PROCESS_DATA_H

#include <string>
#include <unistd.h>
#include "hoststats.h"
#include "config.h" 
#include "profile.h"


void check_time(uint32_t &next_ts_start, uint32_t &next_bf_change, 
                const uint32_t &current_time);

bool record_validity(HostProfile &profile, int index, thread_share_t *share);

void *data_reader_trap(void *mutex_map); //for thread

void *data_process_trap(void *mutex_map); //for thread


#endif
