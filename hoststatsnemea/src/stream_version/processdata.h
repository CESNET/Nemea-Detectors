#ifndef _PROCESS_DATA_H
#define _PROCESS_DATA_H

#include <string>
#include "hoststats.h"
#include "../BloomFilter.hpp"
#include "../../../../unirec/unirec.h"

void UpdateStatsRecord(stat_map_t &stat_map, const flow_key_t &flow_key, 
                       const flow_record_t &flow_rec,
                       bloom_filter *bf_active, bloom_filter *bf_learn);

void new_trap_data(const void *record);

void *data_reader_trap(void *mutex_map); //for thread

void *data_process_trap(void *mutex_map);	//for thread


#endif
