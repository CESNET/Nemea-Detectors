#ifndef _PROCESS_DATA_H
#define _PROCESS_DATA_H

#include <string>
#include "hoststats.h"
#include "../BloomFilter.hpp"
#include "../../../../unirec/unirec.h"

/*
void load_flows(std::vector<std::string> source_filenames,
                std::vector<int> source_priorities,
                flow_map_t &flow_map);
*/
void UpdateStatsRecord(stat_map_t &stat_map, const flow_key_t &flow_key, 
                       const flow_record_t &flow_rec, bloom_filter &bf);

//int compute_host_stats(const flow_map_t &flow_map, flow_filter_func_ptr filter, stat_map_t &stat_map);
/*
void process_data(const std::string& timestamp);
*/

void swap_all_stat_maps(const uint32_t timeslot);

void *data_reader_trap(void *mutex_map); //for thread

void *data_process_trap(void *mutex_map);	//for thread

void new_trap_data(const void *record);

#endif
