#ifndef _UR_FIELDS_H_
#define _UR_FIELDS_H_

/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
#include <unirec/unirec.h>

#define F_DST_IP   0
#define F_DST_IP_T   ip_addr_t
#define F_SRC_IP   1
#define F_SRC_IP_T   ip_addr_t
#define F_AVG_BYTES_CURRENT   2
#define F_AVG_BYTES_CURRENT_T   uint64_t
#define F_AVG_BYTES_ORIGINAL   3
#define F_AVG_BYTES_ORIGINAL_T   uint64_t
#define F_BYTES   4
#define F_BYTES_T   uint64_t
#define F_EVENT_ID   5
#define F_EVENT_ID_T   uint64_t
#define F_TIME_FIRST   6
#define F_TIME_FIRST_T   ur_time_t
#define F_TIME_LAST   7
#define F_TIME_LAST_T   ur_time_t
#define F_AVG_IP_CNT_CURRENT   8
#define F_AVG_IP_CNT_CURRENT_T   uint32_t
#define F_AVG_IP_CNT_ORIGINAL   9
#define F_AVG_IP_CNT_ORIGINAL_T   uint32_t
#define F_EVENT_SEQ   10
#define F_EVENT_SEQ_T   uint16_t

extern uint16_t ur_last_id;
extern ur_static_field_specs_t UR_FIELD_SPECS_STATIC;
extern ur_field_specs_t ur_field_specs;

#endif

