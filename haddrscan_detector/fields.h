#ifndef _UR_FIELDS_H_
#define _UR_FIELDS_H_

/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
#include <unirec/unirec.h>

#define F_DST_IP0   0
#define F_DST_IP0_T   ip_addr_t
#define F_DST_IP1   1
#define F_DST_IP1_T   ip_addr_t
#define F_DST_IP   2
#define F_DST_IP_T   ip_addr_t
#define F_DST_IP2   3
#define F_DST_IP2_T   ip_addr_t
#define F_DST_IP3   4
#define F_DST_IP3_T   ip_addr_t
#define F_SRC_IP   5
#define F_SRC_IP_T   ip_addr_t
#define F_TIME_FIRST   6
#define F_TIME_FIRST_T   ur_time_t
#define F_TIME_LAST   7
#define F_TIME_LAST_T   ur_time_t
#define F_ADDR_CNT   8
#define F_ADDR_CNT_T   uint32_t
#define F_ADDR_THRSD   9
#define F_ADDR_THRSD_T   uint32_t
#define F_PACKETS   10
#define F_PACKETS_T   uint32_t
#define F_DST_PORT   11
#define F_DST_PORT_T   uint16_t
#define F_SRC_PORT   12
#define F_SRC_PORT_T   uint16_t
#define F_EVENT_TYPE   13
#define F_EVENT_TYPE_T   uint8_t
#define F_PROTOCOL   14
#define F_PROTOCOL_T   uint8_t
#define F_TCP_FLAGS   15
#define F_TCP_FLAGS_T   uint8_t

extern uint16_t ur_last_id;
extern ur_static_field_specs_t UR_FIELD_SPECS_STATIC;
extern ur_field_specs_t ur_field_specs;

#endif

