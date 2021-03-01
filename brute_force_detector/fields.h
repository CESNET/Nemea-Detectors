#ifndef _UR_FIELDS_H_
#define _UR_FIELDS_H_

/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
#include <unirec/unirec.h>

#define F_DST_IP   0
#define F_DST_IP_T   ip_addr_t
#define F_SRC_IP   1
#define F_SRC_IP_T   ip_addr_t
#define F_BYTES   2
#define F_BYTES_T   uint64_t
#define F_DETECTION_TIME   3
#define F_DETECTION_TIME_T   ur_time_t
#define F_TIME_FIRST   4
#define F_TIME_FIRST_T   ur_time_t
#define F_TIME_LAST   5
#define F_TIME_LAST_T   ur_time_t
#define F_EVENT_SCALE   6
#define F_EVENT_SCALE_T   uint32_t
#define F_PACKETS   7
#define F_PACKETS_T   uint32_t
#define F_DST_PORT   8
#define F_DST_PORT_T   uint16_t
#define F_SRC_PORT   9
#define F_SRC_PORT_T   uint16_t
#define F_PROTOCOL   10
#define F_PROTOCOL_T   uint8_t
#define F_TCP_FLAGS   11
#define F_TCP_FLAGS_T   uint8_t
#define F_WARDEN_TYPE   12
#define F_WARDEN_TYPE_T   uint8_t
#define F_NOTE   13
#define F_NOTE_T   char

extern uint16_t ur_last_id;
extern ur_static_field_specs_t UR_FIELD_SPECS_STATIC;
extern ur_field_specs_t ur_field_specs;

#endif

