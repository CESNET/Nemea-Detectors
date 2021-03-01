#ifndef _UR_FIELDS_H_
#define _UR_FIELDS_H_

/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
#include <unirec/unirec.h>

#define F_DST_IP   0
#define F_DST_IP_T   ip_addr_t
#define F_SBFD_SOURCE   1
#define F_SBFD_SOURCE_T   ip_addr_t
#define F_SBFD_TARGET   2
#define F_SBFD_TARGET_T   ip_addr_t
#define F_SRC_IP   3
#define F_SRC_IP_T   ip_addr_t
#define F_LINK_BIT_FIELD   4
#define F_LINK_BIT_FIELD_T   uint64_t
#define F_SBFD_BREACH_TIME   5
#define F_SBFD_BREACH_TIME_T   ur_time_t
#define F_SBFD_CEASE_TIME   6
#define F_SBFD_CEASE_TIME_T   ur_time_t
#define F_SBFD_EVENT_ID   7
#define F_SBFD_EVENT_ID_T   uint64_t
#define F_SBFD_EVENT_TIME   8
#define F_SBFD_EVENT_TIME_T   ur_time_t
#define F_SBFD_LINK_BIT_FIELD   9
#define F_SBFD_LINK_BIT_FIELD_T   uint64_t
#define F_TIME_FIRST   10
#define F_TIME_FIRST_T   ur_time_t
#define F_SBFD_ATTEMPTS   11
#define F_SBFD_ATTEMPTS_T   uint32_t
#define F_SBFD_AVG_ATTEMPTS   12
#define F_SBFD_AVG_ATTEMPTS_T   uint32_t
#define F_DST_PORT   13
#define F_DST_PORT_T   uint16_t
#define F_SIP_MSG_TYPE   14
#define F_SIP_MSG_TYPE_T   uint16_t
#define F_SIP_STATUS_CODE   15
#define F_SIP_STATUS_CODE_T   uint16_t
#define F_SRC_PORT   16
#define F_SRC_PORT_T   uint16_t
#define F_PROTOCOL   17
#define F_PROTOCOL_T   uint8_t
#define F_SBFD_EVENT_TYPE   18
#define F_SBFD_EVENT_TYPE_T   uint8_t
#define F_SBFD_PROTOCOL   19
#define F_SBFD_PROTOCOL_T   uint8_t
#define F_SBFD_USER   20
#define F_SBFD_USER_T   char
#define F_SIP_CALLING_PARTY   21
#define F_SIP_CALLING_PARTY_T   char
#define F_SIP_CSEQ   22
#define F_SIP_CSEQ_T   char

extern uint16_t ur_last_id;
extern ur_static_field_specs_t UR_FIELD_SPECS_STATIC;
extern ur_field_specs_t ur_field_specs;

#endif

