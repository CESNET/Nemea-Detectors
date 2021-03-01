#ifndef _UR_FIELDS_H_
#define _UR_FIELDS_H_

/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
#include <unirec/unirec.h>

#define F_DST_IP   0
#define F_DST_IP_T   ip_addr_t
#define F_SRC_IP   1
#define F_SRC_IP_T   ip_addr_t
#define F_CALLEE_CNT   2
#define F_CALLEE_CNT_T   uint64_t
#define F_CALLER_CNT   3
#define F_CALLER_CNT_T   uint64_t
#define F_DETECTION_TIME   4
#define F_DETECTION_TIME_T   ur_time_t
#define F_INVITE_CNT   5
#define F_INVITE_CNT_T   uint64_t
#define F_LINK_BIT_FIELD   6
#define F_LINK_BIT_FIELD_T   uint64_t
#define F_TIME_FIRST   7
#define F_TIME_FIRST_T   ur_time_t
#define F_EVENT_ID   8
#define F_EVENT_ID_T   uint32_t
#define F_VOIP_FRAUD_INVITE_COUNT   9
#define F_VOIP_FRAUD_INVITE_COUNT_T   uint32_t
#define F_VOIP_FRAUD_PREFIX_EXAMINATION_COUNT   10
#define F_VOIP_FRAUD_PREFIX_EXAMINATION_COUNT_T   uint32_t
#define F_VOIP_FRAUD_SUCCESSFUL_CALL_COUNT   11
#define F_VOIP_FRAUD_SUCCESSFUL_CALL_COUNT_T   uint32_t
#define F_SIP_MSG_TYPE   12
#define F_SIP_MSG_TYPE_T   uint16_t
#define F_SIP_STATUS_CODE   13
#define F_SIP_STATUS_CODE_T   uint16_t
#define F_VOIP_FRAUD_PREFIX_LENGTH   14
#define F_VOIP_FRAUD_PREFIX_LENGTH_T   uint16_t
#define F_EVENT_TYPE   15
#define F_EVENT_TYPE_T   uint8_t
#define F_SIP_CALLED_PARTY   16
#define F_SIP_CALLED_PARTY_T   char
#define F_SIP_CALL_ID   17
#define F_SIP_CALL_ID_T   char
#define F_SIP_CALLING_PARTY   18
#define F_SIP_CALLING_PARTY_T   char
#define F_SIP_CSEQ   19
#define F_SIP_CSEQ_T   char
#define F_SIP_REQUEST_URI   20
#define F_SIP_REQUEST_URI_T   char
#define F_SIP_USER_AGENT   21
#define F_SIP_USER_AGENT_T   char
#define F_VOIP_FRAUD_COUNTRY_CODE   22
#define F_VOIP_FRAUD_COUNTRY_CODE_T   char
#define F_VOIP_FRAUD_SIP_FROM   23
#define F_VOIP_FRAUD_SIP_FROM_T   char
#define F_VOIP_FRAUD_SIP_TO   24
#define F_VOIP_FRAUD_SIP_TO_T   char
#define F_VOIP_FRAUD_USER_AGENT   25
#define F_VOIP_FRAUD_USER_AGENT_T   char

extern uint16_t ur_last_id;
extern ur_static_field_specs_t UR_FIELD_SPECS_STATIC;
extern ur_field_specs_t ur_field_specs;

#endif

