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
#define F_TIME_FIRST   3
#define F_TIME_FIRST_T   ur_time_t
#define F_TIME_LAST   4
#define F_TIME_LAST_T   ur_time_t
#define F_EVENT_ID   5
#define F_EVENT_ID_T   uint32_t
#define F_PACKETS   6
#define F_PACKETS_T   uint32_t
#define F_TIMEOUT   7
#define F_TIMEOUT_T   uint32_t
#define F_TUNNEL_CNT_PACKET   8
#define F_TUNNEL_CNT_PACKET_T   uint32_t
#define F_TUNNEL_PER_NEW_DOMAIN   9
#define F_TUNNEL_PER_NEW_DOMAIN_T   float
#define F_TUNNEL_PER_SUBDOMAIN   10
#define F_TUNNEL_PER_SUBDOMAIN_T   float
#define F_DNS_QTYPE   11
#define F_DNS_QTYPE_T   uint16_t
#define F_DST_PORT   12
#define F_DST_PORT_T   uint16_t
#define F_TUNNEL_TYPE   13
#define F_TUNNEL_TYPE_T   uint8_t
#define F_DNS_NAME   14
#define F_DNS_NAME_T   char
#define F_DNS_RDATA   15
#define F_DNS_RDATA_T   char
#define F_SDM_CAPTURE_FILE_ID   16
#define F_SDM_CAPTURE_FILE_ID_T   char
#define F_TUNNEL_DOMAIN   17
#define F_TUNNEL_DOMAIN_T   char

extern uint16_t ur_last_id;
extern ur_static_field_specs_t UR_FIELD_SPECS_STATIC;
extern ur_field_specs_t ur_field_specs;

#endif

