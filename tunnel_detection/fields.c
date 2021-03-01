/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
// Tables are indexed by field ID
#include "fields.h"

char *ur_field_names_static[] = {
   "DST_IP",
   "SRC_IP",
   "BYTES",
   "TIME_FIRST",
   "TIME_LAST",
   "EVENT_ID",
   "PACKETS",
   "TIMEOUT",
   "TUNNEL_CNT_PACKET",
   "TUNNEL_PER_NEW_DOMAIN",
   "TUNNEL_PER_SUBDOMAIN",
   "DNS_QTYPE",
   "DST_PORT",
   "TUNNEL_TYPE",
   "DNS_NAME",
   "DNS_RDATA",
   "SDM_CAPTURE_FILE_ID",
   "TUNNEL_DOMAIN",
};
short ur_field_sizes_static[] = {
   16, /* DST_IP */
   16, /* SRC_IP */
   8, /* BYTES */
   8, /* TIME_FIRST */
   8, /* TIME_LAST */
   4, /* EVENT_ID */
   4, /* PACKETS */
   4, /* TIMEOUT */
   4, /* TUNNEL_CNT_PACKET */
   4, /* TUNNEL_PER_NEW_DOMAIN */
   4, /* TUNNEL_PER_SUBDOMAIN */
   2, /* DNS_QTYPE */
   2, /* DST_PORT */
   1, /* TUNNEL_TYPE */
   -1, /* DNS_NAME */
   -1, /* DNS_RDATA */
   -1, /* SDM_CAPTURE_FILE_ID */
   -1, /* TUNNEL_DOMAIN */
};
ur_field_type_t ur_field_types_static[] = {
   UR_TYPE_IP, /* DST_IP */
   UR_TYPE_IP, /* SRC_IP */
   UR_TYPE_UINT64, /* BYTES */
   UR_TYPE_TIME, /* TIME_FIRST */
   UR_TYPE_TIME, /* TIME_LAST */
   UR_TYPE_UINT32, /* EVENT_ID */
   UR_TYPE_UINT32, /* PACKETS */
   UR_TYPE_UINT32, /* TIMEOUT */
   UR_TYPE_UINT32, /* TUNNEL_CNT_PACKET */
   UR_TYPE_FLOAT, /* TUNNEL_PER_NEW_DOMAIN */
   UR_TYPE_FLOAT, /* TUNNEL_PER_SUBDOMAIN */
   UR_TYPE_UINT16, /* DNS_QTYPE */
   UR_TYPE_UINT16, /* DST_PORT */
   UR_TYPE_UINT8, /* TUNNEL_TYPE */
   UR_TYPE_STRING, /* DNS_NAME */
   UR_TYPE_BYTES, /* DNS_RDATA */
   UR_TYPE_STRING, /* SDM_CAPTURE_FILE_ID */
   UR_TYPE_STRING, /* TUNNEL_DOMAIN */
};
ur_static_field_specs_t UR_FIELD_SPECS_STATIC = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 18};
ur_field_specs_t ur_field_specs = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 18, 18, 18, NULL, UR_UNINITIALIZED};
