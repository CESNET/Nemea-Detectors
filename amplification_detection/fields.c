/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
// Tables are indexed by field ID
#include "fields.h"

char *ur_field_names_static[] = {
   "DST_IP",
   "SRC_IP",
   "BYTES",
   "REQ_BYTES",
   "RSP_BYTES",
   "TIME_FIRST",
   "TIME_LAST",
   "EVENT_ID",
   "PACKETS",
   "REQ_FLOWS",
   "REQ_PACKETS",
   "RSP_FLOWS",
   "RSP_PACKETS",
   "DST_PORT",
   "SRC_PORT",
   "PROTOCOL",
};
short ur_field_sizes_static[] = {
   16, /* DST_IP */
   16, /* SRC_IP */
   8, /* BYTES */
   8, /* REQ_BYTES */
   8, /* RSP_BYTES */
   8, /* TIME_FIRST */
   8, /* TIME_LAST */
   4, /* EVENT_ID */
   4, /* PACKETS */
   4, /* REQ_FLOWS */
   4, /* REQ_PACKETS */
   4, /* RSP_FLOWS */
   4, /* RSP_PACKETS */
   2, /* DST_PORT */
   2, /* SRC_PORT */
   1, /* PROTOCOL */
};
ur_field_type_t ur_field_types_static[] = {
   UR_TYPE_IP, /* DST_IP */
   UR_TYPE_IP, /* SRC_IP */
   UR_TYPE_UINT64, /* BYTES */
   UR_TYPE_UINT64, /* REQ_BYTES */
   UR_TYPE_UINT64, /* RSP_BYTES */
   UR_TYPE_TIME, /* TIME_FIRST */
   UR_TYPE_TIME, /* TIME_LAST */
   UR_TYPE_UINT32, /* EVENT_ID */
   UR_TYPE_UINT32, /* PACKETS */
   UR_TYPE_UINT32, /* REQ_FLOWS */
   UR_TYPE_UINT32, /* REQ_PACKETS */
   UR_TYPE_UINT32, /* RSP_FLOWS */
   UR_TYPE_UINT32, /* RSP_PACKETS */
   UR_TYPE_UINT16, /* DST_PORT */
   UR_TYPE_UINT16, /* SRC_PORT */
   UR_TYPE_UINT8, /* PROTOCOL */
};
ur_static_field_specs_t UR_FIELD_SPECS_STATIC = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 16};
ur_field_specs_t ur_field_specs = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 16, 16, 16, NULL, UR_UNINITIALIZED};
