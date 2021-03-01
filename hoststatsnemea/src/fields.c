/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
// Tables are indexed by field ID
#include "fields.h"

char *ur_field_names_static[] = {
   "DST_IP",
   "SRC_IP",
   "BYTES",
   "LINK_BIT_FIELD",
   "TIME_FIRST",
   "TIME_LAST",
   "EVENT_SCALE",
   "PACKETS",
   "DST_PORT",
   "SRC_PORT",
   "DIR_BIT_FIELD",
   "DIRECTION_FLAGS",
   "EVENT_TYPE",
   "PROTOCOL",
   "TCP_FLAGS",
   "NOTE",
};
short ur_field_sizes_static[] = {
   16, /* DST_IP */
   16, /* SRC_IP */
   8, /* BYTES */
   8, /* LINK_BIT_FIELD */
   8, /* TIME_FIRST */
   8, /* TIME_LAST */
   4, /* EVENT_SCALE */
   4, /* PACKETS */
   2, /* DST_PORT */
   2, /* SRC_PORT */
   1, /* DIR_BIT_FIELD */
   1, /* DIRECTION_FLAGS */
   1, /* EVENT_TYPE */
   1, /* PROTOCOL */
   1, /* TCP_FLAGS */
   -1, /* NOTE */
};
ur_field_type_t ur_field_types_static[] = {
   UR_TYPE_IP, /* DST_IP */
   UR_TYPE_IP, /* SRC_IP */
   UR_TYPE_UINT64, /* BYTES */
   UR_TYPE_UINT64, /* LINK_BIT_FIELD */
   UR_TYPE_TIME, /* TIME_FIRST */
   UR_TYPE_TIME, /* TIME_LAST */
   UR_TYPE_UINT32, /* EVENT_SCALE */
   UR_TYPE_UINT32, /* PACKETS */
   UR_TYPE_UINT16, /* DST_PORT */
   UR_TYPE_UINT16, /* SRC_PORT */
   UR_TYPE_UINT8, /* DIR_BIT_FIELD */
   UR_TYPE_UINT8, /* DIRECTION_FLAGS */
   UR_TYPE_UINT8, /* EVENT_TYPE */
   UR_TYPE_UINT8, /* PROTOCOL */
   UR_TYPE_UINT8, /* TCP_FLAGS */
   UR_TYPE_STRING, /* NOTE */
};
ur_static_field_specs_t UR_FIELD_SPECS_STATIC = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 16};
ur_field_specs_t ur_field_specs = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 16, 16, 16, NULL, UR_UNINITIALIZED};
