/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
// Tables are indexed by field ID
#include "fields.h"

char *ur_field_names_static[] = {
   "DST_IP",
   "SRC_IP",
   "AVG_BYTES_CURRENT",
   "AVG_BYTES_ORIGINAL",
   "BYTES",
   "EVENT_ID",
   "TIME_FIRST",
   "TIME_LAST",
   "AVG_IP_CNT_CURRENT",
   "AVG_IP_CNT_ORIGINAL",
   "EVENT_SEQ",
};
short ur_field_sizes_static[] = {
   16, /* DST_IP */
   16, /* SRC_IP */
   8, /* AVG_BYTES_CURRENT */
   8, /* AVG_BYTES_ORIGINAL */
   8, /* BYTES */
   8, /* EVENT_ID */
   8, /* TIME_FIRST */
   8, /* TIME_LAST */
   4, /* AVG_IP_CNT_CURRENT */
   4, /* AVG_IP_CNT_ORIGINAL */
   2, /* EVENT_SEQ */
};
ur_field_type_t ur_field_types_static[] = {
   UR_TYPE_IP, /* DST_IP */
   UR_TYPE_IP, /* SRC_IP */
   UR_TYPE_UINT64, /* AVG_BYTES_CURRENT */
   UR_TYPE_UINT64, /* AVG_BYTES_ORIGINAL */
   UR_TYPE_UINT64, /* BYTES */
   UR_TYPE_UINT64, /* EVENT_ID */
   UR_TYPE_TIME, /* TIME_FIRST */
   UR_TYPE_TIME, /* TIME_LAST */
   UR_TYPE_UINT32, /* AVG_IP_CNT_CURRENT */
   UR_TYPE_UINT32, /* AVG_IP_CNT_ORIGINAL */
   UR_TYPE_UINT16, /* EVENT_SEQ */
};
ur_static_field_specs_t UR_FIELD_SPECS_STATIC = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 11};
ur_field_specs_t ur_field_specs = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 11, 11, 11, NULL, UR_UNINITIALIZED};
