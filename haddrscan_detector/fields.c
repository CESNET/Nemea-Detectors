/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
// Tables are indexed by field ID
#include "fields.h"

char *ur_field_names_static[] = {
   "DST_IP0",
   "DST_IP1",
   "DST_IP",
   "DST_IP2",
   "DST_IP3",
   "SRC_IP",
   "TIME_FIRST",
   "TIME_LAST",
   "ADDR_CNT",
   "ADDR_THRSD",
   "PACKETS",
   "DST_PORT",
   "SRC_PORT",
   "EVENT_TYPE",
   "PROTOCOL",
   "TCP_FLAGS",
};
short ur_field_sizes_static[] = {
   16, /* DST_IP0 */
   16, /* DST_IP1 */
   16, /* DST_IP */
   16, /* DST_IP2 */
   16, /* DST_IP3 */
   16, /* SRC_IP */
   8, /* TIME_FIRST */
   8, /* TIME_LAST */
   4, /* ADDR_CNT */
   4, /* ADDR_THRSD */
   4, /* PACKETS */
   2, /* DST_PORT */
   2, /* SRC_PORT */
   1, /* EVENT_TYPE */
   1, /* PROTOCOL */
   1, /* TCP_FLAGS */
};
ur_field_type_t ur_field_types_static[] = {
   UR_TYPE_IP, /* DST_IP0 */
   UR_TYPE_IP, /* DST_IP1 */
   UR_TYPE_IP, /* DST_IP */
   UR_TYPE_IP, /* DST_IP2 */
   UR_TYPE_IP, /* DST_IP3 */
   UR_TYPE_IP, /* SRC_IP */
   UR_TYPE_TIME, /* TIME_FIRST */
   UR_TYPE_TIME, /* TIME_LAST */
   UR_TYPE_UINT32, /* ADDR_CNT */
   UR_TYPE_UINT32, /* ADDR_THRSD */
   UR_TYPE_UINT32, /* PACKETS */
   UR_TYPE_UINT16, /* DST_PORT */
   UR_TYPE_UINT16, /* SRC_PORT */
   UR_TYPE_UINT8, /* EVENT_TYPE */
   UR_TYPE_UINT8, /* PROTOCOL */
   UR_TYPE_UINT8, /* TCP_FLAGS */
};
ur_static_field_specs_t UR_FIELD_SPECS_STATIC = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 16};
ur_field_specs_t ur_field_specs = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 16, 16, 16, NULL, UR_UNINITIALIZED};
