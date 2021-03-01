/************* THIS IS AUTOMATICALLY GENERATED FILE, DO NOT EDIT *************/
// Tables are indexed by field ID
#include "fields.h"

char *ur_field_names_static[] = {
   "DST_IP",
   "SBFD_SOURCE",
   "SBFD_TARGET",
   "SRC_IP",
   "LINK_BIT_FIELD",
   "SBFD_BREACH_TIME",
   "SBFD_CEASE_TIME",
   "SBFD_EVENT_ID",
   "SBFD_EVENT_TIME",
   "SBFD_LINK_BIT_FIELD",
   "TIME_FIRST",
   "SBFD_ATTEMPTS",
   "SBFD_AVG_ATTEMPTS",
   "DST_PORT",
   "SIP_MSG_TYPE",
   "SIP_STATUS_CODE",
   "SRC_PORT",
   "PROTOCOL",
   "SBFD_EVENT_TYPE",
   "SBFD_PROTOCOL",
   "SBFD_USER",
   "SIP_CALLING_PARTY",
   "SIP_CSEQ",
};
short ur_field_sizes_static[] = {
   16, /* DST_IP */
   16, /* SBFD_SOURCE */
   16, /* SBFD_TARGET */
   16, /* SRC_IP */
   8, /* LINK_BIT_FIELD */
   8, /* SBFD_BREACH_TIME */
   8, /* SBFD_CEASE_TIME */
   8, /* SBFD_EVENT_ID */
   8, /* SBFD_EVENT_TIME */
   8, /* SBFD_LINK_BIT_FIELD */
   8, /* TIME_FIRST */
   4, /* SBFD_ATTEMPTS */
   4, /* SBFD_AVG_ATTEMPTS */
   2, /* DST_PORT */
   2, /* SIP_MSG_TYPE */
   2, /* SIP_STATUS_CODE */
   2, /* SRC_PORT */
   1, /* PROTOCOL */
   1, /* SBFD_EVENT_TYPE */
   1, /* SBFD_PROTOCOL */
   -1, /* SBFD_USER */
   -1, /* SIP_CALLING_PARTY */
   -1, /* SIP_CSEQ */
};
ur_field_type_t ur_field_types_static[] = {
   UR_TYPE_IP, /* DST_IP */
   UR_TYPE_IP, /* SBFD_SOURCE */
   UR_TYPE_IP, /* SBFD_TARGET */
   UR_TYPE_IP, /* SRC_IP */
   UR_TYPE_UINT64, /* LINK_BIT_FIELD */
   UR_TYPE_TIME, /* SBFD_BREACH_TIME */
   UR_TYPE_TIME, /* SBFD_CEASE_TIME */
   UR_TYPE_UINT64, /* SBFD_EVENT_ID */
   UR_TYPE_TIME, /* SBFD_EVENT_TIME */
   UR_TYPE_UINT64, /* SBFD_LINK_BIT_FIELD */
   UR_TYPE_TIME, /* TIME_FIRST */
   UR_TYPE_UINT32, /* SBFD_ATTEMPTS */
   UR_TYPE_UINT32, /* SBFD_AVG_ATTEMPTS */
   UR_TYPE_UINT16, /* DST_PORT */
   UR_TYPE_UINT16, /* SIP_MSG_TYPE */
   UR_TYPE_UINT16, /* SIP_STATUS_CODE */
   UR_TYPE_UINT16, /* SRC_PORT */
   UR_TYPE_UINT8, /* PROTOCOL */
   UR_TYPE_UINT8, /* SBFD_EVENT_TYPE */
   UR_TYPE_UINT8, /* SBFD_PROTOCOL */
   UR_TYPE_STRING, /* SBFD_USER */
   UR_TYPE_STRING, /* SIP_CALLING_PARTY */
   UR_TYPE_STRING, /* SIP_CSEQ */
};
ur_static_field_specs_t UR_FIELD_SPECS_STATIC = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 23};
ur_field_specs_t ur_field_specs = {ur_field_names_static, ur_field_sizes_static, ur_field_types_static, 23, 23, 23, NULL, UR_UNINITIALIZED};
