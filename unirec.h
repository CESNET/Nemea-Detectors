#ifndef _UNIREC_H_
#define _UNIREC_H_

#include <stdint.h>

// Generic IP address (IPv4 or IPv6)
// In case of IPv4, address is stored in ad[0] and ad[1-3] = 0
typedef struct ip_addr_s {
   uint32_t ad[4];
} ip_addr_t;

// Basic flow record
struct ur_basic_flow_s {
   ip_addr_t src_addr;
   ip_addr_t dst_addr;
   uint64_t packets;
   uint64_t bytes;
   uint32_t first;
   uint32_t last;
   uint16_t msec_first;
   uint16_t msec_last;
   uint16_t src_port;
   uint16_t dst_port;
   uint8_t proto;
   uint8_t tcp_flags;
} __attribute__((packed));
typedef struct ur_basic_flow_s ur_basic_flow_t;

#endif
