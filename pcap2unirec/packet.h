#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#define MAXPCKTPAYLOADSIZE 1600

// Packet FlowFieldIndicator bit masks
#define PCKT_PACKETFIELDINDICATOR               (0x1 << 0)
#define PCKT_TIMESTAMP                          (0x1 << 1)
#define PCKT_HASH                               (0x1 << 2)
#define PCKT_KEY                                (0x1 << 3)
#define PCKT_IPVERSION                          (0x1 << 4)
#define PCKT_PROTOCOLIDENTIFIER                 (0x1 << 5)
#define PCKT_IPLENGTH                           (0x1 << 6)
#define PCKT_IPCLASSOFSERVICE                   (0x1 << 7)
#define PCKT_IPTTL                              (0x1 << 8)
#define PCKT_SOURCEIPV4ADDRESS                  (0x1 << 9)
#define PCKT_DESTINATIONIPV4ADDRESS             (0x1 << 10)
#define PCKT_SOURCEIPV6ADDRESS                  (0x1 << 11)
#define PCKT_DESTINATIONIPV6ADDRESS             (0x1 << 12)
#define PCKT_SOURCETRANSPORTPORT                (0x1 << 13)
#define PCKT_DESTINATIONTRANSPORTPORT           (0x1 << 14)
#define PCKT_TCPCONTROLBITS                     (0x1 << 15)
#define PCKT_TRANSPORTPAYLOADPACKETSECTIONSIZE  (0x1 << 16)
#define PCKT_TRANSPORTPAYLOADPACKETSECTION      (0x1 << 17)

#define PCKT_PCAP_MASK (PCKT_TIMESTAMP) // Bit 0
#define PCKT_INFO_MASK (\
   PCKT_HASH | \
   PCKT_KEY \
)

#define PCKT_IPV4_MASK (\
   PCKT_IPVERSION | \
   PCKT_PROTOCOLIDENTIFIER | \
   PCKT_IPLENGTH | \
   PCKT_IPCLASSOFSERVICE | \
   PCKT_IPTTL | \
   PCKT_SOURCEIPV4ADDRESS | \
   PCKT_DESTINATIONIPV4ADDRESS \
)

#define PCKT_IPV6_MASK (\
   PCKT_IPVERSION | \
   PCKT_PROTOCOLIDENTIFIER | \
   PCKT_IPCLASSOFSERVICE | \
   PCKT_SOURCEIPV6ADDRESS | \
   PCKT_DESTINATIONIPV6ADDRESS \
)

#define PCKT_TCP_MASK  (\
   PCKT_SOURCETRANSPORTPORT | \
   PCKT_DESTINATIONTRANSPORTPORT | \
   PCKT_TCPCONTROLBITS \
)

#define PCKT_UDP_MASK  (\
   PCKT_SOURCETRANSPORTPORT | \
   PCKT_DESTINATIONTRANSPORTPORT \
)

#define PCKT_PAYLOAD_MASK  (\
   PCKT_TRANSPORTPAYLOADPACKETSECTIONSIZE | \
   PCKT_TRANSPORTPAYLOADPACKETSECTION \
)

#define TCP_FIN    0x01
#define TCP_SYN    0x02
#define TCP_RST    0x04
#define TCP_PUSH   0x08
#define TCP_ACK    0x10
#define TCP_URG    0x20

struct Packet {
   uint64_t    packetFieldIndicator;
   double      timestamp;
   uint8_t     ipVersion;
   uint8_t     protocolIdentifier;
   uint16_t    ipLength;
   uint8_t     ipClassOfService;
   uint8_t     ipTtl;
   uint32_t    sourceIPv4Address;
   uint32_t    destinationIPv4Address;
   char        sourceIPv6Address[16];
   char        destinationIPv6Address[16];
   uint16_t    sourceTransportPort;
   uint16_t    destinationTransportPort;
   uint8_t     tcpControlBits;
   uint16_t    transportPayloadPacketSectionSize;
   char        transportPayloadPacketSection[MAXPCKTPAYLOADSIZE];
};

#endif
