#ifndef PCAPREADER_H
#define PCAPREADER_H

#include "pcap2unirec.h"
#include "packet.h"
#include "packetreceiver.h"

// http://standards.ieee.org/develop/regauth/ethertype/eth.txt
#define ETHER_TYPE_IPv4 0x0800
#define ETHER_TYPE_IPv6 0x86DD
#define ETHER_TYPE_8021Q 0x8100

// http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
#define IP_PROTO_ICMP 1
#define IP_PROTO_ICMPv6 58
#define IP_PROTO_TCP 6
#define IP_PROTO_UDP 17

// Header of pcap file
struct pcap_hdr_t {
   uint32_t magic_number;   // magic number
   uint16_t version_major;  // major version number
   uint16_t version_minor;  // minor version number
   int32_t  thiszone;       // GMT to local correction
   uint32_t sigfigs;        // accuracy of timestamps
   uint32_t snaplen;        // max length of captured packets, in octets
   uint32_t network;        // data link type
};

// Header of packet record
struct pcap_rec_hdr_t {
   uint32_t ts_sec;         // timestamp seconds
   uint32_t ts_usec;        // timestamp microseconds
   uint32_t incl_len;       // number of octets of packet saved in file
   uint32_t orig_len;       // actual length of packet
};

// IPv4 header
struct ipv4hdr {
   uint8_t  ver_hdrlen; // version in higher 4 bits, header length in lower 4b
   uint8_t  tos;
   uint16_t tot_len;
   uint16_t id;
   uint16_t frag_off;
   uint8_t  ttl;
   uint8_t  protocol;
   uint16_t check;
   uint32_t saddr;
   uint32_t daddr;
   /*The options start here. */
};

// IPv6 header
struct ipv6hdr {
   uint32_t v6nfo;
   // Lowest 4 bits -- Version = 6
   // Middle 8 bits -- Traffic Class (6MSb -- DSCP, 2LSb -- ECN)
   // Highest 20 bits -- Flow label
   uint16_t payload_len;
   uint8_t next_hdr;
   uint8_t hop_limit;
   char saddr[16];
   char daddr[16];
   /* Options follows */
};

// TCP header
struct tcphdr {
   uint16_t source;
   uint16_t dest;
   uint32_t seq;
   uint32_t ack;
   uint8_t  doff; //data offset (in higher 4 bits)
   uint8_t  flags;
   uint16_t win;
   uint16_t checksum;
   uint16_t urgptr;
};

// UDP header
struct udphdr {
   uint16_t source;
   uint16_t dest;
   uint16_t len;
   uint16_t checksum;
};

class PcapReader : public PacketReceiver
{
public:
   unsigned int cnt_parsed, cnt_total;
   bool opened, verbose;

   PcapReader(options_t options) {
      this->cnt_parsed = 0;
      this->cnt_total = 0;
      this->opened = false;
      this->verbose = options.verbose;
   }

   int open(const std::string &filename);
   int close();
   int get_pkt(Packet &packet);

protected:
   FILE *file;
   unsigned int data_buffer_size;
   char *data_buffer;

   int parse_packet(const pcap_rec_hdr_t &hdr, const char *data, Packet &p);
};

#endif
