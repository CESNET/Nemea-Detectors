#include "pcapreader.h"
#include <cstdio>
#include <cstring>

//inet_ntop

using namespace std;

// definition of ntohs and ntohl functions
// (not using netinet/in.h to allow translation on windows)
#if __BYTE_ORDER == __BIG_ENDIAN
   #define ntohs(x) (x)
   #define ntohl(x) (x)
#else
   inline uint16_t ntohs(uint16_t x)
   {
      return ((x & 0x00ff) << 8) |
             ((x & 0xff00) >> 8);
   }
   inline uint32_t ntohl(uint32_t x)
   {
      return ((x & 0x000000ff) << 24) |
             ((x & 0x0000ff00) <<  8) |
             ((x & 0x00ff0000) >>  8) |
             ((x & 0xff000000) >> 24);
   }
#endif

inline void swapbytes128(char *x)
{
   char tmp;
   for (int i = 0; i < 8; i++) {
      tmp = x[i];
      x[i] = x[15-i];
      x[15-i] = tmp;
   }
}

// Open given pcap file
int PcapReader::open(const string &filename)
{
   pcap_hdr_t hdr;

   file = fopen(filename.c_str(), "rb");
   if (file == NULL) {
      errmsg = "Can't open file.";
      return 1;
   }

   // Load file header
   if (fread(&hdr, sizeof(hdr), 1, file) != 1
       ||
      (hdr.magic_number != 0xa1b2c3d4 && hdr.magic_number != 0xd4c3b2a1)) {

      errmsg = "Not a valid pcap file.";
      fclose(file);
      return 2;
   }

   // Swap byte order, when received header has Little Endian
   if (hdr.magic_number==0xd4c3b2a1) {
      ntohs(hdr.version_major);
      ntohs(hdr.version_minor);
      ntohl(hdr.thiszone);
      ntohl(hdr.sigfigs);
      ntohl(hdr.snaplen);
      ntohl(hdr.network);
   }

// Check version
//    if (hdr.version_major != 2 || hdr.version_minor != 4) {
//       errmsg = "Unknown version of pcap file.";
//       return 4;
//    }

   // Allocate buffer for packet data
   // (pcap->hdr.snaplen should be sufficient, but it's often not set correctly)
   if (hdr.snaplen > 4096)
      data_buffer_size = hdr.snaplen;
   else
      data_buffer_size = 4096;
   data_buffer = new char[data_buffer_size];

   if (!data_buffer) {
      errmsg = "Can't allocate memory for packet data buffer ("+string(data_buffer)+"B was requested).";
      fclose(file);
      return -1;
   }

   // File was successfully opened
   opened = true;
   return 0;
}

// Close a file
int PcapReader::close()
{
   if (!opened)
      return 0;

   if (fclose(file) == 0) {
      opened = false;
      return 0;
   }
   else {
      errmsg = "Can't close file.";
      return 1;
   }
}

// Return next packet (which it's able to parse) from the file
int PcapReader::get_pkt(Packet &packet)
{
   int ret;
   pcap_rec_hdr_t pkt_hdr;

   if (!opened) {
      errmsg = "No file is opened.";
      return 1;
   }

   do {
      // Read packet header
      if (fread(&pkt_hdr, sizeof(pkt_hdr), 1, file) < 1) {
         if (feof(file)) {
            errmsg = "EOF";
            return -1;
         }
         errmsg = "Error when reading file.\n";
         return 1;
      }

      // Check if included length of data is not larger than buffer
      if (pkt_hdr.incl_len > data_buffer_size) {
         errmsg = "Packet is longer than maximum. File is probably corrupted.";
         return 2;
      }

      // Read packet data
      if (fread(data_buffer, pkt_hdr.incl_len, 1, file) < 1) {
         if (feof(file)) {
            errmsg = "Unexpected end of file.";
            return -2;
         }
         errmsg = "Error when reading file.";
         return 4;
      }

      cnt_total++;

      // Parse packet
      ret = parse_packet(pkt_hdr, data_buffer, packet);

   } while (ret != 0); // If packet can't be parsed properly, try next one

   cnt_parsed++;
   return 0;
}

// PcapReader -- PROTECTED ****************************************************

/*
   Based on PCAP Offline Parsing Example by Joshua Robinson, (joshua.robinson – at – gmail.com)
   http://code.google.com/p/pcapsctpspliter/issues/detail?id=6
*/

int PcapReader::parse_packet(const pcap_rec_hdr_t &hdr, const char *data, Packet &p) {
   uint32_t caplen = hdr.incl_len;
   const char *pkt_ptr = data;

   p.packetFieldIndicator = 0x0; // set all fields not valid

// Read timestamp
   p.timestamp = hdr.ts_sec + hdr.ts_usec/1000000.0;
   p.packetFieldIndicator |= PCKT_TIMESTAMP;

// Get ethernet type
   uint16_t ether_type = ((uint8_t)(pkt_ptr[12]) << 8) | (uint8_t)pkt_ptr[13];
   int ether_offset = 0;

   if (ether_type == ETHER_TYPE_IPv4 || ether_type == ETHER_TYPE_IPv6)
      ether_offset = 14;
   else if (ether_type == ETHER_TYPE_8021Q)
      ether_offset = 18;
   else {
      if (verbose)
         fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);
      return 1;
   }

   pkt_ptr += ether_offset;  // skip ethernet header

// Parse IPv4 header
   if (ether_type ==  ETHER_TYPE_IPv4 || ether_type == ETHER_TYPE_8021Q) {
      ipv4hdr *ip_hdr = (ipv4hdr*) pkt_ptr; // point to an IP header structure
      pkt_ptr += (ip_hdr->ver_hdrlen & 0x0f)*4;

      p.ipVersion                = (ip_hdr->ver_hdrlen & 0xf0) >> 4;
      p.protocolIdentifier       = ip_hdr->protocol;
      p.ipClassOfService         = ip_hdr->tos;
      p.ipLength                 = ntohs(ip_hdr->tot_len);
      p.ipTtl                    = ip_hdr->ttl;
      p.sourceIPv4Address        = ntohl(ip_hdr->saddr);
      p.destinationIPv4Address   = ntohl(ip_hdr->daddr);

      p.packetFieldIndicator |= PCKT_IPV4_MASK;
   }

// Parse IPv6 header
   else if (ether_type == ETHER_TYPE_IPv6) {
      ipv6hdr *ip_hdr = (ipv6hdr*) pkt_ptr;
      pkt_ptr += 40;

      p.ipVersion = (ip_hdr->v6nfo & 0xf0000000) >> 28;
      p.ipClassOfService = (ip_hdr->v6nfo & 0x0ff00000) >> 20;
      p.protocolIdentifier = ip_hdr->next_hdr;
      p.ipLength = ntohs(ip_hdr->payload_len);
      memcpy(p.sourceIPv6Address, ip_hdr->saddr, 16);
      memcpy(p.destinationIPv6Address, ip_hdr->daddr, 16);

      swapbytes128(p.sourceIPv6Address);
      swapbytes128(p.destinationIPv6Address);

      p.packetFieldIndicator |= PCKT_IPV6_MASK;
   }

// Parse TCP header
   if (p.protocolIdentifier == IP_PROTO_TCP) {
      tcphdr *tcp_hdr = (tcphdr*)pkt_ptr; //point to a TCP header structure
      pkt_ptr += ((tcp_hdr->doff & 0xf0) >> 4)*4;

      p.sourceTransportPort      = ntohs(tcp_hdr->source);
      p.destinationTransportPort = ntohs(tcp_hdr->dest);
      p.tcpControlBits           = tcp_hdr->flags;
      p.packetFieldIndicator |= PCKT_TCP_MASK;
   }

// Parse UDP header
   else if (p.protocolIdentifier == IP_PROTO_UDP) {
      udphdr *udp_hdr = (udphdr *)pkt_ptr; //point to a UDP header structure
      pkt_ptr += 8;

      p.sourceTransportPort      = ntohs(udp_hdr->source);
      p.destinationTransportPort = ntohs(udp_hdr->dest);
      p.packetFieldIndicator |= PCKT_UDP_MASK;
   }
   else if (p.protocolIdentifier == IP_PROTO_ICMP || p.protocolIdentifier == IP_PROTO_ICMPv6) {
      pkt_ptr += 8;
   }
   else {
      if (verbose)
         fprintf(stderr, "Unknown protocol, %d, skipping...\n", p.protocolIdentifier);
      return 2;
   }

   if ( ((p.packetFieldIndicator & PCKT_TCP_MASK) == PCKT_TCP_MASK) ||
        ((p.packetFieldIndicator & PCKT_UDP_MASK) == PCKT_UDP_MASK) ) {

      p.transportPayloadPacketSectionSize = caplen - (pkt_ptr - data);
      if (p.transportPayloadPacketSectionSize > MAXPCKTPAYLOADSIZE) {
         if (verbose)
            fprintf(stderr, "Payload too long: %d, trimming to: %d\n", p.transportPayloadPacketSectionSize, MAXPCKTPAYLOADSIZE);
         p.transportPayloadPacketSectionSize = MAXPCKTPAYLOADSIZE;
      }
      memcpy(p.transportPayloadPacketSection, pkt_ptr, p.transportPayloadPacketSectionSize);
      p.packetFieldIndicator |= PCKT_PAYLOAD_MASK;
   }
   return 0;
}
