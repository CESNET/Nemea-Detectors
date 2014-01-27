#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

#include "flowwriter.h"

#include <cstring>
#include <iostream>


using namespace std;

void FlowWriter::printinfo()
{
   const uint32_t magic_number = 0xF1003ECD;
   uint32_t offset = 0;
   uint32_t hdr_len = 0;
   const char *hdr = \
   "\x08" "flowFieldIndicator\0" \
   "\x08" "flowStartTimestamp\0" \
   "\x08" "flowEndTimestamp\0" \
   "\x01" "ipVersion\0" \
   "\x01" "protocolIdentifier\0" \
   "\x01" "ipClassOfService\0" \
   "\x01" "ipTtl\0" \
   "\x04" "sourceIPv4Address\0" \
   "\x04" "destinationIPv4Address\0" \
   "\x10" "sourceIPv6Address\0" \
   "\x10" "destinationIPv6Address\0" \
   "\x02" "sourceTransportPort\0" \
   "\x02" "destinationTransportPort\0" \
   "\x04" "packetTotalCount\0" \
   "\x08" "octetTotalLength\0" \
   "\x01" "tcpControlBits\0" \
   "\x08" "flowPayloadStart\0" \
   "\x08" "flowPayloadSize\0";

   hdr_len = 334;

   offset = sizeof(magic_number) + sizeof(offset) + sizeof(hdr_len) + hdr_len;

   flowos->write((char*) &magic_number, sizeof(magic_number));
   flowos->write((char*) &offset, sizeof(offset));
   flowos->write((char*) &hdr_len, sizeof(hdr_len));
   flowos->write(hdr, hdr_len);
}

int FlowWriter::open(const std::string &infilename)
{
   // TRAP INITIALIZE
   // Moved to main.cpp   

   // Create template <COLLECTOR_FLOW>
   tmplt = ur_create_template("<COLLECTOR_FLOW>");
   
   // Create buffer for output data
   data = ur_create(tmplt, 0);

   return 0;
}

int FlowWriter::close()
{
   // Send terminating signal to output interface
   char dummy[1] = {0};
   trap_send_data(0, dummy, 1, TRAP_WAIT);

   // TRAP finalize
   trap_finalize();
   return 0;
}

int FlowWriter::export_flow(FlowRecord &flow)
{
/*
   char flowbinline[sizeof(FlowRecord)];
   char *ptr_line = flowbinline;

// Write payload to data file
   if (plimit > 0) {
      flow.flowPayloadStart = dataos->tellp();
      dataos->write((char *) flow.flowPayloadStart, flow.flowPayloadSize);
   }
// Flow details
   *(uint64_t *) ptr_line = flow.flowFieldIndicator;
   ptr_line += sizeof(flow.flowFieldIndicator);
   *(double *) ptr_line = flow.flowStartTimestamp;
   ptr_line += sizeof(flow.flowStartTimestamp);
   *(double *) ptr_line = flow.flowEndTimestamp;
   ptr_line += sizeof(flow.flowEndTimestamp);
// IP details
   *(uint8_t *) ptr_line = flow.ipVersion;
   ptr_line += sizeof(flow.ipVersion);
   *(uint8_t *) ptr_line = flow.protocolIdentifier;
   ptr_line += sizeof(flow.protocolIdentifier);
   *(uint8_t *) ptr_line = flow.ipClassOfService;
   ptr_line += sizeof(flow.ipClassOfService);
   *(uint8_t *) ptr_line = flow.ipTtl;
   ptr_line += sizeof(flow.ipTtl);
// IPv4
   *(uint32_t *) ptr_line = flow.sourceIPv4Address;
   ptr_line += sizeof(flow.sourceIPv4Address);
   *(uint32_t *) ptr_line = flow.destinationIPv4Address;
   ptr_line += sizeof(flow.destinationIPv4Address);
// IPv6
   memcpy(ptr_line, flow.sourceIPv6Address, sizeof(flow.sourceIPv6Address));
   ptr_line += sizeof(flow.sourceIPv6Address);
   memcpy(ptr_line,flow.destinationIPv6Address,sizeof(flow.destinationIPv6Address));
   ptr_line += sizeof(flow.destinationIPv6Address);
// Packet details
// Payload
   *(uint64_t *) ptr_line = flow.flowPayloadStart;
   ptr_line += sizeof(flow.flowPayloadStart);
   *(uint64_t *) ptr_line = flow.flowPayloadSize;
   ptr_line += sizeof(flow.flowPayloadSize);

   uint32_t linesize = ptr_line - flowbinline;
   flowos->write(flowbinline, linesize);
*/

   uint64_t tmp_time;
   uint32_t time_sec;
   uint32_t time_msec;


   if (flow.ipVersion == 4) {
      // IPv4
      ur_set(tmplt, data, UR_SRC_IP, ip_from_4_bytes_le((char*)&flow.sourceIPv4Address));
      ur_set(tmplt, data, UR_DST_IP, ip_from_4_bytes_le((char*)&flow.destinationIPv4Address));
   } else {
      // IPv6
      ur_set(tmplt, data, UR_SRC_IP, ip_from_16_bytes_le((char*)&flow.sourceIPv6Address));
      ur_set(tmplt, data, UR_DST_IP, ip_from_16_bytes_le((char*)&flow.destinationIPv6Address));


   }

   // Timestamp is double where integral is in seconds and fraction is microseconds/10^6

   time_sec = (uint32_t)flow.flowStartTimestamp;
   time_msec = (uint32_t)((flow.flowStartTimestamp - ((double)((uint32_t)flow.flowStartTimestamp))) * 1000);
   tmp_time = ur_time_from_sec_msec(time_sec, time_msec);
   ur_set(tmplt, data, UR_TIME_FIRST, tmp_time);

   time_sec = (uint32_t)flow.flowEndTimestamp;
   time_msec = (uint32_t)((flow.flowEndTimestamp - ((double)((uint32_t)flow.flowEndTimestamp))) * 1000);
   tmp_time = ur_time_from_sec_msec(time_sec, time_msec);
   ur_set(tmplt, data, UR_TIME_LAST, tmp_time);
   
   


   ur_set(tmplt, data, UR_PROTOCOL, flow.protocolIdentifier);
   ur_set(tmplt, data, UR_SRC_PORT, flow.sourceTransportPort);
   ur_set(tmplt, data, UR_DST_PORT, flow.destinationTransportPort);
   ur_set(tmplt, data, UR_PACKETS, flow.packetTotalCount);
   ur_set(tmplt, data, UR_BYTES, flow.octetTotalLength);
   ur_set(tmplt, data, UR_TCP_FLAGS, flow.tcpControlBits);


   
   ur_set(tmplt, data, UR_DIR_BIT_FIELD, 0);
   ur_set(tmplt, data, UR_LINK_BIT_FIELD, 0);


   trap_send_data(0, data, ur_rec_static_size(tmplt), TRAP_WAIT);





   return 0;
}
