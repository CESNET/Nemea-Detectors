#include <time.h>

#include "detectionrules.h"
#include "eventhandler.h"

#ifdef STREAM_VERSION
#include "stream_version/profile.h"
#else
#include "timeslot_version/profile.h"
#endif

using namespace std;


const std::string get_rec_time(const hosts_record_t &rec)
{
   time_t temp = rec.first_rec_ts;
   struct tm *timeinfo;
   char buff[13]; //12 signs + '/0'

   timeinfo = localtime(&temp);
   strftime(buff, 13, "%4Y%2m%2d%2H%2M", timeinfo); 

   return string(buff);
}

/*
void check_new_rules(const hosts_key_t &addr, const hosts_record_t &rec)
{
   // horizontal SYN scan (scanning address)
   uint64_t est_out_req_syn_cnt = rec.out_req_syn_cnt + (rec.out_all_syn_cnt - (rec.out_req_syn_cnt + rec.out_rsp_syn_cnt))/2;
   uint64_t est_out_req_ack_cnt = rec.out_req_ack_cnt + (rec.out_all_ack_cnt - (rec.out_req_ack_cnt + rec.out_rsp_ack_cnt))/2;
   uint64_t est_in_rsp_ack_cnt = rec.in_rsp_ack_cnt + (rec.out_all_ack_cnt - (rec.out_req_ack_cnt + rec.out_rsp_ack_cnt))/2;

   if (est_out_req_syn_cnt > 200 &&
       est_out_req_syn_cnt > 20*est_out_req_ack_cnt && // most of outgoing flows are SYN-only (no ACKs)
       est_out_req_syn_cnt > 5*est_in_rsp_ack_cnt && // most targets don't answer with ACK
       rec.out_req_uniqueips >= 200 && // a lot of different destinations
       rec.out_req_syn_cnt > rec.out_all_flows/2) // it is more than half of total outgoing traffic of this address
   {
      Event evt(get_rec_time(rec), PORTSCAN_H);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt - rec.out_all_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }
   
   // DoS/DDoS (victim)
   uint64_t est_out_rsp_flows = rec.out_rsp_flows + (rec.out_all_flows - (rec.out_req_flows + rec.out_rsp_flows))/2;
   uint64_t est_in_req_flows = rec.in_req_flows + (rec.in_all_flows - (rec.in_req_flows + rec.in_rsp_flows))/2;
   uint64_t est_in_req_packets = rec.in_req_packets + (rec.in_all_packets - (rec.in_req_packets + rec.in_rsp_packets))/2;

   if ( est_in_req_flows > 135000 && // number of connection requests (if it's less than 128k (plus some margin) it may be vertical scan)
       est_in_req_packets < 2*est_in_req_flows && // packets per flow < 2
       est_out_rsp_flows < est_in_req_flows/2) // less than half of requests are replied
   {
      Event evt(get_rec_time(rec), DOS);
      evt.addProto(TCP).addDstAddr(addr);
      evt.setScale(rec.in_all_flows);
      evt.setNote("in: %u flows, %u packets; out: %u flows, %u packets; approx. %u source addresses",
                  rec.in_all_flows, rec.in_all_packets, rec.out_all_flows, rec.out_all_packets, rec.in_all_uniqueips);
      // Are source addresses random (spoofed)? If less than two incoming flows per address  
      // (i.e. almost every flow comes from different address), it's probably spoofed.
      if (rec.in_all_flows < 2*rec.in_all_uniqueips) {
         evt.note += " (probably spoofed)";
      }
      reportEvent(evt);
   }
   
   // DoS/DDoS (attacker)
   uint64_t est_out_req_flows = rec.out_req_flows + (rec.out_all_flows - (rec.out_req_flows + rec.out_rsp_flows))/2;
   uint64_t est_out_req_packets = rec.out_req_packets + (rec.out_all_packets - (rec.out_req_packets + rec.out_rsp_packets))/2;
   uint64_t est_in_rsp_flows = rec.in_rsp_flows + (rec.in_all_flows - (rec.in_req_flows + rec.in_rsp_flows))/2;
 
   if (est_out_req_flows /135000 >= max(rec.out_all_uniqueips,(uint16_t)1U) && // number of connection requests per target
       est_out_req_packets < 2* est_out_req_flows && // packets per flow < 2
       est_in_rsp_flows < est_out_req_flows) // less than half of requests are replied
   {
      Event evt(get_rec_time(rec), DOS);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_all_flows);
      evt.setNote("out: %u flows, %u packets; in: %u flows, %u packets; approx. %u destination addresses",
                  rec.out_all_flows, rec.out_all_packets, rec.in_all_flows, rec.in_all_packets, rec.out_all_uniqueips);
      reportEvent(evt);
   }
}

*/
void check_rules(const hosts_key_t &addr, const hosts_record_t &rec)
{
   // horizontal SYN scan (scanning address)
   if (rec.out_all_syn_cnt > 200 &&
       rec.out_all_syn_cnt > 20*rec.out_all_ack_cnt && // most of outgoing flows are SYN-only (no ACKs)
       rec.out_all_syn_cnt > 5*rec.in_all_ack_cnt && // most targets don't answer with ACK
       rec.out_all_uniqueips >= 200 && // a lot of different destinations
       rec.out_all_syn_cnt > rec.out_all_flows/2) // it is more than half of total outgoing traffic of this address
   {
      Event evt(get_rec_time(rec), PORTSCAN_H);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt - rec.out_all_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }
   
   // DoS/DDoS (victim)
   if (rec.in_all_flows > 135000 && // number of connection requests (if it's less than 128k (plus some margin) it may be vertical scan)
       rec.in_all_packets < 2*rec.in_all_flows && // packets per flow < 2
       rec.out_all_flows < rec.in_all_flows/2) // less than half of requests are replied
   {
      Event evt(get_rec_time(rec), DOS);
      evt.addProto(TCP).addDstAddr(addr);
      evt.setScale(rec.in_all_flows);
      evt.setNote("in: %u flows, %u packets; out: %u flows, %u packets; approx. %u source addresses",
                  rec.in_all_flows, rec.in_all_packets, rec.out_all_flows, rec.out_all_packets, rec.in_all_uniqueips);
      // Are source addresses random (spoofed)? If less than two incoming flows per address  
      // (i.e. almost every flow comes from different address), it's probably spoofed.
      if (rec.in_all_flows < 2*rec.in_all_uniqueips) {
         evt.note += " (probably spoofed)";
      }
      reportEvent(evt);
   }
   
   // DoS/DDoS (attacker)
   if (rec.out_all_flows/135000 > max(rec.out_all_uniqueips,(uint16_t)1U) && // number of connection requests per target
       rec.out_all_packets < 2*rec.out_all_flows && // packets per flow < 2
       rec.in_all_flows < rec.out_all_flows/2) // less than half of requests are replied
   {
      Event evt(get_rec_time(rec), DOS);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_all_flows);
      evt.setNote("out: %u flows, %u packets; in: %u flows, %u packets; approx. %u destination addresses",
                  rec.out_all_flows, rec.out_all_packets, rec.in_all_flows, rec.in_all_packets, rec.out_all_uniqueips);
      reportEvent(evt);
   }
}

//////////////////////////////////
// Rules specific to SSH traffic

#define SCAN_THRESHOLD 100
#define SCAN_FLAG_RATIO 5
#define SCAN_PACKET_RATIO 5
#define SCAN_IP_RATIO 0.5

#define BRUTEFORCE_OUT_THRESHOLD 10
#define BRUTEFORCE_IPS 5
#define BRUTEFORCE_IPS_RATIO 30
#define BRUTEFORCE_REQ_THRESHOLD 60
#define BRUTEFORCE_REQ_MIN_PACKET_RATIO 5
#define BRUTEFORCE_REQ_MAX_PACKET_RATIO 20
#define BRUTEFORCE_DATA_THRESHOLD 0.5*BRUTEFORCE_REQ_THRESHOLD
#define BRUTEFORCE_DATA_MIN_PACKET_RATIO 10
#define BRUTEFORCE_DATA_MAX_PACKET_RATIO 25
#define BRUTEFORCE_SERVER_RATIO 3

void check_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec)
{
   // Horizontal scanning of ssh ports (output = scanning address)
   // Disabled as scanning should be detected also by generic rules
   /*if (( (rec.out_all_ack_cnt > SCAN_FLAG_RATIO*rec.in_all_ack_cnt && rec.out_all_ack_cnt > SCAN_THRESHOLD) // skenovani posilanim syn-ack
   ||
   ( rec.out_all_syn_cnt > SCAN_FLAG_RATIO*rec.in_all_syn_cnt && rec.out_all_syn_cnt > SCAN_THRESHOLD)) // skenovani posilanim syn
   &&
   rec.out_all_packets < SCAN_PACKET_RATIO*rec.out_all_flows  // prumerny pocet paketu na tok < 5
   && rec.out_all_flows > SCAN_IP_RATIO * rec.out_all_uniqueips // kazde flow jde na jinou adresu (priblizne)
   && rec.out_all_uniqueips > SCAN_THRESHOLD/2
   ) {
      // Neni 100% zaruceno, ze skenovany port je 22, teoreticky muze byt port 22 vzdy zdrojovy, to je ale hodne nepravdepodobne
      Event evt(timeslot, PORTSCAN_H);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt - rec.out_all_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }*/

   // SSH bruteforce (output = address under attack)
   if (( // odpovedi
   rec.out_all_packets >= BRUTEFORCE_DATA_MIN_PACKET_RATIO*rec.out_all_syn_cnt &&
   rec.out_all_packets <= BRUTEFORCE_DATA_MAX_PACKET_RATIO*rec.out_all_syn_cnt &&
   rec.out_all_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   &&
   ( // dotazy
   rec.in_all_packets >= BRUTEFORCE_REQ_MIN_PACKET_RATIO*rec.in_all_syn_cnt &&
   rec.in_all_packets <= BRUTEFORCE_REQ_MAX_PACKET_RATIO*rec.in_all_syn_cnt &&
   rec.in_all_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   &&
   (
   rec.in_all_syn_cnt >= rec.out_all_syn_cnt
   )
   && ( rec.out_all_syn_cnt > BRUTEFORCE_IPS_RATIO*rec.out_all_uniqueips) // alespon 30x odpovidal stejne adrese
   ) {
      Event evt(get_rec_time(rec), BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addDstAddr(addr);
      evt.setScale(rec.in_all_syn_cnt);
      //evt.setNote("");
      reportEvent(evt);
   }
   
   // SSH bruteforce (output = attacking address)
   if (
   ( // dotazy
   rec.out_all_packets > BRUTEFORCE_REQ_MIN_PACKET_RATIO*rec.out_all_syn_cnt &&
   rec.out_all_packets < BRUTEFORCE_REQ_MAX_PACKET_RATIO*rec.out_all_syn_cnt &&
   rec.out_all_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   &&
   ( // odpovedi
   rec.in_all_packets > BRUTEFORCE_DATA_MIN_PACKET_RATIO*rec.in_all_syn_cnt &&
   rec.in_all_packets < BRUTEFORCE_DATA_MAX_PACKET_RATIO*rec.in_all_syn_cnt &&
   rec.in_all_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   &&
   (
   rec.in_all_syn_cnt <= rec.out_all_syn_cnt
   )
   &&
   (
   (
   rec.out_all_syn_cnt > BRUTEFORCE_IPS_RATIO*rec.out_all_uniqueips // na jednu adresu jde alespon 30 dotazu
   && rec.out_all_uniqueips < BRUTEFORCE_IPS // hada na mene nez 5 adresach
   )
   ||
   (
   rec.out_all_syn_cnt > 0.5*BRUTEFORCE_IPS_RATIO*rec.out_all_uniqueips && // na jednu adresu jde alespon 15 dotazu
   rec.out_all_uniqueips >= BRUTEFORCE_IPS // hada na vice nez 5 adresach
   )
   )
   )
   {
      Event evt(get_rec_time(rec), BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt);
      //evt.setNote("");
      reportEvent(evt);
   } 
}
/*
void check_new_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec)
{

   // SSH bruteforce (output = address under attack)
   if (( // odpovedi
   // average response size must be in between BRUTEFORCE_DATA_MIN_PACKET_RATIO and BRUTEFORCE_DATA_MAX_PACKET_RATIO
   // and number of responses must be at least  BRUTEFORCE_DATA_THRESHOLD
   rec.out_rsp_packets >= BRUTEFORCE_DATA_MIN_PACKET_RATIO*rec.out_rsp_syn_cnt &&   
   rec.out_rsp_packets <= BRUTEFORCE_DATA_MAX_PACKET_RATIO*rec.out_rsp_syn_cnt &&
   rec.out_rsp_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   &&
   ( // dotazy
   // average  request size must be in between BRUTEFORCE_REQ_MIN_PACKET_RATIO and BRUTEFORCE_REQ_MAX_PACKET_RATIO
   // and number of responses must be at least  BRUTEFORCE_REQ_THRESHOLD
   rec.in_req_packets >= BRUTEFORCE_REQ_MIN_PACKET_RATIO*rec.in_req_syn_cnt &&
   rec.in_req_packets <= BRUTEFORCE_REQ_MAX_PACKET_RATIO*rec.in_req_syn_cnt &&
   rec.in_req_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   &&
   (
   // number of incoming requests on SSH server must be BRUTEFORCE_SERVER_RATIO-times larger than 
   // the number of outgoing requests
   rec.in_req_syn_cnt > BRUTEFORCE_SERVER_RATIO*rec.out_req_syn_cnt
   )
   && ( rec.out_rsp_syn_cnt > BRUTEFORCE_IPS_RATIO*rec.out_all_uniqueips) // alespon 30x odpovidal stejne adrese
   ) {
      Event evt(get_rec_time(rec), BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addDstAddr(addr);
      evt.setScale(rec.in_all_syn_cnt);
      //evt.setNote("");
      reportEvent(evt);
   }
   
   // SSH bruteforce (output = attacking address)
   if (
   ( // dotazy
   rec.out_req_packets > BRUTEFORCE_REQ_MIN_PACKET_RATIO*rec.out_req_syn_cnt &&
   rec.out_req_packets < BRUTEFORCE_REQ_MAX_PACKET_RATIO*rec.out_req_syn_cnt &&
   rec.out_req_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   &&
   ( // odpovedi
   rec.in_rsp_packets > BRUTEFORCE_DATA_MIN_PACKET_RATIO*rec.in_rsp_syn_cnt &&
   rec.in_rsp_packets < BRUTEFORCE_DATA_MAX_PACKET_RATIO*rec.in_rsp_syn_cnt &&
   rec.in_rsp_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   &&
   (
   rec.in_req_syn_cnt < BRUTEFORCE_SERVER_RATIO*rec.out_req_syn_cnt
   )
   &&
   (
   (
   rec.out_rsp_syn_cnt > BRUTEFORCE_IPS_RATIO*rec.out_all_uniqueips // na jednu adresu jde alespon 30 dotazu
   && rec.out_all_uniqueips < BRUTEFORCE_IPS // hada na mene nez 5 adresach
   )
   ||
   (
   rec.out_rsp_syn_cnt > 0.5*BRUTEFORCE_IPS_RATIO*rec.out_all_uniqueips && // na jednu adresu jde alespon 15 dotazu
   rec.out_all_uniqueips >= BRUTEFORCE_IPS // hada na vice nez 5 adresach
   )
   )
   )
   {
      Event evt(get_rec_time(rec), BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt);
      //evt.setNote("");
      reportEvent(evt);
   } 
}
*/
