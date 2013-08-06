#include "detectionrules.h"
#include "eventhandler.h"

#ifdef STREAM_VERSION
#include "stream_version/profile.h"
#else
#include "timeslot_version/profile.h"
#endif

using namespace std;

// Check every IP address' stats whether it comply to some simple rules

#ifndef STREAM_VERSION
////////////////////////////////////
// Generic rules for all traffic
void check_rules(const Profile* profile)
{
   const string &timeslot = profile->current_timeslot;
   const stat_map_t &stat_map = *(profile->stat_map_to_check);
   
   log(LOG_DEBUG, "check_rules()");
            
   for (stat_map_citer it = stat_map.begin(); it != stat_map.end(); ++it)
   {
      check_rules(it->first, it->second, timeslot);
   }
}
#endif

void check_rules(const hosts_key_t &addr, const hosts_record_t &rec, const std::string &timeslot)
{
   // horizontal SYN scan (scanning address)
   if (rec.out_syn_cnt > 200 &&
       rec.out_syn_cnt > 20*rec.out_ack_cnt && // most of outgoing flows are SYN-only (no ACKs)
       rec.out_syn_cnt > 5*rec.in_ack_cnt && // most targets don't answer with ACK
       rec.out_uniqueips >= 200 && // a lot of different destinations
       rec.out_syn_cnt > rec.out_flows/2) // it is more than half of total outgoing traffic of this address
   {
      Event evt(timeslot, PORTSCAN_H);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_syn_cnt - rec.out_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }
   
   // DoS/DDoS (victim)
   if (rec.in_flows > 135000 && // number of connection requests (if it's less than 128k (plus some margin) it may be vertical scan)
       rec.in_packets < 2*rec.in_flows && // packets per flow < 2
       rec.out_flows < rec.in_flows/2) // less than half of requests are replied
   {
      Event evt(timeslot, DOS);
      evt.addProto(TCP).addDstAddr(addr);
      evt.setScale(rec.in_flows);
      evt.setNote("in: %u flows, %u packets; out: %u flows, %u packets; approx. %u source addresses",
                  rec.in_flows, rec.in_packets, rec.out_flows, rec.out_packets, rec.in_uniqueips);
      // Are source addresses random (spoofed)? If less than two incoming flows per address  
      // (i.e. almost every flow comes from different address), it's probably spoofed.
      if (rec.in_flows < 2*rec.in_uniqueips) {
         evt.note += " (probably spoofed)";
      }
      reportEvent(evt);
   }
   
   // DoS/DDoS (attacker)
   if (rec.out_flows/135000 > max(rec.out_uniqueips,1U) && // number of connection requests per target
       rec.out_packets < 2*rec.out_flows && // packets per flow < 2
       rec.in_flows < rec.out_flows/2) // less than half of requests are replied
   {
      Event evt(timeslot, DOS);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_flows);
      evt.setNote("out: %u flows, %u packets; in: %u flows, %u packets; approx. %u destination addresses",
                  rec.out_flows, rec.out_packets, rec.in_flows, rec.in_packets, rec.out_uniqueips);
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

#ifndef STREAM_VERSION
void check_rules_ssh(const Profile* profile)
{
   const string &timeslot = profile->current_timeslot;
   const stat_map_t &stat_map = *(profile->stat_map_to_check);
   
   log(LOG_DEBUG, "check_rules_ssh()");
               
   for (stat_map_citer it = stat_map.begin(); it != stat_map.end(); ++it)
   {
      check_rules_ssh(it->first, it->second, timeslot);
   }
}
#endif

void check_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec, const std::string &timeslot)
{
   // Horizontal scanning of ssh ports (output = scanning address)
   // Disabled as scanning should be detected also by generic rules
   /*if (( (rec.out_ack_cnt > SCAN_FLAG_RATIO*rec.in_ack_cnt && rec.out_ack_cnt > SCAN_THRESHOLD) // skenovani posilanim syn-ack
   ||
   ( rec.out_syn_cnt > SCAN_FLAG_RATIO*rec.in_syn_cnt && rec.out_syn_cnt > SCAN_THRESHOLD)) // skenovani posilanim syn
   &&
   rec.out_packets < SCAN_PACKET_RATIO*rec.out_flows  // prumerny pocet paketu na tok < 5
   && rec.out_flows > SCAN_IP_RATIO * rec.out_uniqueips // kazde flow jde na jinou adresu (priblizne)
   && rec.out_uniqueips > SCAN_THRESHOLD/2
   ) {
      // Neni 100% zaruceno, ze skenovany port je 22, teoreticky muze byt port 22 vzdy zdrojovy, to je ale hodne nepravdepodobne
      Event evt(timeslot, PORTSCAN_H);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(rec.out_syn_cnt - rec.out_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }*/

   // SSH bruteforce (output = address under attack)
   if (( // odpovedi
   rec.out_packets >= BRUTEFORCE_DATA_MIN_PACKET_RATIO*rec.out_syn_cnt &&
   rec.out_packets <= BRUTEFORCE_DATA_MAX_PACKET_RATIO*rec.out_syn_cnt &&
   rec.out_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   &&
   ( // dotazy
   rec.in_packets >= BRUTEFORCE_REQ_MIN_PACKET_RATIO*rec.in_syn_cnt &&
   rec.in_packets <= BRUTEFORCE_REQ_MAX_PACKET_RATIO*rec.in_syn_cnt &&
   rec.in_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   &&
   (
   rec.in_syn_cnt >= rec.out_syn_cnt
   )
   && ( rec.out_syn_cnt > BRUTEFORCE_IPS_RATIO*rec.out_uniqueips) // alespon 30x odpovidal stejne adrese
   ) {
      Event evt(timeslot, BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addDstAddr(addr);
      evt.setScale(rec.in_syn_cnt);
      //evt.setNote("");
      reportEvent(evt);
   }
   
   // SSH bruteforce (output = attacking address)
   if (
   ( // dotazy
   rec.out_packets > BRUTEFORCE_REQ_MIN_PACKET_RATIO*rec.out_syn_cnt &&
   rec.out_packets < BRUTEFORCE_REQ_MAX_PACKET_RATIO*rec.out_syn_cnt &&
   rec.out_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   &&
   ( // odpovedi
   rec.in_packets > BRUTEFORCE_DATA_MIN_PACKET_RATIO*rec.in_syn_cnt &&
   rec.in_packets < BRUTEFORCE_DATA_MAX_PACKET_RATIO*rec.in_syn_cnt &&
   rec.in_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   &&
   (
   rec.in_syn_cnt <= rec.out_syn_cnt
   )
   &&
   (
   (
   rec.out_syn_cnt > BRUTEFORCE_IPS_RATIO*rec.out_uniqueips // na jednu adresu jde alespon 30 dotazu
   && rec.out_uniqueips < BRUTEFORCE_IPS // hada na mene nez 5 adresach
   )
   ||
   (
   rec.out_syn_cnt > 0.5*BRUTEFORCE_IPS_RATIO*rec.out_uniqueips && // na jednu adresu jde alespon 15 dotazu
   rec.out_uniqueips >= BRUTEFORCE_IPS // hada na vice nez 5 adresach
   )
   )
   )
   {
      Event evt(timeslot, BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(rec.out_syn_cnt);
      //evt.setNote("");
      reportEvent(evt);
   } 
}