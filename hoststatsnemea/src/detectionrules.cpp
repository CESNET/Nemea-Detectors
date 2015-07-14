/*
 * Copyright (C) 2013-2015 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <time.h>

#include "detectionrules.h"
#include "eventhandler.h"
#include "profile.h"

using namespace std;


#define SYN_SCAN_TRESHOLD 200
#define SYN_SCAN_SYN_TO_ACK_RATIO 20
#define SYN_SCAN_REQUEST_TO_RESPONSE_RATIO 5
#define SYN_SCAN_IPS 200

#define DOS_VICTIM_CONNECTIONS_SYNFLOOD 270000
#define DOS_VICTIM_CONNECTIONS_OTHERS 1000000
#define DOS_VICTIM_PACKET_RATIO 2

#define DOS_ATTACKER_CONNECTIONS_SYNFLOOD 270000U
#define DOS_ATTACKER_CONNECTIONS_OTHERS 1000000U
#define DOS_ATTACKER_PACKET_RATIO 2

#define DOS_REQ_RSP_EST_RATIO (4.0/5.0)
#define DOS_RSP_REQ_EST_RATIO (1.0 - DOS_REQ_RSP_EST_RATIO)

#define DOS_MIN_RSP_RATIO (0.02)

void check_new_rules(const hosts_key_t &addr, const hosts_record_t &rec)
{
   // horizontal SYN scan (scanning address)
   uint64_t est_out_req_syn_cnt = rec.out_req_syn_cnt + (rec.out_all_syn_cnt
           - (rec.out_req_syn_cnt + rec.out_rsp_syn_cnt))*DOS_REQ_RSP_EST_RATIO;
   uint64_t est_out_req_ack_cnt = rec.out_req_ack_cnt + (rec.out_all_ack_cnt
           - (rec.out_req_ack_cnt + rec.out_rsp_ack_cnt))*DOS_REQ_RSP_EST_RATIO;
   uint64_t est_in_rsp_ack_cnt = rec.in_rsp_ack_cnt + (rec.in_all_ack_cnt
           - (rec.in_req_ack_cnt + rec.in_rsp_ack_cnt))*DOS_RSP_REQ_EST_RATIO;

   if (est_out_req_syn_cnt > SYN_SCAN_TRESHOLD &&
       est_out_req_syn_cnt > SYN_SCAN_SYN_TO_ACK_RATIO * est_out_req_ack_cnt && // most of outgoing flows are SYN-only (no ACKs)
       est_out_req_syn_cnt > SYN_SCAN_REQUEST_TO_RESPONSE_RATIO * est_in_rsp_ack_cnt && // most targets don't answer with ACK
       rec.out_req_uniqueips >= SYN_SCAN_IPS && // a lot of different destinations
       rec.out_req_syn_cnt > rec.out_all_flows/2 && // it is more than half of total outgoing traffic of this address
       rec.out_req_syn_cnt > 10*rec.in_all_syn_cnt) // there is not much incoming connections
                                                    //  - this was added to filter out p2p communication
   {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_PORTSCAN_H);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt - rec.out_all_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }

   // DoS/DDoS (victim)
   uint64_t est_out_rsp_flows = rec.out_rsp_flows + (rec.out_all_flows
           - (rec.out_req_flows + rec.out_rsp_flows))*DOS_RSP_REQ_EST_RATIO;
   uint64_t est_in_req_flows = rec.in_req_flows + (rec.in_all_flows
           - (rec.in_req_flows + rec.in_rsp_flows))*DOS_REQ_RSP_EST_RATIO;
   uint64_t est_in_req_packets = rec.in_req_packets + (rec.in_all_packets
           - (rec.in_req_packets + rec.in_rsp_packets))*DOS_REQ_RSP_EST_RATIO;

   bool ddos_tcp_victim = false;
   if (( //TCP (syn flood)
      rec.in_all_syn_cnt > DOS_VICTIM_CONNECTIONS_SYNFLOOD &&
      rec.in_all_syn_cnt > 2 * rec.in_all_ack_cnt &&
      rec.in_all_packets < DOS_VICTIM_PACKET_RATIO * rec.in_all_flows &&
      (ddos_tcp_victim = true)
   ) || ( // UDP & others...
      est_in_req_flows > DOS_VICTIM_CONNECTIONS_OTHERS && // number of connection requests (if it's less than 128k (plus some margin) it may be vertical scan)
      est_in_req_packets < DOS_VICTIM_PACKET_RATIO * est_in_req_flows && // packets per flow < 2
      est_out_rsp_flows < est_in_req_flows/2) // less than half of requests are replied
       // && est_out_rsp_flows > est_in_req_flows * DOS_MIN_RSP_RATIO) // more then 2% of requests are replied
   ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_DOS);
      evt.addDstAddr(addr);
      evt.setScale(rec.in_all_flows);
      evt.setNote("in: %u flows, %u packets; out: %u flows, %u packets; approx."
         " %u source addresses", rec.in_all_flows, rec.in_all_packets,
         rec.out_all_flows, rec.out_all_packets, rec.in_all_uniqueips);
      if (ddos_tcp_victim) {
         evt.addProto(TCP);
         evt.note += "; SYN flood";
      }
      // Are source addresses random (spoofed)? If less than two incoming flows
      // per address (i.e. almost every flow comes from different address),
      // it's probably spoofed.
      if (rec.in_all_flows < 2*rec.in_all_uniqueips) {
         evt.note += " (probably spoofed)";
      }

      reportEvent(evt);
   }

   // DoS/DDoS (attacker)
   uint64_t est_out_req_flows = rec.out_req_flows + (rec.out_all_flows
           - (rec.out_req_flows + rec.out_rsp_flows))*DOS_REQ_RSP_EST_RATIO;
   uint64_t est_out_req_packets = rec.out_req_packets + (rec.out_all_packets
           - (rec.out_req_packets + rec.out_rsp_packets))*DOS_REQ_RSP_EST_RATIO;
   uint64_t est_in_rsp_flows = rec.in_rsp_flows + (rec.in_all_flows
           - (rec.in_req_flows + rec.in_rsp_flows))*DOS_RSP_REQ_EST_RATIO;

   bool ddos_tcp_attacker = false;
   if (( // TCP (syn flood)
      rec.out_all_flows >= DOS_ATTACKER_CONNECTIONS_SYNFLOOD * max(rec.out_all_uniqueips,(uint16_t)1U) &&
      rec.out_all_packets < DOS_ATTACKER_PACKET_RATIO * rec.out_all_flows &&
      rec.out_all_syn_cnt > 2 * rec.out_all_ack_cnt &&
      (ddos_tcp_attacker = true)
   ) || ( // UDP & others...
      est_out_req_flows >= DOS_ATTACKER_CONNECTIONS_OTHERS * max(rec.out_all_uniqueips,(uint16_t)1U) && // number of connection requests per target
      est_out_req_packets < DOS_ATTACKER_PACKET_RATIO * est_out_req_flows && // packets per flow < 2
      est_in_rsp_flows < est_out_req_flows/2) // less than half of requests are replied
      // && est_in_rsp_flows > est_out_req_flows * DOS_MIN_RSP_RATIO) // more then 2% of requests are replied
   ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_DOS);
      evt.addSrcAddr(addr);
      evt.setScale(rec.out_all_flows);
      evt.setNote("out: %u flows, %u packets; in: %u flows, %u packets; approx."
         " %u destination addresses", rec.out_all_flows, rec.out_all_packets,
         rec.in_all_flows, rec.in_all_packets, rec.out_all_uniqueips);
      if (ddos_tcp_attacker) {
         evt.addProto(TCP);
         evt.note += "; SYN flood";
      }

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
#define BRUTEFORCE_IPS_RATIO 20
#define BRUTEFORCE_REQ_THRESHOLD 60
#define BRUTEFORCE_REQ_MIN_PACKET_RATIO 5
#define BRUTEFORCE_REQ_MAX_PACKET_RATIO 20
#define BRUTEFORCE_DATA_THRESHOLD 0.5*BRUTEFORCE_REQ_THRESHOLD
#define BRUTEFORCE_DATA_MIN_PACKET_RATIO 10
#define BRUTEFORCE_DATA_MAX_PACKET_RATIO 25
#define BRUTEFORCE_SERVER_RATIO 3


void check_new_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec)
{
   const ssh_data_t &ssh_rec = *rec.ssh_data;

   // SSH bruteforce (output = address under attack)
   if (( // responses
         // average response size must be in between
         // BRUTEFORCE_DATA_MIN_PACKET_RATIO and BRUTEFORCE_DATA_MAX_PACKET_RATIO
         // and number of responses must be at least  BRUTEFORCE_DATA_THRESHOLD
         ssh_rec.out_rsp_packets >= BRUTEFORCE_DATA_MIN_PACKET_RATIO * ssh_rec.out_rsp_syn_cnt &&
         ssh_rec.out_rsp_packets <= BRUTEFORCE_DATA_MAX_PACKET_RATIO * ssh_rec.out_rsp_syn_cnt &&
         ssh_rec.out_rsp_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
      )
      && ( // requests
         // average  request size must be in between
         // BRUTEFORCE_REQ_MIN_PACKET_RATIO and BRUTEFORCE_REQ_MAX_PACKET_RATIO
         // and number of responses must be at least  BRUTEFORCE_REQ_THRESHOLD
         ssh_rec.in_req_packets >= BRUTEFORCE_REQ_MIN_PACKET_RATIO * ssh_rec.in_req_syn_cnt &&
         ssh_rec.in_req_packets <= BRUTEFORCE_REQ_MAX_PACKET_RATIO * ssh_rec.in_req_syn_cnt &&
         ssh_rec.in_req_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
      )
      && ( // ratio
         // number of incoming requests on SSH server must be
         // BRUTEFORCE_SERVER_RATIO-times larger than the number of outgoing
         // requests
         ssh_rec.in_req_syn_cnt > BRUTEFORCE_SERVER_RATIO * ssh_rec.out_req_syn_cnt
      )
      && (
         // at least BRUTEFORCE_IPS_RATIO responses to same address
         ssh_rec.out_rsp_syn_cnt > BRUTEFORCE_IPS_RATIO * ssh_rec.out_all_uniqueips)
      ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addDstAddr(addr);
      evt.setScale(ssh_rec.in_req_syn_cnt);
      evt.setNote("victim");
      reportEvent(evt);
   }

   // SSH bruteforce (output = attacking address)
   if (( // requests
      ssh_rec.out_req_packets > BRUTEFORCE_REQ_MIN_PACKET_RATIO * ssh_rec.out_req_syn_cnt &&
      ssh_rec.out_req_packets < BRUTEFORCE_REQ_MAX_PACKET_RATIO * ssh_rec.out_req_syn_cnt &&
      ssh_rec.out_req_syn_cnt > BRUTEFORCE_REQ_THRESHOLD
   )
   && ( // responses
      ssh_rec.in_rsp_packets > BRUTEFORCE_DATA_MIN_PACKET_RATIO * ssh_rec.in_rsp_syn_cnt &&
      ssh_rec.in_rsp_packets < BRUTEFORCE_DATA_MAX_PACKET_RATIO * ssh_rec.in_rsp_syn_cnt &&
      ssh_rec.in_rsp_syn_cnt > BRUTEFORCE_DATA_THRESHOLD
   )
   && (
      ssh_rec.in_req_syn_cnt < BRUTEFORCE_SERVER_RATIO * ssh_rec.out_req_syn_cnt
   )
   && (( // at least 20 requests to the same address and less than
         // BRUTEFORCE_IPS password-guessing addresses
         ssh_rec.out_req_syn_cnt > BRUTEFORCE_IPS_RATIO * ssh_rec.out_all_uniqueips &&
         ssh_rec.out_all_uniqueips < BRUTEFORCE_IPS
      ) || (
         // at least 10 requests to the same address and more than
         // BRUTEFORCE_IPS password-guessing addresses
         ssh_rec.out_req_syn_cnt > 0.5 * BRUTEFORCE_IPS_RATIO * ssh_rec.out_all_uniqueips &&
         ssh_rec.out_all_uniqueips >= BRUTEFORCE_IPS
      ))
   ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(ssh_rec.out_req_syn_cnt);
      evt.setNote("attacker");
      reportEvent(evt);
   }
}

//////////////////////////////////
// Rules specific to DNS traffic
#define DNS_AMPLIF_THRESHOLD 10000

void check_new_rules_dns(const hosts_key_t &addr, const hosts_record_t &rec)
{
   const dns_data_t &dns_rec = *rec.dns_data;

   // Misused server
   if (dns_rec.out_rsp_overlimit_cnt > DNS_AMPLIF_THRESHOLD) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_DNSAMP);
      evt.addSrcPort(53).addSrcAddr(addr);
      evt.setScale(dns_rec.out_rsp_overlimit_cnt);
      evt.setNote("DNS amplification - misused server");
      reportEvent(evt);
   }

   // Victim
   if (dns_rec.in_rsp_overlimit_cnt > DNS_AMPLIF_THRESHOLD) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, UR_EVT_T_DNSAMP);
      evt.addDstPort(53).addDstAddr(addr);
      evt.setScale(dns_rec.in_rsp_overlimit_cnt);
      evt.setNote("DNS amplification - victim");
      reportEvent(evt);
   }
}
