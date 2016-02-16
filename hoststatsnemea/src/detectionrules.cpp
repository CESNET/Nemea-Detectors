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

#ifndef MAX
#define MAX(a, b) (((a) >= (b))?(a):(b))
#endif

using namespace std;

struct general_detector_config general_conf;

void check_new_rules(const hosts_key_t &addr, const hosts_record_t &rec)
{
   // horizontal SYN scan (scanning address)
   uint64_t est_out_req_syn_cnt = rec.out_req_syn_cnt + (rec.out_all_syn_cnt
           - (rec.out_req_syn_cnt + rec.out_rsp_syn_cnt)) * general_conf.dos_req_rsp_est_ratio;
   uint64_t est_out_req_ack_cnt = rec.out_req_ack_cnt + (rec.out_all_ack_cnt
           - (rec.out_req_ack_cnt + rec.out_rsp_ack_cnt)) * general_conf.dos_req_rsp_est_ratio;
   uint64_t est_in_rsp_ack_cnt = rec.in_rsp_ack_cnt + (rec.in_all_ack_cnt
           - (rec.in_req_ack_cnt + rec.in_rsp_ack_cnt)) * general_conf.dos_rsp_req_est_ratio;

   if (est_out_req_syn_cnt > general_conf.syn_scan_threshold &&
       est_out_req_syn_cnt > general_conf.syn_scan_syn_to_ack_ratio * est_out_req_ack_cnt && // most of outgoing flows are SYN-only (no ACKs)
       est_out_req_syn_cnt > general_conf.syn_scan_request_to_response_ratio * est_in_rsp_ack_cnt && // most targets don't answer with ACK
       rec.out_req_uniqueips >= general_conf.syn_scan_ips && // a lot of different destinations
       rec.out_req_syn_cnt > rec.out_all_flows / 2 && // it is more than half of total outgoing traffic of this address
       rec.out_req_syn_cnt > 10 * rec.in_all_syn_cnt) // there is not much incoming connections
                                                    //  - this was added to filter out p2p communication
   {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_PORTSCAN_H);
      evt.addProto(TCP).addSrcAddr(addr);
      evt.setScale(rec.out_all_syn_cnt - rec.out_all_ack_cnt);
      evt.setNote("horizontal SYN scan");
      reportEvent(evt);
   }

   // DoS/DDoS (victim)
   uint64_t est_out_rsp_flows = rec.out_rsp_flows + (rec.out_all_flows
           - (rec.out_req_flows + rec.out_rsp_flows)) * general_conf.dos_rsp_req_est_ratio;
   uint64_t est_in_req_flows = rec.in_req_flows + (rec.in_all_flows
           - (rec.in_req_flows + rec.in_rsp_flows)) * general_conf.dos_req_rsp_est_ratio;
   uint64_t est_in_req_packets = rec.in_req_packets + (rec.in_all_packets
           - (rec.in_req_packets + rec.in_rsp_packets)) * general_conf.dos_req_rsp_est_ratio;

   bool ddos_tcp_victim = false;
   if (( //TCP (syn flood)
      rec.in_all_syn_cnt > general_conf.dos_victim_connections_synflood &&
      rec.in_all_syn_cnt > 2 * rec.in_all_ack_cnt &&
      rec.in_all_packets < general_conf.dos_victim_packet_ratio * rec.in_all_flows &&
      (ddos_tcp_victim = true)
   ) || ( // UDP & others...
      est_in_req_flows > general_conf.dos_victim_connections_others && // number of connection requests (if it's less than 128k (plus some margin) it may be vertical scan)
      est_in_req_packets < general_conf.dos_victim_packet_ratio * est_in_req_flows && // packets per flow < 2
      est_out_rsp_flows < est_in_req_flows / 2) // less than half of requests are replied
       // && est_out_rsp_flows > est_in_req_flows * general_conf.dos_min_rsp_ratio) // more then 2% of requests are replied
   ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_DOS);
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
      if (rec.in_all_flows < 2 * rec.in_all_uniqueips) {
         evt.note += " (probably spoofed)";
      }

      reportEvent(evt);
   }

   // DoS/DDoS (attacker)
   uint64_t est_out_req_flows = rec.out_req_flows + (rec.out_all_flows
           - (rec.out_req_flows + rec.out_rsp_flows)) * general_conf.dos_req_rsp_est_ratio;
   uint64_t est_out_req_packets = rec.out_req_packets + (rec.out_all_packets
           - (rec.out_req_packets + rec.out_rsp_packets)) * general_conf.dos_req_rsp_est_ratio;
   uint64_t est_in_rsp_flows = rec.in_rsp_flows + (rec.in_all_flows
           - (rec.in_req_flows + rec.in_rsp_flows)) * general_conf.dos_rsp_req_est_ratio;

   bool ddos_tcp_attacker = false;
   if (( // TCP (syn flood)
      rec.out_all_flows / MAX(rec.out_all_uniqueips, 1U) >= general_conf.dos_attacker_connections_synflood &&
      rec.out_all_packets < general_conf.dos_attacker_packet_ratio * rec.out_all_flows &&
      rec.out_all_syn_cnt > 2 * rec.out_all_ack_cnt &&
      (ddos_tcp_attacker = true)
   ) || ( // UDP & others...
      est_out_req_flows / MAX(rec.out_all_uniqueips, 1U) >= general_conf.dos_attacker_connections_others && // number of connection requests per target
      est_out_req_packets < general_conf.dos_attacker_packet_ratio * est_out_req_flows && // packets per flow < 2
      est_in_rsp_flows < est_out_req_flows / 2) // less than half of requests are replied
      // && est_in_rsp_flows > est_out_req_flows * general_conf.dos_min_rsp_ratio) // more then 2% of requests are replied
   ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_DOS);
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

struct ssh_detector_config ssh_conf;

void check_new_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec)
{
   const ssh_data_t &ssh_rec = *rec.ssh_data;

   // SSH bruteforce (output = address under attack)
   if (( // responses
         // average response size must be in between
         // general_conf.bruteforce_data_min_packet_ratio and general_conf.bruteforce_data_max_packet_ratio
         // and number of responses must be at least general_conf.bruteforce_data_threshold
         ssh_rec.out_rsp_packets >= ssh_conf.bruteforce_data_min_packet_ratio * ssh_rec.out_rsp_syn_cnt &&
         ssh_rec.out_rsp_packets <= ssh_conf.bruteforce_data_max_packet_ratio * ssh_rec.out_rsp_syn_cnt &&
         ssh_rec.out_rsp_syn_cnt > ssh_conf.bruteforce_data_threshold
      )
      && ( // requests
         // average  request size must be in between
         // general_conf.bruteforce_req_min_packet_ratio and general_conf.bruteforce_req_max_packet_ratio
         // and number of responses must be at least general_conf.bruteforce_req_threshold
         ssh_rec.in_req_packets >= ssh_conf.bruteforce_req_min_packet_ratio * ssh_rec.in_req_syn_cnt &&
         ssh_rec.in_req_packets <= ssh_conf.bruteforce_req_max_packet_ratio * ssh_rec.in_req_syn_cnt &&
         ssh_rec.in_req_syn_cnt > ssh_conf.bruteforce_req_threshold
      )
      && ( // ratio
         // number of incoming requests on SSH server must be
         // general_conf.bruteforce_server_ratio-times larger than the number of outgoing
         // requests
         ssh_rec.in_req_syn_cnt > ssh_conf.bruteforce_server_ratio * ssh_rec.out_req_syn_cnt
      )
      && (
         // at least general_conf.bruteforce_ips_ratio responses to same address
         ssh_rec.out_rsp_syn_cnt > ssh_conf.bruteforce_ips_ratio * ssh_rec.out_all_uniqueips)
      ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addDstAddr(addr);
      evt.setScale(ssh_rec.in_req_syn_cnt);
      evt.setNote("victim");
      reportEvent(evt);
   }

   // SSH bruteforce (output = attacking address)
   if (( // requests
      ssh_rec.out_req_packets > ssh_conf.bruteforce_req_min_packet_ratio * ssh_rec.out_req_syn_cnt &&
      ssh_rec.out_req_packets < ssh_conf.bruteforce_req_max_packet_ratio * ssh_rec.out_req_syn_cnt &&
      ssh_rec.out_req_syn_cnt > ssh_conf.bruteforce_req_threshold
   )
   && ( // responses
      ssh_rec.in_rsp_packets > ssh_conf.bruteforce_data_min_packet_ratio * ssh_rec.in_rsp_syn_cnt &&
      ssh_rec.in_rsp_packets < ssh_conf.bruteforce_data_max_packet_ratio * ssh_rec.in_rsp_syn_cnt &&
      ssh_rec.in_rsp_syn_cnt > ssh_conf.bruteforce_data_threshold
   )
   && (
      ssh_rec.in_req_syn_cnt < ssh_conf.bruteforce_server_ratio * ssh_rec.out_req_syn_cnt
   )
   && (( // at least 20 requests to the same address and less than
         // general_conf.bruteforce_ips password-guessing addresses
         ssh_rec.out_req_syn_cnt > ssh_conf.bruteforce_ips_ratio * ssh_rec.out_all_uniqueips &&
         ssh_rec.out_all_uniqueips < ssh_conf.bruteforce_ips
      ) || (
         // at least 10 requests to the same address and more than
         // general_conf.bruteforce_ips password-guessing addresses
         ssh_rec.out_req_syn_cnt > 0.5 * ssh_conf.bruteforce_ips_ratio * ssh_rec.out_all_uniqueips &&
         ssh_rec.out_all_uniqueips >= ssh_conf.bruteforce_ips
      ))
   ) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_BRUTEFORCE);
      evt.addProto(TCP).addDstPort(22).addSrcAddr(addr);
      evt.setScale(ssh_rec.out_req_syn_cnt);
      evt.setNote("attacker");
      reportEvent(evt);
   }
}

//////////////////////////////////
// Rules specific to DNS traffic

struct dns_detector_config dns_conf;

void check_new_rules_dns(const hosts_key_t &addr, const hosts_record_t &rec)
{
   const dns_data_t &dns_rec = *rec.dns_data;

   // Misused server
   if (dns_rec.out_rsp_overlimit_cnt > dns_conf.dns_amplif_threshold) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_DNSAMP);
      evt.addSrcPort(53).addSrcAddr(addr);
      evt.setScale(dns_rec.out_rsp_overlimit_cnt);
      evt.setNote("DNS amplification - misused server");
      reportEvent(evt);
   }

   // Victim
   if (dns_rec.in_rsp_overlimit_cnt > dns_conf.dns_amplif_threshold) {
      Event evt(rec.first_rec_ts, rec.last_rec_ts, EVT_T_DNSAMP);
      evt.addDstPort(53).addDstAddr(addr);
      evt.setScale(dns_rec.in_rsp_overlimit_cnt);
      evt.setNote("DNS amplification - victim");
      reportEvent(evt);
   }
}
