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

#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#include "hoststats.h"

#define DIR_FLAG_REQ   0x8   //Request
#define DIR_FLAG_RSP   0x4   //Response
#define DIR_FLAG_SF    0x2   //Single flow
#define DIR_FLAG_NRC   0x1   //Not recognized

#define TCP_FIN        0x1   //Finish bit flag
#define TCP_SYN        0x2   //Synchronize bit flag
#define TCP_RST        0x4   //Reset bit flag
#define TCP_PSH        0x8   //Push bit flag
#define TCP_ACK        0x10   //Acknowledgement bit flag
#define TCP_URG        0x20   //Urgent bit flag

/**
 * \brief Struct containing general detector configuration.
 */
struct general_detector_config {
   float syn_scan_threshold;
   float syn_scan_syn_to_ack_ratio;
   float syn_scan_request_to_response_ratio;
   float syn_scan_ips;

   uint32_t dos_victim_connections_synflood;
   uint32_t dos_victim_connections_others;
   float dos_victim_packet_ratio;

   uint32_t dos_attacker_connections_synflood;
   uint32_t dos_attacker_connections_others;
   float dos_attacker_packet_ratio;

   float dos_req_rsp_est_ratio;
   float dos_rsp_req_est_ratio;

   float dos_min_rsp_ratio;

   general_detector_config() {
      syn_scan_threshold = 200;
      syn_scan_syn_to_ack_ratio = 20;
      syn_scan_request_to_response_ratio = 5;
      syn_scan_ips = 200;

      dos_victim_connections_synflood = 270000;
      dos_victim_connections_others = 1000000;
      dos_victim_packet_ratio = 2;

      dos_attacker_connections_synflood = 270000;
      dos_attacker_connections_others = 1000000;
      dos_attacker_packet_ratio = 2;

      dos_req_rsp_est_ratio = 4.0 / 5.0;
      dos_rsp_req_est_ratio = 1.0 - dos_req_rsp_est_ratio;

      dos_min_rsp_ratio = 0.02;
   }
};

/**
 * \brief Struct containing ssh detector configuration.
 */
struct ssh_detector_config {
   float scan_threshold;
   float scan_flag_ratio;
   float scan_packet_ratio;
   float scan_ip_ratio;

   float bruteforce_out_threshold;
   float bruteforce_ips;
   float bruteforce_ips_ratio;
   float bruteforce_req_threshold;
   float bruteforce_req_min_packet_ratio;
   float bruteforce_req_max_packet_ratio;
   float bruteforce_data_threshold;
   float bruteforce_data_min_packet_ratio;
   float bruteforce_data_max_packet_ratio;
   float bruteforce_server_ratio;

   ssh_detector_config() {
      scan_threshold = 100;
      scan_flag_ratio = 5;
      scan_packet_ratio = 5;
      scan_ip_ratio = 0.5;

      bruteforce_out_threshold = 10;
      bruteforce_ips = 5;
      bruteforce_ips_ratio = 20;
      bruteforce_req_threshold = 60;
      bruteforce_req_min_packet_ratio = 5;
      bruteforce_req_max_packet_ratio = 20;
      bruteforce_data_threshold = bruteforce_req_threshold * 0.5;
      bruteforce_data_min_packet_ratio = 10;
      bruteforce_data_max_packet_ratio = 25;
      bruteforce_server_ratio = 3;
   }
};

/**
 * \brief Struct containing dns detector configuration.
 */
struct dns_detector_config {
   float dns_amplif_threshold;

   dns_detector_config() {
      dns_amplif_threshold = 10000;
   }
};


// General detector
void check_new_rules(const hosts_key_t &addr, const hosts_record_t &rec);
extern struct general_detector_config general_conf;

// SSH detector
void check_new_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec);
extern struct ssh_detector_config ssh_conf;

// DNS detector
void check_new_rules_dns(const hosts_key_t &addr, const hosts_record_t &rec);
extern struct dns_detector_config dns_conf;

#endif
