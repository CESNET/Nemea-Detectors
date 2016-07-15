/**
 * \file brute_force_detector.h
 * \author Vaclav Pacholik <xpacho03@stud.fit.vutbr.cz || vaclavpacholik@gmail.com>
 * \date 2014
 */

/*
 * Copyright (C) 2014 CESNET
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

#ifndef BRUTE_FORCE_DETECTOR_H
#define BRUTE_FORCE_DETECTOR_H

#include <iostream>
#include <unirec/ipaddr.h> //ip_addr_t

const static uint8_t  TCP_PROTOCOL_NUM = 6;
const static uint16_t TCP_SSH_PORT     = 22;
const static uint16_t TCP_TELNET_PORT  = 23;
const static uint16_t TCP_RDP_PORT     = 3389;

const static uint8_t FLOW_INCOMING_DIRECTION = 1;
const static uint8_t FLOW_OUTGOING_DIRECTION = 2;


//ip address comparison for std::map and std::set
struct cmpByIpAddr {
    bool operator ()(const ip_addr_t& a, const ip_addr_t& b) const {
	    return (memcmp((char*)&a, (char*)&b, sizeof(ip_addr_t)) < 0);
    }
};

struct thousandsSeparator : std::numpunct<char> {
   // use dot as separator
   char do_thousands_sep() const { return '.'; }

   // digits are grouped by 3 digits each
   std::string do_grouping() const { return "\3"; }
};

#endif
