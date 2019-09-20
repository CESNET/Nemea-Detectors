#include <utility>

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

const static uint8_t TCP_PROTOCOL_NUM = 6;
const static uint16_t TCP_SSH_PORT = 22;
const static uint16_t TCP_TELNET_PORT = 23;
const static uint16_t TCP_RDP_PORT = 3389;

const static uint8_t FLOW_INCOMING_DIRECTION = 1;
const static uint8_t FLOW_OUTGOING_DIRECTION = 2;

static const uint16_t TELNET_OUTGOING_MIN_PACKETS = 6;


void printFlowPercent(uint64_t b, uint64_t p, const std::string &comment = "");

//ip address comparison for std::map and std::set
struct cmpByIpAddr {
    bool operator()(const ip_addr_t &a, const ip_addr_t &b) const {
        return (memcmp((char *) &a, (char *) &b, sizeof(ip_addr_t)) < 0);
    }
};

struct thousandsSeparator : std::numpunct<char> {
    // use dot as separator
    char do_thousands_sep() const override { return '.'; }

    // digits are grouped by 3 digits each
    std::string do_grouping() const override { return "\3"; }
};


class logInfo {
public:

    explicit logInfo(std::string _protocolName) : protocolName(std::move(_protocolName)),
                                                  flows(0),
                                                  incomingFlows(0),
                                                  outgoingFlows(0),
                                                  matchedFlows(0),
                                                  matchedIncomingFlows(0),
                                                  matchedOutgoingFlows(0) {};

    void printLogInfo() {
        std::cout << this->protocolName << std::endl;
        std::cout.imbue(std::locale(std::locale(), new thousandsSeparator));
        std::cout << "  Total Flows: " << this->flows << std::endl;
        std::cout << "  Incoming Flows: " << this->incomingFlows;
        printFlowPercent(this->flows, this->incomingFlows);
        std::cout << std::endl;
        std::cout << "  Outgoing Flows: " << this->outgoingFlows;
        printFlowPercent(this->flows, this->outgoingFlows);
        std::cout << std::endl;
        std::cout << "  Matched Flows: " << this->matchedFlows;
        printFlowPercent(this->flows, this->matchedFlows);
        std::cout << std::endl;
        std::cout << "  Matched Incoming Flows: " << this->matchedIncomingFlows;
        printFlowPercent(this->matchedFlows, this->matchedIncomingFlows, " from matched");
        printFlowPercent(this->flows, this->matchedIncomingFlows, " from incoming");
        std::cout << std::endl;
        std::cout << "  Matched Outgoing Flows: " << this->matchedOutgoingFlows;
        printFlowPercent(this->matchedFlows, this->matchedOutgoingFlows, " from matched");
        printFlowPercent(this->flows, this->matchedOutgoingFlows, " from outgoing");
        std::cout << std::endl;
    }

    std::string protocolName;
    uint64_t flows;
    uint64_t incomingFlows;
    uint64_t outgoingFlows;
    uint64_t matchedFlows;
    uint64_t matchedIncomingFlows;
    uint64_t matchedOutgoingFlows;
};

#endif
