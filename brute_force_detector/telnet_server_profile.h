/**
 * \file telnet_server_profile.h
 * \brief TODO
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

#ifndef TELNET_SERVER_PROFILE_H
#define TELNET_SERVER_PROFILE_H

#include "brute_force_detector.h"
#include <unirec/ipaddr.h> //ip_addr_t
#include <unirec/unirec.h> //ur_time_t
#include <map>
#include <list>
#include <vector>
#include <algorithm>
#include <iterator>

const static uint16_t TSPArraySize = 15;
const static uint8_t profileEvery = 10;

class TelnetServerProfile {
public:
    TelnetServerProfile(ur_time_t firstSeen, ip_addr_t ip) : timeOfCreation(firstSeen), serverIp(ip), profiled(false),
                                                             listSize(0), maxBytes(0), maxPackets(0) {}

    bool isProfiled() const { return profiled; }

    uint32_t getMaxPackets() const { return maxPackets; }

    uint64_t getMaxBytes() const { return maxBytes; }

    void profileWithNewData(uint32_t packets, uint64_t bytes);



private:
    ur_time_t timeOfCreation;
    ip_addr_t serverIp;
    bool profiled;

    std::list<uint64_t> byteList;
    std::list<uint32_t> packetList;
    uint16_t listSize;

    uint64_t maxBytes;
    uint32_t maxPackets;

    void countNewMaxValues();
};

class TelnetServerProfileMap {
public:
    TelnetServerProfileMap() {};

    TelnetServerProfile *createProfile(ip_addr_t ip, ur_time_t firstSeen);

    TelnetServerProfile *findProfile(ip_addr_t &hostIp) const;

private:
    std::map<ip_addr_t, TelnetServerProfile *, cmpByIpAddr> TSPMap;
};

#endif
