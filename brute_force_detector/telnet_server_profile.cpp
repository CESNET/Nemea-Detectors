/**
 * \file telnet_server_profile.cpp
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

#include "telnet_server_profile.h"
using namespace std;
#include <iostream>

void TelnetServerProfile::profileWithNewData(uint32_t packets, uint64_t bytes)
{
    //at least 6 packets from server to client
    //1. syn+ack
    //2. supported configuration
    //3. username request //or only password
    //4. ack username
    //4/5. password request
    //4/6. ack password
    //5/7. information about successfull/failed login
    //6/8. FIN packet
    if(packets < 6)
        return;
    
    static uint16_t profileCounter = 0;
    profileCounter++;
    
    if(listSize >= TSPArraySize)
    {
        byteList.pop_front();
        packetList.pop_front();
        listSize--;
    }
    
    byteList.push_back(bytes);
    packetList.push_back(packets);
    listSize++;
    
    if(!profiled && listSize == TSPArraySize)
    {
        countNewMaxValues();
        profiled = true;
    }
    else if(profiled && profileCounter == profileEvery)
    {
        countNewMaxValues();
        profileCounter = 0;
    } 
}

void TelnetServerProfile::countNewMaxValues()
{
    size_t n = packetList.size() / 2;
    
    vector<uint32_t> packetVector;
    vector<uint64_t> byteVector;  
    
    copy(packetList.begin(), packetList.end(), back_inserter(packetVector));
    copy(byteList.begin(),   byteList.end(),   back_inserter(byteVector));
    
    //median
    nth_element(byteVector.begin(),   byteVector.begin() + n,   byteVector.end());
    nth_element(packetVector.begin(), packetVector.begin() + n, packetVector.end());
    
    maxPackets = packetVector[n] + 5;
    maxBytes   = byteVector[n] + 500;
    
    //char *c = new char[55];
    //ip_to_str(&serverIp,c);
    //std::cout<<"Profilovano "<<c<<": "<<maxPackets<<" "<<maxBytes<<std::endl; ///delete c;
}

TelnetServerProfile * TelnetServerProfileMap::createProfile(ip_addr_t ip, ur_time_t firstSeen)
{
    TelnetServerProfile *TSP;
    
    TSP = new TelnetServerProfile(firstSeen, ip);
    TSPMap.insert(std::pair<ip_addr_t, TelnetServerProfile*>(ip, TSP));
    
    return TSP;
}

TelnetServerProfile * TelnetServerProfileMap::findProfile(ip_addr_t & hostIp) const
{
    auto it = TSPMap.find(hostIp);
    if(it == TSPMap.end())
        return nullptr;
    
    return it->second;
}
