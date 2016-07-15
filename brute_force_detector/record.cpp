/**
 * \file record.cpp
 * \brief Record classes and record list
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

#include "record.h"

// ************************************************************/
// ************************ SSH RECORD  ***********************/
// ************************************************************/

SSHRecord::SSHRecord(ip_addr_t dstIp, ur_time_t flowLastSeen)
{
    this->dstIp = dstIp;
    this->flowLastSeen = flowLastSeen;
}

bool SSHRecord::matchWithIncomingSignature(void *structure, Whitelist *wl)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*)(structure);
    uint32_t packets = st.packets;
    uint64_t bytes   = st.bytes;
    uint8_t  flags   = st.flags;

    uint8_t signatureFlags = 0b00011010; //SYN + ACK + PSH set

    signatureMatched = false;

    if((flags & signatureFlags) != signatureFlags)
        return false;

    if(packets > Config::getInstance().getSSHBFIncMaxPackets() || packets < Config::getInstance().getSSHBFIncMinPackets())
        return false;
    if(bytes > Config::getInstance().getSSHBFIncMaxBytes() || bytes < Config::getInstance().getSSHBFIncMinBytes())
        return false;

    if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
    {
        return false;
    }

    signatureMatched = true;
    return true;
}

bool SSHRecord::matchWithOutgoingSignature(void *structure, Whitelist *wl)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*)(structure);
    uint32_t packets = st.packets;
    uint64_t bytes   = st.bytes;
    uint8_t  flags   = st.flags;

    uint8_t signatureFlags = 0b00011010; //SYN + ACK + PSH set
    
    if((flags & signatureFlags) != signatureFlags)
        return false;
    
    if(packets > Config::getInstance().getSSHBFOutMaxPackets() || packets < Config::getInstance().getSSHBFOutMinPackets())
        return false;
    if(bytes > Config::getInstance().getSSHBFOutMaxBytes() || bytes < Config::getInstance().getSSHBFOutMinBytes())
        return false;

    if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swap src/dst ip/port
    {
        return false;
    }

    signatureMatched = true;
    return true;
}


// ************************************************************/
// ************************ RDP RECORD  ***********************/
// ************************************************************/

RDPRecord::RDPRecord(ip_addr_t dstIp, ur_time_t flowLastSeen)
{
    this->dstIp = dstIp;
    this->flowLastSeen = flowLastSeen;
}

bool RDPRecord::matchWithIncomingSignature(void *structure, Whitelist *wl)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*)(structure);
    uint32_t packets = st.packets;
    uint64_t bytes   = st.bytes;
    uint8_t  flags   = st.flags;

    signatureMatched = false;
	
    //win8 manual input
    uint8_t signatureFlagsWin8ManualCon = 0b00011110; //SYN + ACK + PSH + RST
    if((flags & signatureFlagsWin8ManualCon) == signatureFlagsWin8ManualCon)
    {   // s port, d port, packets, bytes, flags
        //  42315,   3389,       8,  1691,  30
        //  42345,   3389,       9,  1747,  30
        if(packets >= 7 && packets <= 11 && bytes >= 1500 && bytes <= 2000)
        {
            if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
            {
                return false;
            }
            signatureMatched = true;
            return true;        
        }
    }	
	
    //Ncrack/thc hydra to win8 unsuccessful connection
    uint8_t signatureFlagsWin8FailedCon = 0b00011010; //SYN + ACK + PSH
    if((flags & signatureFlagsWin8FailedCon) == signatureFlagsWin8FailedCon)
    {   // s port, d port, packets, bytes, flags
        //  37501,   3389,       3,   165,  26
        if(packets == 3 && ( bytes >= 100 && bytes <= 200))
        {
            if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
            {
                return false;
            }
            signatureMatched = true;
            return true;
        }
    }

    uint8_t signatureFlags = 0b00011010; //SYN + ACK + PSH	

    if((flags & signatureFlags) != signatureFlags)
        return false;

    if(packets > Config::getInstance().getRDPBFIncMaxPackets() || packets < Config::getInstance().getRDPBFIncMinPackets())
        return false;
    if(bytes > Config::getInstance().getRDPBFIncMaxBytes() || bytes < Config::getInstance().getRDPBFIncMinBytes())
        return false;

    if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
    {
        return false;
    }

    signatureMatched = true;
    return true;
}

bool RDPRecord::matchWithOutgoingSignature(void *structure, Whitelist *wl)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*)(structure);
    uint32_t packets = st.packets;
    uint64_t bytes   = st.bytes;
    uint8_t  flags   = st.flags;
    
    signatureMatched = false;
    
    //win8 manual input
    uint8_t signatureFlagsWin8ManualCon = 0b00011010; //SYN + ACK + PSH
    if((flags & signatureFlagsWin8ManualCon) == signatureFlagsWin8ManualCon)
    {   // s port, d port, packets, bytes, flags
        //   3389,  42320,       7,  1882,  26
        //   3389,  42303,       7,  1951,  26
        if(packets == 7 && bytes >= 1700 && bytes <= 2200)
        {
            if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swap src/dst ip/port
            {
                return false;
            }
            signatureMatched = true;
            return true;
        }
    }   
    
    //Ncrack/thc hydra to win8 unsuccessful connection
    uint8_t signatureFlagsWin8FailedCon = 0b00011010; //SYN + ACK + RST
    if((flags & signatureFlagsWin8FailedCon) == signatureFlagsWin8FailedCon)
    {   // s port, d port, packets, bytes, flags
        //   3389,  37639,       2,    92,  22
        if(packets == 2 && ( bytes > 80 && bytes < 120))
        {
            if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swap src/dst ip/port
            {
                return false;
            }
            signatureMatched = true;
            return true;
        }
    }
      
    uint8_t signatureFlags = 0b00011010; //SYN + ACK + PSH + RST   
    if((flags & signatureFlags) != signatureFlags)
        return false;
    
    if(packets > Config::getInstance().getRDPBFOutMaxPackets()  || packets < Config::getInstance().getRDPBFOutMinPackets())
        return false;
    if(bytes > Config::getInstance().getRDPBFOutMaxBytes() || bytes < Config::getInstance().getRDPBFOutMinBytes())
        return false;
    
    
    if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swap src/dst ip/port
    {
        return false;
    }

    signatureMatched = true;
    return true;    
}


// ************************************************************/
// ********************** TELNET RECORD  **********************/
// ************************************************************/

TELNETRecord::TELNETRecord(ip_addr_t dstIp, ur_time_t flowLastSeen)
{
    this->dstIp = dstIp;
    this->flowLastSeen = flowLastSeen;
}

bool TELNETRecord::matchWithIncomingSignature(void *structure, Whitelist *wl)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*)(structure);
    uint32_t packets = st.packets;
    uint64_t bytes   = st.bytes;
    uint8_t  flags   = st.flags;

    uint8_t signatureFlags = 0b00011010; //SYN + ACK + PSH set

    signatureMatched = false;

    if((flags & signatureFlags) != signatureFlags)
        return false;

    if(packets > Config::getInstance().getTELNETBFIncMaxPackets() || packets < Config::getInstance().getTELNETBFIncMinPackets())
        return false;
    if(bytes > Config::getInstance().getTELNETBFIncMaxBytes() || bytes < Config::getInstance().getTELNETBFIncMinBytes())
	    return false;

    if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
    {
        return false;
    }

    signatureMatched = true;
    return true;
}

bool TELNETRecord::matchWithOutgoingSignature(void *structure, Whitelist *wl)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*)(structure);
    uint32_t packets = st.packets;
    uint64_t bytes   = st.bytes;
    uint8_t  flags   = st.flags;
    
    uint8_t signatureFlags = 0b00011011; //SYN + ACK + PSH set + FIN

    signatureMatched = false;

    if((flags & signatureFlags) != signatureFlags)
        return false;
    
    TelnetServerProfile * TSPProfile = TSPMap.findProfile(st.srcIp);
    if(TSPProfile == NULL)
        TSPProfile = TSPMap.createProfile(st.srcIp, st.flowFirstSeen);
    
    TSPProfile->profileWithNewData(packets, bytes);
    
    if(packets < 6)
        return false;
    
    //for max range only
    if(TSPProfile->isProfiled())
    {
        if(packets > TSPProfile->getMaxPackets() || bytes > TSPProfile->getMaxBytes())
            return false;
    }
    else
        return false;
    
    signatureMatched = true;
    return true;       
}


