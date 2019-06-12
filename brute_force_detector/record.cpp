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

    signatureMatched = false;

    if((st.flags & SSHRecord::signatureFlags) != SSHRecord::signatureFlags)
	{
    	return false;
	}

    if(st.packets > Config::getInstance().getSSHIncMaxPackets() || st.packets <
																			 Config::getInstance().getSSHIncMinPackets())
	{
    	return false;
	}

    if(st.bytes > Config::getInstance().getSSHIncMaxBytes() || st.bytes < Config::getInstance().getSSHIncMinBytes())
	{
    	return false;
	}

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

    if((st.flags & SSHRecord::signatureFlags) != SSHRecord::signatureFlags)
	{
    	return false;
	}
    
    if(st.packets > Config::getInstance().getSSHOutMaxPackets() || st.packets <
																			 Config::getInstance().getSSHOutMinPackets())
	{
    	return false;
	}

    if(st.bytes > Config::getInstance().getSSHOutMaxBytes() || st.bytes < Config::getInstance().getSSHOutMinBytes())
	{
    	return false;
	}

    if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swapped src/dst ip and port
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

    signatureMatched = false;
	
    // Win8 manual input

    if((st.flags & RDPRecord::signatureFlagsWin8ManualCon) == RDPRecord::signatureFlagsWin8ManualCon)
    {
    	// s port, d port, packets, bytes, flags
        //  42315,   3389,       8,  1691,  30
        //  42345,   3389,       9,  1747,  30

        if(st.packets >= 7 && st.packets <= 11 && st.bytes >= 1500 && st.bytes <= 2000)
        {
            if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
            {
                return false;
            }
            signatureMatched = true;
            return true;        
        }
    }	
	
    // Ncrack/thc hydra to win8 unsuccessful connection

    if((st.flags & RDPRecord::signatureFlagsWin8FailedCon) == RDPRecord::signatureFlagsWin8FailedCon)
    {
    	// s port, d port, packets, bytes, flags
        //  37501,   3389,       3,   165,  26

        if(st.packets == 3 && ( st.bytes >= 100 && st.bytes <= 200))
        {
            if(wl->isWhitelisted(&st.srcIp, &st.dstIp, st.srcPort, st.dstPort))
            {
                return false;
            }
            signatureMatched = true;
            return true;
        }
    }


    if((st.flags & RDPRecord::signatureFlags) != RDPRecord::signatureFlags)
	{
    	return false;
	}

    if(st.packets > Config::getInstance().getRDPIncMaxPackets() || st.packets <
																			 Config::getInstance().getRDPIncMinPackets())
	{
    	return false;
	}
    if(st.bytes > Config::getInstance().getRDPIncMaxBytes() || st.bytes < Config::getInstance().getRDPIncMinBytes())
	{
    	return false;
	}

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
    
    signatureMatched = false;
    
    // Win8 manual input

    if((st.flags & RDPRecord::signatureFlagsWin8ManualCon) == RDPRecord::signatureFlagsWin8ManualCon)
    {
    	// s port, d port, packets, bytes, flags
        //   3389,  42320,       7,  1882,  26
        //   3389,  42303,       7,  1951,  26

        if(st.packets == 7 && st.bytes >= 1700 && st.bytes <= 2200)
        {
            if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swapped src/dst ip and port
            {
                return false;
            }
            signatureMatched = true;
            return true;
        }
    }   
    
    // Ncrack/thc hydra to win8 unsuccessful connection

    if((st.flags & RDPRecord::signatureFlagsWin8FailedCon) == RDPRecord::signatureFlagsWin8FailedCon)
    {
    	// s port, d port, packets, bytes, flags
        //   3389,  37639,       2,    92,  22

        if(st.packets == 2 && ( st.bytes > 80 && st.bytes < 120))
        {
            if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swapped src/dst ip and port
            {
                return false;
            }
            signatureMatched = true;
            return true;
        }
    }
      
    if((st.flags & RDPRecord::signatureFlags) != RDPRecord::signatureFlags)
	{
    	return false;
	}
    
    if(st.packets > Config::getInstance().getRDPOutMaxPackets()  || st.packets <
																			  Config::getInstance().getRDPOutMinPackets())
	{
    	return false;
	}
    if(st.bytes > Config::getInstance().getRDPOutMaxBytes() || st.bytes < Config::getInstance().getRDPOutMinBytes())
	{
    	return false;
	}
    
    
    if(wl->isWhitelisted(&st.dstIp, &st.srcIp, st.dstPort, st.srcPort)) //swapped src/dst ip and port
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

    signatureMatched = false;

    if((st.flags & TELNETRecord::signatureFlags) != TELNETRecord::signatureFlags)
	{
    	return false;
	}

    if(st.packets > Config::getInstance().getTELNETIncMaxPackets() || st.packets <
																				Config::getInstance().getTELNETIncMinPackets())
	{
    	return false;
	}
    if(st.bytes > Config::getInstance().getTELNETIncMaxBytes() || st.bytes <
																			Config::getInstance().getTELNETIncMinBytes())
	{
    	return false;
	}

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

    signatureMatched = false;

    if((st.flags & TELNETRecord::signatureFlagsFin) != TELNETRecord::signatureFlagsFin)
	{
        return false;
	}

    TelnetServerProfile * TSPProfile = TSPMap.findProfile(st.srcIp);
    if(TSPProfile == nullptr)
	{
        TSPProfile = TSPMap.createProfile(st.srcIp, st.flowFirstSeen);
	}

    TSPProfile->profileWithNewData(st.packets, st.bytes);
    
    if(st.packets < 6)
    {
        return false;
	}
    
    //for max range only
    if(TSPProfile->isProfiled())
    {
        if(st.packets > TSPProfile->getMaxPackets() || st.bytes > TSPProfile->getMaxBytes())
		{
            return false;
		}
    }
    else
	{
        return false;
	}

    signatureMatched = true;
    return true;       
}


