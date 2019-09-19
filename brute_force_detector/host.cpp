/**
 * \file host.cpp
 * \brief Class for every supported host and hostmap
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

#include "host.h"

// ************************************************************/
// ************************* SSH HOST *************************/
// ************************************************************/
bool SSHHost::addRecord(SSHRecord *record, void *structure, uint8_t direction)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*) (structure);

	// ignore port-scans
    if(isFlowScan(&st.packets, &st.flags))
	{
    	return false;
	}
    else if(st.packets == 1 && st.flags == 0b00010000) // skip ack only packet
	{
    	return false;
	}
    else if(st.packets == 4 && st.flags == 0b00000010) // 4 packet SYN request
	{
    	return false;
	}
    else
    {
        timeOfLastReceivedRecord = st.flowLastSeen;
        if(direction == FLOW_INCOMING_DIRECTION)
		{
        	recordListIncoming.addRecord(record, isReported());
		}
        else
		{
        	recordListOutgoing.addRecord(record, isReported());
		}

		return true;
    }
}


SSHHost::ATTACK_STATE SSHHost::checkForAttack(ur_time_t actualTime)
{
    uint16_t incomingMatched = recordListIncoming.getActualMatchedFlows();
    uint16_t outgoingMatched = recordListOutgoing.getActualMatchedFlows();

    if(!isReported())
    {
    	// no attack yet
        uint16_t incomingListSize = recordListIncoming.getActualListSize();
        uint16_t outgoingListSize = recordListOutgoing.getActualListSize();


        // Number of records in list is lower than BottomSize (50 by default)
        if (std::max(incomingListSize, outgoingListSize) <= Config::getInstance().getSSHListBottomSize())
        {
            if(std::max(incomingMatched, outgoingMatched) >= Config::getInstance().getSSHListThreshold())
            {
                // crossed threshold, new attack detected
				recordListIncoming.initTotalTargetsSet();
				recordListOutgoing.initTotalTargetsSet();
                return SSHHost::REPORT_NEW_ATTACK;
            }
            else
			{
				cout << std::max(incomingMatched, outgoingMatched) << "< bottomThreshold" << "\n"; // DEBUG

				return SSHHost::NO_ATTACK;
            }
        }
        else
		{
			// Number of records is between bottom size and max list size per protocol

			double topMatchedRatio = std::max((double)incomingMatched/incomingListSize, (double)outgoingMatched/outgoingListSize);

            if(topMatchedRatio >= Config::getInstance().getGlobalMatchedFlowRatio())
            {
                // crossed threshold, new attack detected
				recordListIncoming.initTotalTargetsSet();
				recordListOutgoing.initTotalTargetsSet();
                return SSHHost::REPORT_NEW_ATTACK;
            }
            else
			{
				// cout << incomingMatched << "/" << incomingListSize << "\n";
				// cout << outgoingMatched << "/" << outgoingListSize	 << "\n";
				cout << topMatchedRatio << " < ratio" << "\n"; // DEBUG
                return SSHHost::NO_ATTACK;

			}
        }
    }
    else // isReported
    {
    	// host is attacking, wait for timeout to report again
        if(!canReportAgain(actualTime))
		{
        	return SSHHost::ATTACK_REPORT_WAIT;
		}
        else
        {
            uint32_t incomingMatchedNew = recordListIncoming.getMatchedFlowsSinceLastReport();
			uint32_t incomingTotalNew  = recordListIncoming.getTotalFlowsSinceLastReport();

			uint32_t outgoingMatchedNew = recordListOutgoing.getMatchedFlowsSinceLastReport();
			uint32_t outgoingTotalNew  = recordListOutgoing.getTotalFlowsSinceLastReport();

			if(incomingMatched == 0 && incomingMatchedNew == 0 &&
               outgoingMatched == 0 && outgoingMatchedNew == 0)
			{
				return SSHHost::END_OF_ATTACK;
			}

			auto keepTrackingHostRatio = Config::getInstance().getGlobalAttackMinRatioToKeepTrackingHost();

			// avoids div by zero
			auto incomingMatchedNewRatio = (incomingTotalNew == 0 ? 0 : (double)incomingMatchedNew / incomingTotalNew);
			auto outgoingMatchedNewRatio = (outgoingTotalNew == 0 ? 0 : (double)outgoingMatchedNew / outgoingTotalNew);

			if (std::max(incomingMatchedNewRatio, outgoingMatchedNewRatio) < keepTrackingHostRatio)
            {
                if(std::max(incomingMatchedNew, outgoingMatchedNew) >= Config::getInstance().getGlobalAttackMinEvToReport())
				{
                	return SSHHost::REPORT_END_OF_ATTACK;
				}
                else
				{
                	return SSHHost::END_OF_ATTACK;
				}
            }

            if(std::max(incomingMatchedNew, outgoingMatchedNew) >= Config::getInstance().getGlobalAttackMinEvToReport())
			{
            	return SSHHost::REPORT_ATTACK;
			}
            else
			{
            	return SSHHost::ATTACK_MIN_EVENTS_WAIT;
			}
        }
    }
}

// ************************************************************/
// ************************* RDP HOST *************************/
// ************************************************************/
bool RDPHost::addRecord(RDPRecord *record, void *structure, uint8_t direction)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*) (structure);

    // ignore port-scans
    if(isFlowScan(&st.packets, &st.flags))
	{
    	return false;
	}
    else
    {
        timeOfLastReceivedRecord = st.flowLastSeen;
        if(direction == FLOW_INCOMING_DIRECTION)
		{
        	recordListIncoming.addRecord(record, isReported());
		}
        else
		{
        	recordListOutgoing.addRecord(record, isReported());
		}
        return true;
    }
}

RDPHost::ATTACK_STATE RDPHost::checkForAttack(ur_time_t actualTime)
{
    uint16_t incomingMatched = recordListIncoming.getActualMatchedFlows();
    uint16_t outgoingMatched = recordListOutgoing.getActualMatchedFlows();

    if(!isReported())
    {
    	// no attack yet
        uint16_t incomingListSize = recordListIncoming.getActualListSize();
        uint16_t outgoingListSize = recordListOutgoing.getActualListSize();

        if (std::max(incomingListSize, outgoingListSize) <= Config::getInstance().getRDPListBottomSize())
        {

            if(std::max(incomingMatched, outgoingMatched) >= Config::getInstance().getRDPListThreshold())
            {
                // crossed threshold, new attack detected
				recordListIncoming.initTotalTargetsSet();
				recordListOutgoing.initTotalTargetsSet();
                return RDPHost::REPORT_NEW_ATTACK;
            }
            else
			{
				return RDPHost::NO_ATTACK;
            }
        }
        else
		{
        	// Number of records is between bottom size and max size

			auto topMatchedRatio = std::max((double)incomingMatched/incomingListSize, (double)outgoingMatched/outgoingListSize);

			if(topMatchedRatio >= Config::getInstance().getGlobalMatchedFlowRatio())
            {
                // crossed threshold, new attack detected
				recordListIncoming.initTotalTargetsSet();
				recordListOutgoing.initTotalTargetsSet();
                return RDPHost::REPORT_NEW_ATTACK;
            }
            else
			{
                return RDPHost::NO_ATTACK;
            }
        }
    }
    else // isReported
    {
    	// host is attacking, wait for timeout to report again
        if(!canReportAgain(actualTime))
		{
        	return RDPHost::ATTACK_REPORT_WAIT;
		}
        else
        {
            uint32_t incomingMatchedNew = recordListIncoming.getMatchedFlowsSinceLastReport();
            uint32_t incomingTotalNew  = recordListIncoming.getTotalFlowsSinceLastReport();

            uint32_t outgoingMatchedNew = recordListOutgoing.getMatchedFlowsSinceLastReport();
            uint32_t outgoingTotalNew  = recordListOutgoing.getTotalFlowsSinceLastReport();

            if(incomingMatched == 0 && incomingMatchedNew == 0 &&
               outgoingMatched == 0 && outgoingMatchedNew == 0)
			{
            	return RDPHost::END_OF_ATTACK;
			}

            auto keepTrackingHostRatio = Config::getInstance().getGlobalAttackMinRatioToKeepTrackingHost();

            // avoids div by zero
			auto incomingMatchedNewRatio = (incomingTotalNew == 0 ? 0 : (double)incomingMatchedNew / incomingTotalNew);
			auto outgoingMatchedNewRatio = (outgoingTotalNew == 0 ? 0 : (double)outgoingMatchedNew / outgoingTotalNew);

			if (std::max(incomingMatchedNewRatio, outgoingMatchedNewRatio) < keepTrackingHostRatio)
			{
                if(std::max(incomingMatchedNew, outgoingMatchedNew) >= Config::getInstance().getGlobalAttackMinEvToReport())
				{
                	return RDPHost::REPORT_END_OF_ATTACK;
				}
                else
				{
                	return RDPHost::END_OF_ATTACK;
				}
            }

            if(std::max(incomingMatchedNew, outgoingMatchedNew) >= Config::getInstance().getGlobalAttackMinEvToReport())
			{
            	return RDPHost::REPORT_ATTACK;
			}
            else
			{
            	return RDPHost::ATTACK_MIN_EVENTS_WAIT;
			}
        }
    }
}

// ************************************************************/
// ************************ TELNET HOST ***********************/
// ************************************************************/
bool TELNETHost::addRecord(TELNETRecord *record, void *structure, uint8_t direction)
{
    IRecord::MatchStructure st = *(IRecord::MatchStructure*) (structure);

	// ignore port-scans
    if(isFlowScan(&st.packets, &st.flags))
	{
    	return false;
	}
    else
    {
        timeOfLastReceivedRecord = st.flowLastSeen;
        if(direction == FLOW_INCOMING_DIRECTION)
		{
        	recordListIncoming.addRecord(record, isReported());
		}
        else
		{
        	recordListOutgoing.addRecord(record, isReported());
		}
        return true;
    }
}

TELNETHost::ATTACK_STATE TELNETHost::checkForAttack(ur_time_t actualTime)
{
    uint16_t incomingMatched = recordListIncoming.getActualMatchedFlows();
    uint16_t outgoingMatched = recordListOutgoing.getActualMatchedFlows();

    if(!isReported())
    {
    	// no attack yet
        uint16_t incomingListSize = recordListIncoming.getActualListSize();
        uint16_t outgoingListSize = recordListOutgoing.getActualListSize();

        if (std::max(incomingListSize, outgoingListSize) <= Config::getInstance().getTELNETListBottomSize())
        {

            if(std::max(incomingMatched, outgoingMatched) >= Config::getInstance().getTELNETListThreshold())
            {
                // crossed threshold, new attack detected
				recordListIncoming.initTotalTargetsSet();
				recordListOutgoing.initTotalTargetsSet();
                return TELNETHost::REPORT_NEW_ATTACK;
            }
            else
			{
                return TELNETHost::NO_ATTACK;
            }
        }
        else
		{
        	// Number of records is between bottom size and max size

			auto topMatchedRatio = std::max((double)incomingMatched/incomingListSize, (double)outgoingMatched/outgoingListSize);

			if(topMatchedRatio >= Config::getInstance().getGlobalMatchedFlowRatio())
            {
                // crossed threshold, new attack detected
				recordListIncoming.initTotalTargetsSet();
				recordListOutgoing.initTotalTargetsSet();
                return TELNETHost::REPORT_NEW_ATTACK;
            }
            else
			{
                return TELNETHost::NO_ATTACK;
            }
        }
    }
    else // isReported
    {
    	// host is attacking, wait for timeout to report again
        if(!canReportAgain(actualTime))
		{
        	return TELNETHost::ATTACK_REPORT_WAIT;
		}
        else
        {
            uint32_t incomingMatchedNew = recordListIncoming.getMatchedFlowsSinceLastReport();
            uint32_t incomingTotalNew  = recordListIncoming.getTotalFlowsSinceLastReport();

            uint32_t outgoingMatchedNew = recordListOutgoing.getMatchedFlowsSinceLastReport();
            uint32_t outgoingTotalNew  = recordListOutgoing.getTotalFlowsSinceLastReport();

            if(incomingMatched == 0 && incomingMatchedNew == 0 &&
               outgoingMatched == 0 && outgoingMatchedNew == 0)
			{
            	return TELNETHost::END_OF_ATTACK;
			}

            auto keepTrackingHostRatio = Config::getInstance().getGlobalAttackMinRatioToKeepTrackingHost();

			// avoids div by zero
			auto incomingMatchedNewRatio = (incomingTotalNew == 0 ? 0 : (double)incomingMatchedNew / incomingTotalNew);
			auto outgoingMatchedNewRatio = (outgoingTotalNew == 0 ? 0 : (double)outgoingMatchedNew / outgoingTotalNew);

			if (std::max(incomingMatchedNewRatio, outgoingMatchedNewRatio) < keepTrackingHostRatio)
			{
                if(std::max(incomingMatchedNew, outgoingMatchedNew) >= Config::getInstance().getGlobalAttackMinEvToReport())
				{
                	return TELNETHost::REPORT_END_OF_ATTACK;
				}
                else
				{
                	return TELNETHost::END_OF_ATTACK;
				}
            }

			if(std::max(incomingMatchedNew, outgoingMatchedNew) >= Config::getInstance().getGlobalAttackMinEvToReport())
			{
            	return TELNETHost::REPORT_ATTACK;
			}
			else
			{
            	return TELNETHost::ATTACK_MIN_EVENTS_WAIT;
			}
        }
    }
}

// ************************************************************/
// *********************** SSH HOST MAP ***********************/
// ************************************************************/

SSHHost *SSHHostMap::findHost(IRecord::MatchStructure *structure, uint8_t direction)
{
    ip_addr_t ip;
    if(direction == FLOW_INCOMING_DIRECTION)
	{
    	ip = structure->srcIp;
	}
    else
	{
    	ip = structure->dstIp;
	}

    auto it = hostMap.find(ip);

    SSHHost *host;

    if(it == hostMap.end())
    {
    	// not found, create new host
        host = new SSHHost(ip, structure->flowFirstSeen);
        hostMap.insert(std::pair<ip_addr_t, SSHHost*>(ip, host));
    }
    else
	{
    	host = it->second;
	}

    return host;
}

void SSHHostMap::checkForAttackTimeout(ur_time_t actualTime, Sender *sender)
{
    for (const auto & it : hostMap)
    {
        SSHHost *host = it.second;
        if(host->isReported() && host->checkForAttackTimeout(actualTime))
        {
            uint32_t numOfEvents = host->getPointerToIncomingRecordList()->getMatchedFlowsSinceLastReport();

            if(numOfEvents >= Config::getInstance().getGlobalAttackMinEvToReport())
            {
                sender->continuingReport(host, TCP_SSH_PORT, actualTime, true);
            }
            host->setNotReported();
            host->clearAllRecords();
        }
    }
}

void SSHHostMap::deleteOldRecordAndHosts(ur_time_t actualTime)
{
	std::cerr << "deleting:" << hostMap.size(); // DEBUG
	IHostMap::clearOldRecAndHost(&hostMap, actualTime);
	std::cerr << "," << size() << "\n"; // DEBUG
}

// ************************************************************/
// *********************** RDP HOST MAP ***********************/
// ************************************************************/

RDPHost *RDPHostMap::findHost(IRecord::MatchStructure *structure, uint8_t direction)
{
    ip_addr_t ip;
    if(direction == FLOW_INCOMING_DIRECTION)
	{
    	ip = structure->srcIp;
	}
    else
	{
    	ip = structure->dstIp; // attacker is now destination address
	}

    auto it = hostMap.find(ip);

    RDPHost *host;

    if (it == hostMap.end())
    {
    	// not found, create new host
        host = new RDPHost(ip, structure->flowFirstSeen);
        hostMap.insert(std::pair<ip_addr_t, RDPHost*>(ip, host));
    }
    else
	{
    	host = it->second;
	}

    return host;
}

void RDPHostMap::checkForAttackTimeout(ur_time_t actualTime, Sender *sender)
{
    for(const auto & it : hostMap)
    {
        RDPHost *host = it.second;
        if(host->isReported() && host->checkForAttackTimeout(actualTime))
        {
            uint32_t numOfEvents = host->getPointerToIncomingRecordList()->getMatchedFlowsSinceLastReport();

            if(numOfEvents >= Config::getInstance().getGlobalAttackMinEvToReport())
            {
                sender->continuingReport(host, TCP_RDP_PORT, actualTime, true);
            }
            host->setNotReported();
            host->clearAllRecords();
        }
    }
}

void RDPHostMap::deleteOldRecordAndHosts(ur_time_t actualTime)
{
	IHostMap::clearOldRecAndHost(&hostMap, actualTime);
}

// ************************************************************/
// ********************** TELNET HOST MAP *********************/
// ************************************************************/

TELNETHost *TELNETHostMap::findHost(IRecord::MatchStructure *structure, uint8_t direction)
{
    ip_addr_t ip;
    if(direction == FLOW_INCOMING_DIRECTION)
	{
    	ip = structure->srcIp;
	}
    else
	{
    	ip = structure->dstIp; // attacker is now destination address
	}

    auto it = hostMap.find(ip);

    TELNETHost *host;

    if(it == hostMap.end())
    {
    	// not found, create new host
        host = new TELNETHost(ip, structure->flowFirstSeen);
        hostMap.insert(std::pair<ip_addr_t, TELNETHost*>(ip, host));
    }
    else
	{
    	host = it->second;
	}

    return host;
}

void TELNETHostMap::checkForAttackTimeout(ur_time_t actualTime, Sender *sender)
{
    for(const auto & it : hostMap)
    {
        TELNETHost *host = it.second;
        if(host->isReported() && host->checkForAttackTimeout(actualTime))
        {
            uint32_t numOfEvents = host->getPointerToIncomingRecordList()->getMatchedFlowsSinceLastReport();

            if(numOfEvents >= Config::getInstance().getGlobalAttackMinEvToReport())
            {
                sender->continuingReport(host, TCP_TELNET_PORT, actualTime, true);
            }

            host->setNotReported();
            host->clearAllRecords();
        }
    }
}

void TELNETHostMap::deleteOldRecordAndHosts(ur_time_t actualTime)
{
	IHostMap::clearOldRecAndHost(&hostMap, actualTime);
}
