/*!
 * \file record.h
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

#ifndef RECORD_H
#define RECORD_H

#include <iostream>
//class TelnetServerProfileMap;
#include "telnet_server_profile.h"

#include <unirec/ipaddr.h> //ip_addr_t
#include <unirec/unirec.h> //ur_time_t
#include <typeinfo>
#include <set>
#include "brute_force_detector.h"
#include "whitelist.h"
#include <nemea-common.h>
#include <cassert>
#include <list>
#include "config.h"

//If we don't have a lot of memory use hash
//#define USE_HASH 

/**
 * Interface for record
 */
class IRecord {
	
public:
    IRecord () : signatureMatched(false) {}
    virtual ~IRecord() = default;
    virtual bool matchWithIncomingSignature(void *structure, Whitelist *wl) = 0;
    virtual bool matchWithOutgoingSignature(void *structure, Whitelist *wl) = 0;
	
    inline bool isMatched() { return signatureMatched; }
    virtual ur_time_t getRecordTimeout() = 0;

    struct MatchStructure
    {
        uint8_t flags;
        uint32_t packets;
        uint64_t bytes;
        ip_addr_t srcIp;
        ip_addr_t dstIp;
        uint16_t srcPort;
        uint16_t dstPort;
        ur_time_t flowFirstSeen;
        ur_time_t flowLastSeen;
    };

    // TODO Why is it even here?
	ip_addr_t dstIp{};
	ur_time_t flowLastSeen{};


protected:
    bool signatureMatched;
};

class SSHRecord : public IRecord {
	
public:
    SSHRecord(ip_addr_t dstIp, ur_time_t flowLastSeen);
    bool matchWithIncomingSignature(void *structure, Whitelist *wl) override;
    bool matchWithOutgoingSignature(void *structure, Whitelist *wl) override;
    ur_time_t getRecordTimeout() override { return Config::getInstance().getSSHRecordTimeout(); }

};

class RDPRecord : public IRecord {

public:
    RDPRecord(ip_addr_t dstIp, ur_time_t flowLastSeen);
    bool matchWithIncomingSignature(void *structure, Whitelist *wl) override;
    bool matchWithOutgoingSignature(void *structure, Whitelist *wl) override;
    ur_time_t getRecordTimeout() override { return Config::getInstance().getRDPRecordTimeout(); }

};

class TELNETRecord : public IRecord {

public:
    TELNETRecord(ip_addr_t dstIp, ur_time_t flowLastSeen);
    bool matchWithIncomingSignature(void *structure, Whitelist *wl) override;
    bool matchWithOutgoingSignature(void *structure, Whitelist *wl) override;
    ur_time_t getRecordTimeout() override { return Config::getInstance().getTELNETRecordTimeout(); }


private:
    static TelnetServerProfileMap TSPMap;
};

template<class T>
class RecordList {

public:
    RecordList();
    ~RecordList();
	
    void addRecord(T record, bool isHostReported);
    void setNewMaxListSize(uint16_t newMaxListSize);
    void clearOldRecords(ur_time_t actualTime);
    void clearAllRecords();
    ur_time_t getTimeOfLastRecord();
	
    inline uint16_t getActualListSize() { return actualListSize; };
    inline uint16_t getActualMatchedFlows() { return actualListMatchedFlows; }
    inline uint32_t getMatchedFlowsSinceLastReport() { return matchedFlowsSinceLastReport; }
    inline uint32_t getTotalFlowsSinceLastReport() { return totalFlowsSinceLastReport; }
    inline void clearMatchedFlowsSinceLastReport() { matchedFlowsSinceLastReport = 0; }
    inline void clearTotalFlowsSinceLastReport() { totalFlowsSinceLastReport = 0; }

    inline uint16_t getTargetsSinceLastReport() { return hashedDstIPSet.size(); }
    inline void clearTargetsSinceLastReport() { hashedDstIPSet.clear(); }

    inline uint16_t getCurrentTargets(); // TODO does this need implementation?

    inline uint32_t getTotalTargetsSinceAttack() { return hashedDstTotalIPSet.size(); }
    inline void clearTotalTargetsSinceAttack() { hashedDstTotalIPSet.clear(); }
    inline void initTotalTargetsSet();
    std::vector<std::string> getIpsOfVictims();

private:
    std::list<T> list;
    uint16_t maxListSize;
    uint16_t actualListSize;
    uint16_t actualListMatchedFlows;
    uint32_t matchedFlowsSinceLastReport;
    uint32_t totalFlowsSinceLastReport;
	
    uint32_t flowCounter;
    uint32_t flowMatchedCounter;

    std::set<ip_addr_t, cmpByIpAddr> hashedDstIPSet;
    std::set<ip_addr_t, cmpByIpAddr> hashedDstTotalIPSet;

    char victimIP[46]{};

    bool checkForTimeout(ur_time_t flowTime, ur_time_t timer, ur_time_t actualTime)
    {
		return flowTime + timer <= actualTime;
    }
};

template <class T>
RecordList<T>::RecordList()
{
    actualListSize = 0;
    actualListMatchedFlows = 0;
    flowCounter = 0;
    flowMatchedCounter = 0;

    matchedFlowsSinceLastReport = 0;
    totalFlowsSinceLastReport = 0;

    if(typeid(T) == typeid(SSHRecord*))
        maxListSize = Config::getInstance().getSSHMaxListSize();
    else if(typeid(T) == typeid(RDPRecord*))
        maxListSize = Config::getInstance().getRDPMaxListSize();
    else if(typeid(T) == typeid(TELNETRecord*))
        maxListSize = Config::getInstance().getTELNETMaxListSize();
    else     
    {    
        std::cerr<<"Error record.h: Max list size for class "<<typeid(T).name()<<" is not defined!\n";    
        std::terminate();
    }
}

template <class T>
RecordList<T>::~RecordList()
{
    while(!list.empty())
    {
        T recToDel = list.front();
        list.pop_front();
        delete recToDel;
    }
}

template <class T>
void RecordList<T>::clearAllRecords()
{
    while(!list.empty())
    {
        T recToDel = list.front();
        list.pop_front();
        delete recToDel;
    }

    actualListSize = 0;
    actualListMatchedFlows = 0;
    flowCounter = 0;
    flowMatchedCounter = 0;

    matchedFlowsSinceLastReport = 0;
    totalFlowsSinceLastReport = 0;

	clearTargetsSinceLastReport();
}


template <class T>
void RecordList<T>::addRecord(T record, bool isHostReported)
{	
    flowCounter++;
    actualListSize++;
    if(actualListSize > maxListSize)
    {   //list is full
        //delete first record
        if((*list.begin())->isMatched())
		{
        	actualListMatchedFlows--;
		}
        T recToDelete = list.front();
        delete recToDelete;
        list.pop_front();
        actualListSize--;
    }
	
    if(record->isMatched())
    {
        flowMatchedCounter++;
        actualListMatchedFlows++; 
    }
	
    if(isHostReported)
    {
        totalFlowsSinceLastReport++;

        if(record->isMatched())
        {
            matchedFlowsSinceLastReport++;
            
            hashedDstIPSet.insert(record->dstIp);   
            hashedDstTotalIPSet.insert(record->dstIp);
        }
    }

    list.push_back(record); //finally push record to a list
}

template <class T>
void RecordList<T>::setNewMaxListSize(uint16_t newMaxListSize)
{
    uint32_t currentMaxSize = maxListSize;

    if (currentMaxSize > newMaxListSize)
    {
        while (actualListSize > newMaxListSize)
        {
            //delete first record
            T recToDelete = list.front();

            if (recToDelete->isMatched())
                actualListMatchedFlows--;

            delete recToDelete;
            list.pop_front();
            actualListSize--;
        }
    }
    maxListSize = newMaxListSize;
}

template <class T>
void RecordList<T>::clearOldRecords(ur_time_t actualTime)
{
    if(list.empty())
        return;

    T rec = list.front();
    ur_time_t timer = rec->getRecordTimeout();

    typename std::list<T>::iterator it = list.begin();

    while(it != list.end())
    {
        ur_time_t flowTime = (*it)->flowLastSeen;
        if (checkForTimeout(flowTime, timer, actualTime))
        {
            if ((*it)->isMatched())
            {
                actualListMatchedFlows--;
            }

            actualListSize--;

            delete *it;
            list.erase(it++);
        }
        else
            break;
    }
}

template <class T>
ur_time_t RecordList<T>::getTimeOfLastRecord()
{
    if(!list.empty())
	{
    	return list.back()->flowLastSeen;
	}
    else
	{
    	return 0;
	}
}

template<class T>
uint16_t RecordList<T>::getCurrentTargets()
{
    std::set<ip_addr_t, cmpByIpAddr> dstIpSet;
    for(auto it : list)
    {
		if(it->isMatched())
        {
            dstIpSet.insert(it->dstIp);
        }
    }
    return dstIpSet.size();
}

template<class T>
void RecordList<T>::initTotalTargetsSet()
{
    for(auto it : list)
    {
		if(it->isMatched())
        {
            hashedDstTotalIPSet.insert(it->dstIp);
        }
    }
}

template<class T>
std::vector<std::string> RecordList<T>::getIpsOfVictims()
{
    std::vector<std::string> tmpIpsOfVictims;

    for(auto& it : list)
    {
        if(it->isMatched())
        {
            ip_to_str(&(it->dstIp), victimIP);

            tmpIpsOfVictims.push_back(std::string(victimIP));
        }
    }

    return tmpIpsOfVictims;
}

#endif
