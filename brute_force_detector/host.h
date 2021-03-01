/**
 * \file host.h
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

#ifndef HOST_H
#define HOST_H

#include <iostream>
#include <unirec/ipaddr.h> //ip_addr_t
#include <unirec/unirec.h> //ur_time_t
#include "record.h"
#include "config.h"
#include "sender.h"
#include <typeinfo>
#include <map>
#include "brute_force_detector.h"

/**
 * Base class for host
 */
template <class T>
class IHost {

public:
    IHost(ip_addr_t _hostIp, ur_time_t _firstSeen)
    {
        hostIp = _hostIp;
        firstSeen = _firstSeen;
        timeOfLastReport = 0;
        timeOfLastReceivedRecord = 0;
        scanned = false;
    }

    virtual ~IHost() {}

    enum ATTACK_STATE { NO_ATTACK, NEW_ATTACK, ATTACK_REPORT_WAIT, ATTACK,
	                    ATTACK_MIN_EVENTS_WAIT, END_OF_ATTACK, REPORT_END_OF_ATTACK};

    inline ip_addr_t getHostIp() { return hostIp; }
    inline ur_time_t getTimeOfLastReport() { return timeOfLastReport; }
    inline bool isReported() { if(timeOfLastReport == 0) return false; else return true; }
    inline void setReportTime(ur_time_t actualTime) { timeOfLastReport = actualTime; }
    inline void setNotReported()
    {
        timeOfLastReport = 0;
        recordListIncoming.clearNumOfTotalTargetsSinceAttack();
        recordListOutgoing.clearNumOfTotalTargetsSinceAttack();
    }
	
    inline bool getHostScannedNetwork() { return scanned; }

    virtual bool addRecord(T record, void *structure, uint8_t direction = FLOW_INCOMING_DIRECTION)
    {
        if(direction == FLOW_INCOMING_DIRECTION)
            recordListIncoming.addRecord(record, isReported());
        else
            recordListOutgoing.addRecord(record, isReported());
        return true;
    }

    void clearOldRecords(ur_time_t actualTime) { recordListIncoming.clearOldRecords(actualTime); recordListOutgoing.clearOldRecords(actualTime);}
	
	
    virtual ur_time_t getHostDeleteTimeout() = 0; 
	
    virtual bool canDeleteHost(ur_time_t actualTime)
    {
        /*
         ur_time_t timeOfLastIncomingRecord = recordListIncoming.getTimeOfLastRecord();
         ur_time_t timeOfLastOutgoingRecord = recordListOutgoing.getTimeOfLastRecord();
         
         if(timeOfLastIncomingRecord == 0 && timeOfLastOutgoingRecord == 0) //empty lists
             return true;
         
         
         ur_time_t timeOfLastRecord = timeOfLastIncomingRecord > timeOfLastOutgoingRecord ? timeOfLastIncomingRecord : timeOfLastOutgoingRecord;
         */
        ur_time_t timer = getHostDeleteTimeout();
        //return checkForTimeout(timeOfLastRecord, timer, actualTime);

        return checkForTimeout(timeOfLastReceivedRecord, timer, actualTime);

    }

    virtual ur_time_t getHostReportTimeout() = 0;

    virtual bool canReportAgain(ur_time_t actualTime)
    {
        ur_time_t timer = getHostReportTimeout();
        return checkForTimeout(timeOfLastReport, timer, actualTime);
    }

    virtual ur_time_t getHostAttackTimeout() = 0;

    virtual bool checkForAttackTimeout(ur_time_t actualTime)
    {
        ur_time_t timer = getHostAttackTimeout();
        return checkForTimeout(timeOfLastReport, timer, actualTime);
    }

    virtual ATTACK_STATE checkForAttack(ur_time_t actualTime) = 0;

    RecordList<T>* getPointerToIncomingRecordList() {return &recordListIncoming; }
    RecordList<T>* getPointerToOutgoingRecordList() {return &recordListOutgoing; }

    virtual void clearAllRecords() { recordListIncoming.clearAllRecords(); recordListOutgoing.clearAllRecords();}

    bool isFlowScan(uint32_t *packets, uint8_t *flags)
    {
        if((*packets == 1 && *flags == 0b00000010) //SYN
                || (*packets == 2 && *flags == 0b00000010) //SYN
                || (*packets == 2 && *flags == 0b00000110) //SYN + RST
                || (*packets == 1 && *flags == 0b00010010) //SYN + ACK
                || (*packets == 1 && *flags == 0b00010100) //RST + ACK
                || (*packets == 3 && *flags == 0b00000010))//3-syn packets
        {
            scanned = true;
            return true;
        }
        else
            return false;
    }

protected:
    bool checkForTimeout(ur_time_t flowTime, ur_time_t timer, ur_time_t actualTime)
    {
        if(flowTime + timer <= actualTime)
            return true;
        else
            return false;
    }

    bool scanned;

    ip_addr_t hostIp;
    ur_time_t firstSeen;
    ur_time_t timeOfLastReport;
    ur_time_t timeOfLastReceivedRecord;
    RecordList<T> recordListIncoming; //incoming direction to victim (attacker -> victim)
    RecordList<T> recordListOutgoing;
};


class SSHHost : public IHost<SSHRecord*> {

public:
    SSHHost(ip_addr_t hostIp, ur_time_t firstSeen) : IHost<SSHRecord*> (hostIp,  firstSeen) {}

	virtual bool addRecord(SSHRecord *record, void *structure, uint8_t direction = FLOW_INCOMING_DIRECTION);
	virtual ATTACK_STATE checkForAttack(ur_time_t actualTime);
	virtual ur_time_t getHostDeleteTimeout() { return Config::getInstance().getSSHHostTimeout(); }
    virtual ur_time_t getHostReportTimeout() { return Config::getInstance().getSSHReportTimeout(); }
    virtual ur_time_t getHostAttackTimeout() { return Config::getInstance().getSSHAttackTimeout(); } 
};

class RDPHost : public IHost<RDPRecord*> {

public:
    RDPHost(ip_addr_t hostIp, ur_time_t firstSeen) : IHost<RDPRecord*> (hostIp,  firstSeen) {}

	virtual bool addRecord(RDPRecord *record, void *structure, uint8_t direction = FLOW_INCOMING_DIRECTION);
	virtual ATTACK_STATE checkForAttack(ur_time_t actualTime);
	virtual ur_time_t getHostDeleteTimeout() { return Config::getInstance().getRDPHostTimeout(); }
    virtual ur_time_t getHostReportTimeout() { return Config::getInstance().getRDPReportTimeout(); }
    virtual ur_time_t getHostAttackTimeout() { return Config::getInstance().getRDPAttackTimeout(); } 
};

class TELNETHost : public IHost<TELNETRecord*> {

public:
    TELNETHost(ip_addr_t hostIp, ur_time_t firstSeen) : IHost<TELNETRecord*> (hostIp,  firstSeen) {}

	virtual bool addRecord(TELNETRecord *record, void *structure, uint8_t direction = FLOW_INCOMING_DIRECTION);
	virtual ATTACK_STATE checkForAttack(ur_time_t actualTime);
	virtual ur_time_t getHostDeleteTimeout() { return Config::getInstance().getTELNETHostTimeout(); }
	virtual ur_time_t getHostReportTimeout() { return Config::getInstance().getTELNETReportTimeout(); }
    virtual ur_time_t getHostAttackTimeout() { return Config::getInstance().getTELNETAttackTimeout(); } 	
};


//////////////////////////////////////////////////////////////////////////////////////
/************************************************************************************/
//////////////////////////////////////////////////////////////////////////////////////

class IHostMap {

public:
    IHostMap() {}
	~IHostMap() {}

	virtual void clear() = 0;
	virtual inline uint16_t size() = 0;

	virtual void deleteOldRecordAndHosts(ur_time_t actualTime) = 0;
	virtual void checkForAttackTimeout(ur_time_t actualTime, Sender *sender) = 0;

protected:

    template<typename Container>
    void clearMap(Container *c)
    {
        typename Container::iterator it = c->begin();
        while(it != c->end())
        {
            if(it->second)
                delete it->second;
            it++;

        }
        c->clear();
    }

    template<typename Container>
    void clearOldRecAHost(Container *c, ur_time_t actualTime)
    {
        typename Container::iterator it = c->begin();
        while(it != c->end())
        {
            it->second->clearOldRecords(actualTime);

            bool canDelete = it->second->canDeleteHost(actualTime);
            if(canDelete)
            {
                delete it->second;
                c->erase(it++);
            }
            else
                it++;
        }
    }
};

class SSHHostMap : public IHostMap {

public:
    SSHHostMap() {}
    ~SSHHostMap() {}

    virtual void clear()
    {
        IHostMap::clearMap(&hostMap);
    }
    virtual inline uint16_t size()
    {
        return hostMap.size();
    }

    SSHHost *findHost(IRecord::MatchStructure *structure, uint8_t direction = FLOW_INCOMING_DIRECTION);
    virtual void deleteOldRecordAndHosts(ur_time_t actualTime);
    virtual void checkForAttackTimeout(ur_time_t actualTime, Sender *sender);

private:
    map<ip_addr_t, SSHHost*, cmpByIpAddr> hostMap;
};

class RDPHostMap: public IHostMap {

public:
    RDPHostMap() {}
    ~RDPHostMap() {}

    virtual void clear()
    {
        IHostMap::clearMap(&hostMap);
    }
    
    virtual inline uint16_t size()
    {
        return hostMap.size();
    }

    RDPHost *findHost(IRecord::MatchStructure *structure, uint8_t direction = FLOW_INCOMING_DIRECTION);
    virtual void deleteOldRecordAndHosts(ur_time_t actualTime);
    virtual void checkForAttackTimeout(ur_time_t actualTime, Sender *sender);

private:
    map<ip_addr_t, RDPHost*, cmpByIpAddr> hostMap;
};


class TELNETHostMap: public IHostMap {

public:
    TELNETHostMap() {}
    ~TELNETHostMap() {}

    virtual void clear()
    {
        IHostMap::clearMap(&hostMap);
    }
    
    virtual inline uint16_t size()
    {
        return hostMap.size();
    }

    TELNETHost *findHost(IRecord::MatchStructure *structure, uint8_t direction = FLOW_INCOMING_DIRECTION);
    virtual void deleteOldRecordAndHosts(ur_time_t actualTime);
    virtual void checkForAttackTimeout(ur_time_t actualTime, Sender *sender);

private:
    map<ip_addr_t, TELNETHost*, cmpByIpAddr> hostMap;
};

#endif
