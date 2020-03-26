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
template<class T>
class IHost {

public:
    IHost(ip_addr_t _hostIp, ur_time_t _firstSeen) {
        hostIp = _hostIp;
        firstSeen = _firstSeen;
        timeOfLastReport = 0;
        timeOfLastReceivedRecord = 0;
        scanned = false;
    }

    virtual ~IHost() {};

    enum ATTACK_STATE {
        NO_ATTACK,
        REPORT_NEW_ATTACK,            // send report
        ATTACK_REPORT_WAIT,
        REPORT_ATTACK,                    // send report
        ATTACK_MIN_EVENTS_WAIT,
        END_OF_ATTACK,
        REPORT_END_OF_ATTACK    // send report
    };

    inline ip_addr_t getHostIp() { return hostIp; }

    inline ur_time_t getTimeOfLastReport() { return timeOfLastReport; }

    inline bool isReported() { return timeOfLastReport != 0; }

    inline void setReportTime(ur_time_t actualTime) { timeOfLastReport = actualTime; }

    inline void setNotReported() {
        recordListIncoming.clearTotalTargetsSinceAttack();
        recordListOutgoing.clearTotalTargetsSinceAttack();
        timeOfLastReport = 0;
    }

    inline bool getHostScannedNetwork() { return scanned; }

    virtual bool addRecord(T record, IRecord::MatchStructure* flow, uint8_t direction) {
        if (direction == FLOW_INCOMING_DIRECTION) {
            recordListIncoming.addRecord(record, isReported());
        }
        else {
            recordListOutgoing.addRecord(record, isReported());
        }
        return true;
    }

    void clearOldRecords(ur_time_t actualTime) {
        recordListIncoming.clearOldRecords(actualTime);
        recordListOutgoing.clearOldRecords(actualTime);
    }

    virtual ur_time_t getHostDeleteTimeout() = 0;

    virtual bool canDeleteHost(ur_time_t actualTime) {
        ur_time_t timer = getHostDeleteTimeout();

        return checkForTimeout(timeOfLastReceivedRecord, timer, actualTime);
    }

    virtual ur_time_t getHostReportTimeout() = 0;

    virtual bool canReportAgain(ur_time_t actualTime) {
        ur_time_t timer = getHostReportTimeout();
        return checkForTimeout(timeOfLastReport, timer, actualTime);
    }

    virtual ur_time_t getHostAttackTimeout() = 0;

    virtual bool checkForAttackTimeout(ur_time_t actualTime) {
        ur_time_t timer = getHostAttackTimeout();
        return checkForTimeout(timeOfLastReport, timer, actualTime);
    }

    virtual ATTACK_STATE checkForAttack(ur_time_t actualTime) = 0;

    RecordList<T> *getPointerToIncomingRecordList() { return &recordListIncoming; }

    RecordList<T> *getPointerToOutgoingRecordList() { return &recordListOutgoing; }

    virtual void clearAllRecords() {
        recordListIncoming.clearAllRecords();
        recordListOutgoing.clearAllRecords();
    }

    bool isFlowScan(const uint32_t packets, const uint8_t flags) {
        if ((packets == 1 && flags == 0b00000010)    // SYN
            || (packets == 1 && flags == 0b00010010)  // SYN + ACK
            || (packets == 1 && flags == 0b00010100)  // RST + ACK
            || (packets == 2 && flags == 0b00000010)  // SYN
            || (packets == 2 && flags == 0b00000110)  // SYN + RST
            || (packets == 3 && flags == 0b00000010)) // 3 SYN packets
        {
            scanned = true;
            return true;
        }
        else {
            return false;
        }
    }

protected:

    bool scanned;

    ip_addr_t hostIp;
    ur_time_t firstSeen; // TODO unused
    ur_time_t timeOfLastReport;
    ur_time_t timeOfLastReceivedRecord;
    RecordList<T> recordListIncoming; // direction to victim (attacker -> victim)
    RecordList<T> recordListOutgoing;
};


class SSHHost : public IHost<SSHRecord *> {

public:
    SSHHost(ip_addr_t hostIp, ur_time_t firstSeen) : IHost<SSHRecord *>(hostIp, firstSeen) {}

    bool addRecord(SSHRecord *record, IRecord::MatchStructure *flow, uint8_t direction);

    ATTACK_STATE checkForAttack(ur_time_t actualTime);

    ur_time_t getHostDeleteTimeout()  { return Config::getInstance().getSSHHostDeleteTimeout(); }

    ur_time_t getHostReportTimeout()  { return Config::getInstance().getSSHReportTimeout(); }

    ur_time_t getHostAttackTimeout()  { return Config::getInstance().getSSHAttackTimeout(); }
};


class RDPHost : public IHost<RDPRecord *> {

public:
    RDPHost(ip_addr_t hostIp, ur_time_t firstSeen) : IHost<RDPRecord *>(hostIp, firstSeen) {}

    bool addRecord(RDPRecord *record, IRecord::MatchStructure *flow, uint8_t direction);

    ATTACK_STATE checkForAttack(ur_time_t actualTime);

    ur_time_t getHostDeleteTimeout()  { return Config::getInstance().getRDPHostDeleteTimeout(); }

    ur_time_t getHostReportTimeout()  { return Config::getInstance().getRDPReportTimeout(); }

    ur_time_t getHostAttackTimeout()  { return Config::getInstance().getRDPAttackTimeout(); }
};

class TELNETHost : public IHost<TELNETRecord *> {

public:
    TELNETHost(ip_addr_t hostIp, ur_time_t firstSeen) : IHost<TELNETRecord *>(hostIp, firstSeen) {}

    bool addRecord(TELNETRecord *record, IRecord::MatchStructure *flow, uint8_t direction);

    ATTACK_STATE checkForAttack(ur_time_t actualTime);

    ur_time_t getHostDeleteTimeout()  { return Config::getInstance().getTELNETHostDeleteTimeout(); }

    ur_time_t getHostReportTimeout()  { return Config::getInstance().getTELNETReportTimeout(); }

    ur_time_t getHostAttackTimeout()  { return Config::getInstance().getTELNETAttackTimeout(); }
};

//////////////////////////////////////////////////////////////////////////////////////
/************************************************************************************/
//////////////////////////////////////////////////////////////////////////////////////

class IHostMap {

public:
    IHostMap() {};

    ~IHostMap() {};

    virtual void clear() = 0;

    virtual inline uint16_t size() = 0;

    virtual void deleteOldRecordAndHosts(ur_time_t actualTime) = 0;

    virtual void checkForAttackTimeout(ur_time_t actualTime, Sender *sender) = 0;

protected:

    template<typename Container>
    void clearMap(Container *c) {
        typename Container::iterator it = c->begin();

        while (it != c->end()) {
            delete it->second;
            it++;
        }
        c->clear();
    }

    /**
     * @brief clear old hostMap records and old hosts
     *
     * @tparam Container
     * @param c
     * @param actualTime
     */
    template<typename Container>
    void clearOldRecAndHost(Container *c, ur_time_t actualTime) {

        typename Container::iterator it = c->begin();
        // iterating over map<ip_addr_t, SSHHost*>  (or RDPHost* or TELNETHost*)

        while (it != c->end()) {
            it->second->clearOldRecords(actualTime);

            bool canDelete = it->second->canDeleteHost(actualTime);
            if (canDelete) {
                delete it->second;
                c->erase(it++);
            }
            else {
                it++;
            }
        }
    }
};

class SSHHostMap : public IHostMap {

public:
    SSHHostMap() {};

    ~SSHHostMap() {};

    void clear()  {
        IHostMap::clearMap(&hostMap);
    }

    inline uint16_t size()  {
        return hostMap.size();
    }

    SSHHost *findHost(const IRecord::MatchStructure *const flow, uint8_t direction = FLOW_INCOMING_DIRECTION);

    void deleteOldRecordAndHosts(ur_time_t actualTime);

    void checkForAttackTimeout(ur_time_t actualTime, Sender *sender);

private:
    map<ip_addr_t, SSHHost *, cmpByIpAddr> hostMap;
};

class RDPHostMap : public IHostMap {

public:
    RDPHostMap() {};

    ~RDPHostMap() {};

    void clear()  {
        IHostMap::clearMap(&hostMap);
    }

    inline uint16_t size()  {
        return hostMap.size();
    }

    RDPHost *findHost(const IRecord::MatchStructure *const flow, uint8_t direction = FLOW_INCOMING_DIRECTION);

    void deleteOldRecordAndHosts(ur_time_t actualTime);

    void checkForAttackTimeout(ur_time_t actualTime, Sender *sender);

private:
    map<ip_addr_t, RDPHost *, cmpByIpAddr> hostMap;
};


class TELNETHostMap : public IHostMap {

public:
    TELNETHostMap() {};

    ~TELNETHostMap() {};

    void clear()  {
        IHostMap::clearMap(&hostMap);
    }

    inline uint16_t size()  {
        return hostMap.size();
    }

    TELNETHost *findHost(IRecord::MatchStructure *flow, uint8_t direction = FLOW_INCOMING_DIRECTION);

    void deleteOldRecordAndHosts(ur_time_t actualTime);

    void checkForAttackTimeout(ur_time_t actualTime, Sender *sender);

private:
    map<ip_addr_t, TELNETHost *, cmpByIpAddr> hostMap;
};

#endif // HOST_H
