/**
 * \file config.h
 * \brief Class Config used for loading configuration, singleton implementation
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

#ifndef CONFIG_H
#define CONFIG_H

#include <cstring>
#include <unirec/unirec.h> //ur_time_t
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cctype>
#include <cstdlib>

class Config {

public:
    bool initFromFile(const std::string& path);

	inline ur_time_t getGlobalTimerForReportCheck() const {return GENERAL_CHECK_FOR_REPORT_TIMEOUT;}
	inline ur_time_t getGlobalTimerForDeleteCheck() const {return GENERAL_CHECK_FOR_DELETE_TIMEOUT;}
	inline ur_time_t getGlobalAttackMinEvToReport() const {return GENERAL_ATTACK_MIN_EVENTS_TO_REPORT;}
    inline double    getGlobalAttackMinRatioToKeepTrackingHost() const {return GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST;}

    inline int       getGlobalIgnoreFirstSend()  const {return GENERAL_IGNORE_FIRST_SEND;}
    inline double    getGlobalMatchedFlowRatio() const {return GENERAL_MATCHED_FLOW_RATIO;}

	//SSH
	inline uint16_t  getSSHMaxListSize()       const {return SSH_LIST_SIZE;}
    inline uint16_t  getSSHListBottomSize()    const {return SSH_LIST_SIZE_BOTTOM_THRESHOLD;}

	inline uint16_t  getSSHListThreshold()     const {return SSH_LIST_THRESHOLD;}
	inline ur_time_t getSSHRecordTimeout()     const {return SSH_RECORD_TIMEOUT;}
	inline ur_time_t getSSHHostDeleteTimeout() const {return SSH_HOST_TIMEOUT;}
	inline ur_time_t getSSHReportTimeout()     const {return SSH_REPORT_TIMEOUT;}
	inline ur_time_t getSSHAttackTimeout()     const {return SSH_ATTACK_TIMEOUT;}

    // SSH INCOMING DIRECTION (ATTACKER -> VICTIM)
    inline uint16_t getSSHIncMinPackets()    const  {return SSH_BRUTEFORCE_INC_MIN_PACKETS;}
    inline uint16_t getSSHIncMaxPackets()    const  {return SSH_BRUTEFORCE_INC_MAX_PACKETS;}
    inline uint16_t getSSHIncMinBytes()      const  {return SSH_BRUTEFORCE_INC_MIN_BYTES;}
    inline uint16_t getSSHIncMaxBytes()      const  {return SSH_BRUTEFORCE_INC_MAX_BYTES;}

    // SSH OUTGOING DIRECTION (VICTIM -> ATTACKER)
    inline uint16_t getSSHOutMinPackets()    const  {return SSH_BRUTEFORCE_OUT_MIN_PACKETS;}
    inline uint16_t getSSHOutMaxPackets()    const  {return SSH_BRUTEFORCE_OUT_MAX_PACKETS;}
    inline uint16_t getSSHOutMinBytes()      const  {return SSH_BRUTEFORCE_OUT_MIN_BYTES;}
    inline uint16_t getSSHOutMaxBytes()      const  {return SSH_BRUTEFORCE_OUT_MAX_BYTES;}

	//RDP
    inline uint16_t  getRDPListBottomSize()    const {return RDP_LIST_SIZE_BOTTOM_THRESHOLD;}
	inline uint16_t  getRDPMaxListSize()       const {return RDP_LIST_SIZE;}
	inline uint16_t  getRDPListThreshold()     const {return RDP_LIST_THRESHOLD;}
	inline ur_time_t getRDPRecordTimeout()     const {return RDP_RECORD_TIMEOUT;}
	inline ur_time_t getRDPHostDeleteTimeout() const {return RDP_HOST_TIMEOUT;}
	inline ur_time_t getRDPReportTimeout()     const {return RDP_REPORT_TIMEOUT;}
	inline ur_time_t getRDPAttackTimeout()     const {return RDP_ATTACK_TIMEOUT;}

    // RDP INCOMING DIRECTION (ATTACKER -> VICTIM)
    inline uint16_t getRDPIncMinPackets()    const  {return RDP_BRUTEFORCE_INC_MIN_PACKETS;}
    inline uint16_t getRDPIncMaxPackets()    const  {return RDP_BRUTEFORCE_INC_MAX_PACKETS;}
    inline uint16_t getRDPIncMinBytes()      const  {return RDP_BRUTEFORCE_INC_MIN_BYTES;}
    inline uint16_t getRDPIncMaxBytes()      const  {return RDP_BRUTEFORCE_INC_MAX_BYTES;}

	// RDP OUTGOING DIRECTION (VICTIM -> ATTACKER)
    inline uint16_t getRDPOutMinPackets()    const  {return RDP_BRUTEFORCE_OUT_MIN_PACKETS;}
    inline uint16_t getRDPOutMaxPackets()    const  {return RDP_BRUTEFORCE_OUT_MAX_PACKETS;}
    inline uint16_t getRDPOutMinBytes()      const  {return RDP_BRUTEFORCE_OUT_MIN_BYTES;}
    inline uint32_t getRDPOutMaxBytes()      const  {return RDP_BRUTEFORCE_OUT_MAX_BYTES;}

	//TELNET
    inline uint16_t  getTELNETListBottomSize() const {return TELNET_LIST_SIZE_BOTTOM_THRESHOLD;}
	inline uint16_t  getTELNETMaxListSize()    const {return TELNET_LIST_SIZE;}
	inline uint16_t  getTELNETListThreshold()  const {return TELNET_LIST_THRESHOLD;}
	inline ur_time_t getTELNETRecordTimeout()  const {return TELNET_RECORD_TIMEOUT;}
	inline ur_time_t getTELNETHostDeleteTimeout()const {return TELNET_HOST_TIMEOUT;}
	inline ur_time_t getTELNETReportTimeout()  const {return TELNET_REPORT_TIMEOUT;}
    inline ur_time_t getTELNETAttackTimeout()  const {return TELNET_ATTACK_TIMEOUT;}

    inline uint16_t getTELNETIncMinPackets() const  {return TELNET_BRUTEFORCE_INC_MIN_PACKETS;}
    inline uint16_t getTELNETIncMaxPackets() const  {return TELNET_BRUTEFORCE_INC_MAX_PACKETS;}
    inline uint16_t getTELNETIncMinBytes()   const  {return TELNET_BRUTEFORCE_INC_MIN_BYTES;}
    inline uint16_t getTELNETIncMaxBytes()   const  {return TELNET_BRUTEFORCE_INC_MAX_BYTES;}

    // TODO Where is telnet outgoing

    static Config& getInstance()
    {
        static Config instance;
        return instance;
    }

    void reloadConfig();

private:
    Config();
    std::string configPath;

    //general
    ur_time_t GENERAL_CHECK_FOR_REPORT_TIMEOUT;
    ur_time_t GENERAL_CHECK_FOR_DELETE_TIMEOUT;
    uint16_t  GENERAL_ATTACK_MIN_EVENTS_TO_REPORT;
    double    GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST;
    uint8_t   GENERAL_IGNORE_FIRST_SEND;
    float	  GENERAL_MATCHED_FLOW_RATIO;

    std::string kw_GENERAL_CHECK_FOR_REPORT_TIMEOUT;
    std::string kw_GENERAL_CHECK_FOR_DELETE_TIMEOUT;
    std::string kw_GENERAL_ATTACK_MIN_EVENTS_TO_REPORT;
    std::string kw_GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST;
    std::string kw_GENERAL_IGNORE_FIRST_SEND;
    std::string kw_GENERAL_MATCHED_FLOW_RATIO;



    //SSH
    uint16_t  SSH_LIST_SIZE;
    uint16_t  SSH_LIST_THRESHOLD;
    uint16_t  SSH_LIST_SIZE_BOTTOM_THRESHOLD;

    ur_time_t SSH_RECORD_TIMEOUT;
    ur_time_t SSH_HOST_TIMEOUT;
    ur_time_t SSH_REPORT_TIMEOUT;
    ur_time_t SSH_ATTACK_TIMEOUT;

    uint16_t SSH_BRUTEFORCE_INC_MIN_PACKETS;
    uint16_t SSH_BRUTEFORCE_INC_MAX_PACKETS;
    uint16_t SSH_BRUTEFORCE_INC_MIN_BYTES;
    uint16_t SSH_BRUTEFORCE_INC_MAX_BYTES;

    uint16_t SSH_BRUTEFORCE_OUT_MIN_PACKETS;
    uint16_t SSH_BRUTEFORCE_OUT_MAX_PACKETS;
    uint16_t SSH_BRUTEFORCE_OUT_MIN_BYTES;
    uint16_t SSH_BRUTEFORCE_OUT_MAX_BYTES;

    //SSH keywords
    std::string kw_SSH_LIST_SIZE;
    std::string kw_SSH_LIST_THRESHOLD;
    std::string kw_SSH_LIST_SIZE_BOTTOM_THRESHOLD;
    std::string kw_SSH_RECORD_TIMEOUT;
    std::string kw_SSH_HOST_TIMEOUT;
    std::string kw_SSH_BRUTEFORCE_INC_MIN_PACKETS;
    std::string kw_SSH_BRUTEFORCE_INC_MAX_PACKETS;
    std::string kw_SSH_BRUTEFORCE_INC_MIN_BYTES;
    std::string kw_SSH_BRUTEFORCE_INC_MAX_BYTES;
    std::string kw_SSH_BRUTEFORCE_OUT_MIN_PACKETS;
    std::string kw_SSH_BRUTEFORCE_OUT_MAX_PACKETS;
    std::string kw_SSH_BRUTEFORCE_OUT_MIN_BYTES;
    std::string kw_SSH_BRUTEFORCE_OUT_MAX_BYTES;
    std::string kw_SSH_REPORT_TIMEOUT;
    std::string kw_SSH_ATTACK_TIMEOUT;


    //RDP
    uint16_t  RDP_LIST_SIZE;
    uint16_t  RDP_LIST_SIZE_BOTTOM_THRESHOLD;
    uint16_t  RDP_LIST_THRESHOLD;
    ur_time_t RDP_RECORD_TIMEOUT;
    ur_time_t RDP_HOST_TIMEOUT;
    ur_time_t RDP_REPORT_TIMEOUT;
    ur_time_t RDP_ATTACK_TIMEOUT;

    uint16_t RDP_BRUTEFORCE_INC_MIN_PACKETS;
    uint16_t RDP_BRUTEFORCE_INC_MAX_PACKETS;
    uint16_t RDP_BRUTEFORCE_INC_MIN_BYTES;
    uint16_t RDP_BRUTEFORCE_INC_MAX_BYTES;

    uint16_t RDP_BRUTEFORCE_OUT_MIN_PACKETS;
    uint16_t RDP_BRUTEFORCE_OUT_MAX_PACKETS;
    uint16_t RDP_BRUTEFORCE_OUT_MIN_BYTES;
    uint32_t RDP_BRUTEFORCE_OUT_MAX_BYTES;

    //RDP keywords
    std::string kw_RDP_LIST_SIZE;
    std::string kw_RDP_LIST_THRESHOLD;
    std::string kw_RDP_LIST_SIZE_BOTTOM_THRESHOLD;
    std::string kw_RDP_RECORD_TIMEOUT;
    std::string kw_RDP_HOST_TIMEOUT;
    std::string kw_RDP_BRUTEFORCE_INC_MIN_PACKETS;
    std::string kw_RDP_BRUTEFORCE_INC_MAX_PACKETS;
    std::string kw_RDP_BRUTEFORCE_INC_MIN_BYTES;
    std::string kw_RDP_BRUTEFORCE_INC_MAX_BYTES;
    std::string kw_RDP_BRUTEFORCE_OUT_MIN_PACKETS;
    std::string kw_RDP_BRUTEFORCE_OUT_MAX_PACKETS;
    std::string kw_RDP_BRUTEFORCE_OUT_MIN_BYTES;
    std::string kw_RDP_BRUTEFORCE_OUT_MAX_BYTES;
    std::string kw_RDP_REPORT_TIMEOUT;
    std::string kw_RDP_ATTACK_TIMEOUT;


	//TELNET
	uint16_t  TELNET_LIST_SIZE;
	uint16_t  TELNET_LIST_SIZE_BOTTOM_THRESHOLD;
	uint16_t  TELNET_LIST_THRESHOLD;
	ur_time_t TELNET_RECORD_TIMEOUT;
	ur_time_t TELNET_HOST_TIMEOUT;
	ur_time_t TELNET_REPORT_TIMEOUT;
	ur_time_t TELNET_ATTACK_TIMEOUT;

	uint16_t TELNET_BRUTEFORCE_INC_MIN_PACKETS;
	uint16_t TELNET_BRUTEFORCE_INC_MAX_PACKETS;
	uint16_t TELNET_BRUTEFORCE_INC_MIN_BYTES;
	uint16_t TELNET_BRUTEFORCE_INC_MAX_BYTES;

	//TELNET keywords
	std::string kw_TELNET_LIST_SIZE;
	std::string kw_TELNET_LIST_THRESHOLD;
	std::string kw_TELNET_LIST_SIZE_BOTTOM_THRESHOLD;

	std::string kw_TELNET_RECORD_TIMEOUT;
	std::string kw_TELNET_HOST_TIMEOUT;
	std::string kw_TELNET_BRUTEFORCE_INC_MIN_PACKETS;
	std::string kw_TELNET_BRUTEFORCE_INC_MAX_PACKETS;
	std::string kw_TELNET_BRUTEFORCE_INC_MIN_BYTES;
	std::string kw_TELNET_BRUTEFORCE_INC_MAX_BYTES;
	std::string kw_TELNET_REPORT_TIMEOUT;
	std::string kw_TELNET_ATTACK_TIMEOUT;

};

#endif
