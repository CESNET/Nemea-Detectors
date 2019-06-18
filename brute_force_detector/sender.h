/**
 * \file sender.h
 * \brief Sender of warden reports
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

#ifndef SENDER_H
#define SENDER_H

#include <iostream>
#include <vector>
#include <cstring>

#include <libtrap/trap.h>
#include "brute_force_detector.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#include "fields.h"

#ifdef __cplusplus
}
#endif // __cplusplus

#include <unirec/unirec.h>
using namespace std;

// WARDEN_TYPE
#define WT_BRUTEFORCE      2

/**
 * @desc Class for handling output messages
 */
class Sender
{
public:
    explicit Sender(bool *success);
    ~Sender();

    template <class Host>
    int firstReport(Host *host, uint16_t dstPort, ur_time_t actualTime, uint16_t detectionThreshold)
    {
        if(Config::getInstance().getGlobalIgnoreFirstSend())
        {
        	// Ignore first report
            host->setReportTime(actualTime);
            return TRAP_E_OK;
        }

        //TODO check
		uint32_t incomingMatched = host->getPointerToIncomingRecordList()->getMatchedFlowsSinceLastReport();
		uint32_t outgoingMatched = host->getPointerToOutgoingRecordList()->getMatchedFlowsSinceLastReport();

		string sNote;

       return send(host, dstPort, actualTime, std::max(incomingMatched, outgoingMatched), false, sNote);
    }

    template <class Host>
    int continuingReport(Host *host, uint16_t dstPort, ur_time_t actualTime, bool endOfAttack = false)
    {
        uint32_t incomingMatched = host->getPointerToIncomingRecordList()->getMatchedFlowsSinceLastReport();
        uint32_t outgoingMatched = host->getPointerToOutgoingRecordList()->getMatchedFlowsSinceLastReport();

        string sNote;

        host->getPointerToIncomingRecordList()->clearTargetsSinceLastReport();
        host->getPointerToIncomingRecordList()->clearMatchedFlowsSinceLastReport();
        host->getPointerToIncomingRecordList()->clearTotalFlowsSinceLastReport();

        host->getPointerToOutgoingRecordList()->clearTargetsSinceLastReport();
        host->getPointerToOutgoingRecordList()->clearMatchedFlowsSinceLastReport();
        host->getPointerToOutgoingRecordList()->clearTotalFlowsSinceLastReport();

        return send(host, dstPort, actualTime, std::max(incomingMatched, outgoingMatched), endOfAttack, sNote);
    }

private:
    ur_template_t *outTemplate;

    template <class Host>
    int send(Host *host, uint16_t dstPort, ur_time_t actualTime, uint32_t intensity, bool endOfAttack = false, const string& stringNote = string())
    {
        vector<string> incIpsVictims = host->getPointerToIncomingRecordList()->getIpsOfVictims();
        vector<string> outIpsVictims = host->getPointerToOutgoingRecordList()->getIpsOfVictims();
        string note;

        sort(incIpsVictims.begin(), incIpsVictims.end());
        incIpsVictims.erase(unique(incIpsVictims.begin(), incIpsVictims.end()), incIpsVictims.end());

        sort(outIpsVictims.begin(), outIpsVictims.end());
        outIpsVictims.erase(unique(outIpsVictims.begin(), outIpsVictims.end()), outIpsVictims.end());

        // Incoming
        note.append("I:");
        for (const auto & incIpsVictim : incIpsVictims) {
            note.append(incIpsVictim);
            note.append(",");
        }

        // Outgoing
        note.append("O:");
        for (const auto & outIpsVictim : outIpsVictims) {
            note.append(outIpsVictim);
            note.append(",");
        }
        note.erase(note.length(),1);

		// get size of note
        uint16_t noteSize = note.size() + 1; // plus '\0'

        void *rec = ur_create_record(outTemplate, noteSize);

        // @WARDEN_REPORT=DETECTION_TIME,WARDEN_TYPE,SRC_IP,PROTOCOL,DST_PORT,EVENT_SCALE,
        //                NOTE (IP addresses of victims)
        // set fields
        ur_set(outTemplate, rec, F_DETECTION_TIME, actualTime);
        ur_set(outTemplate, rec, F_WARDEN_TYPE, WT_BRUTEFORCE);
        ur_set(outTemplate, rec, F_SRC_IP, host->getHostIp());
        ur_set(outTemplate, rec, F_DST_PORT, dstPort);
        ur_set(outTemplate, rec, F_PROTOCOL, TCP_PROTOCOL_NUM);
        ur_set(outTemplate, rec, F_EVENT_SCALE, intensity);

        // set dynamic field
        ur_set_string(outTemplate, rec, F_NOTE, note.c_str());

        // send
        int sendState = trap_send(0, rec, ur_rec_size(outTemplate, rec));

        host->setReportTime(actualTime);

        ur_free_record(rec);
        return sendState;
    }
};

#endif // SENDER_H
