/**
 * \file sender.cpp
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

#include "sender.h"

UR_FIELDS(
        time
        DETECTION_TIME,    // Timestamp of the detection of some event
        uint8
                WARDEN_TYPE,      // Type of event (see Warden README for more information)
        ipaddr
                SRC_IP,          // Source address of a flow
        uint8
                PROTOCOL,         // L4 protocol (TCP, UDP, ICMP, etc.)
        uint16
                DST_PORT,        // Destination transport-layer port
        uint32
                EVENT_SCALE,     // Attack intensity
        string NOTE,            // Generic string note
)


Sender::Sender(bool *success) {
    std::string unirecSpecifier = "DETECTION_TIME,WARDEN_TYPE,SRC_IP,PROTOCOL,DST_PORT,EVENT_SCALE,NOTE";

    outTemplate = ur_create_output_template(0, unirecSpecifier.c_str(), NULL);
    if (outTemplate == NULL) {
        *success = false;
        return;
    }
    *success = true;
}

Sender::~Sender() {
    if (outTemplate != NULL) {
        ur_free_template(outTemplate);
    }
}


