/**
 * \file sender.cpp
 * \brief Nemea module for detecting bitcoin miners.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2016
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


Sender::Sender(bool *success)
{
    std::string unirecSpecifier = "TIME_FIRST,TIME_LAST,SRC_IP,DST_IP,DST_PORT,EVENT_SCALE";

    outTemplate = ur_create_output_template(0, unirecSpecifier.c_str(), NULL);
    if (outTemplate == NULL) {
        *success = false;
        return;
    }
    *success = true;
}

Sender::~Sender()
{
    if (outTemplate != NULL) {
        ur_free_template (outTemplate);
    }
}


int Sender::send(ip_addr_t &src, ip_addr_t &dst, uint16_t dst_port, uint32_t first_seen, uint32_t last_seen, uint64_t scale)
{
    void *rec = ur_create_record(outTemplate, 0);

    ur_time_t first_ts = ur_time_from_sec_msec(first_seen, 0);
    ur_time_t last_ts = ur_time_from_sec_msec(last_seen, 0);

    ur_set(outTemplate, rec, F_TIME_FIRST, first_ts);
    ur_set(outTemplate, rec, F_TIME_LAST, last_ts);
    ur_set(outTemplate, rec, F_SRC_IP, src);
    ur_set(outTemplate, rec, F_DST_IP, dst);
    ur_set(outTemplate, rec, F_DST_PORT, dst_port);
    ur_set(outTemplate, rec, F_EVENT_SCALE, (uint32_t)scale);

    // send
    int sendState = trap_send(0, rec, ur_rec_size(outTemplate, rec));

    ur_free_record(rec);
    return sendState;
}
