/**
 * \file sip_bf_detector.h
 * \brief Module for detecting brute-force attacks on Session Initiation Protocol.
 * \author Tomas Jansky <janskto1@fit.cvut.cz>
 * \date 2016
 */
/*
 * Copyright (C) 2016 CESNET
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
extern "C" {
#include <b_plus_tree.h>
}

#define SIP_MSG_TYPE_STATUS      99
#define SIP_STATUS_FORBIDDEN     403
#define SIP_STATUS_OK            200
#define MAX_LENGTH_SIP_FROM      100
#define MAX_LENGTH_SIP_TO        100
#define MAX_LENGTH_CSEQ          100
#define CSEQ_EXPECTED            "2 R"

/** \brief UniRec input template definition. */
#define UNIREC_INPUT_TEMPLATE "DST_IP,SRC_IP,TIME_FIRST,SIP_MSG_TYPE,SIP_STATUS_CODE,SIP_CSEQ,SIP_CALLING_PARTY"

/** \brief UniRec output template definition. */
#define UNIREC_OUTPUT_TEMPLATE "SIP_MSG_TYPE"

class SIPAttackedServer {
public:
   SIPAttackedServer() : m_count(0) {}
   ~SIPAttackedServer() {}
   void increaseCount() {m_count++;}
private:
   int32_t m_count;  
};
