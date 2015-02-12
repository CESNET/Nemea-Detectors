/**
 * \file sip_stats.h
 * \brief Defines structure macros for sip_stats
 * \author Nikolas Jíša <jisaniko@fit.cvut.cz>
 * \author Katerina Pilatova <xpilat05@stud.fit.vutbr.cz>
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

#ifndef _SIP_STATS_H
#define _SIP_STATS_H

#ifdef	__cplusplus
extern "C" {
#endif

/* \brief Gets statistics from INVEA_SIP_STATS (uint64)
 * VOIP PACKET T. | SERVICE REQ | SERVICE RESP     | CALL REQ | CALL RESP
 * SIP_STATS_0    | INFO        | OK               | CANCEL   | OK
 * SIP_STATS_8    | PUBLISH     | BAD REQUEST	   | ACK      | BUSY HERE
 * SIP_STATS_16   | NOTIFY	| FORBIDDEN        | BYE      | RINGING
 * SIP_STATS_24   | SUBSCRIBE   | INTERNAL ERROR   |          | DECLINE
 * SIP_STATS_32   | OPTIONS     | NOT FOUND        | INVITE   | DIALOG ESTABL.
 * SIP_STATS_40   |             | PROXY AUTH. REQ. |          | SESSION PROGRESS
 * SIP_STATS_48   | REGISTER    | UNAUTHORIZED     |          | PROXY AUTH. REQ.
 * SIP_STATS_56   |             | TRYING           |          | TRYING
 */


/* \brief Macros used for accessing parts of INVEA_SIP_STATS 
 * name: SIP_STATS_N ... N stands for shift length
 * \param[in]  packet_t  For distinguishing access (each packet type is divided
 *                       differently) 
 */
#define SIP_STATS_OLD_0 (sip_stats & 0xff)
#define SIP_STATS_OLD_8 ((sip_stats & 0xff00) >> 8)
#define SIP_STATS_OLD_16(packet_t) \
          ((packet_t == CALL_SIP_REQUEST) ? ((sip_stats & 0xffff0000) >> 16) :\
                                           ((sip_stats & 0xff0000) >> 16))
#define SIP_STATS_OLD_24 ((sip_stats & 0xff000000) >> 24)
#define SIP_STATS_OLD_32(packet_t) \
           (((packet_t == SERVICE_SIP_RESPONSE)||(packet_t == CALL_SIP_RESPONSE)) ?\
                                                ((sip_stats & 0xff00000000) >> 32):\
           ((packet_t == SERVICE_SIP_REQUEST)?((sip_stats & 0xffff00000000) >> 32):\
                                              ((sip_stats & 0xffffffff00000000) >> 32)))
#define SIP_STATS_OLD_40 ((sip_stats & 0xff0000000000) >> 40)
#define SIP_STATS_OLD_48(packet_t) \
           ((packet_t == SERVICE_SIP_REQUEST) ?\
              ((sip_stats & 0xffff000000000000) >> 48) :\
              ((sip_stats & 0xff000000000000) >> 48))
#define SIP_STATS_OLD_56 ((sip_stats & 0xff00000000000000) >> 56)

#define SIP_STATS_0  ((sip_stats & 0xff00000000000000) >> 56)
#define SIP_STATS_8  ((sip_stats & 0x00ff000000000000) >> 48)
#define SIP_STATS_16(packet_t) ((packet_t == CALL_SIP_REQUEST) ? \
                     ((sip_stats & 0x0000ffff00000000) >> 32) :\
                     ((sip_stats & 0x0000ff0000000000) >> 40))
#define SIP_STATS_24 ((sip_stats & 0x000000ff00000000) >> 32)
#define SIP_STATS_32(packet_t) \
           (((packet_t == SERVICE_SIP_RESPONSE)||(packet_t == CALL_SIP_RESPONSE)) ?\
                     ((sip_stats & 0x00000000ff000000) >> 24):\
           ((packet_t == SERVICE_SIP_REQUEST) ?\
                     ((sip_stats & 0x00000000ffff0000) >> 16):\
                     ((sip_stats & 0x00000000ffffffff) >>  0)))
#define SIP_STATS_40 ((sip_stats & 0x0000000000ff0000) >> 16)
#define SIP_STATS_48(packet_t) ((packet_t == SERVICE_SIP_REQUEST) ?\
                     ((sip_stats & 0x000000000000ffff) >>  0) :\
                     ((sip_stats & 0x000000000000ff00) >>  8))
#define SIP_STATS_56 ((sip_stats & 0x00000000000000ff) >>  0)

/* Enumerates INVEA_VOIP_PACKET_TYPE options */
enum voip_packet_enum {
   NON_VOIP,
   SERVICE_SIP_REQUEST,
   SERVICE_SIP_RESPONSE,
   CALL_SIP_REQUEST,
   CALL_SIP_RESPONSE,
   RTP_VOICE_DATA = 8,
   RTCP_STATISTIC_DATA = 16
};

#ifdef  __cplusplus
}
#endif

#endif  /* _SIP_STATS_H */
