/*
 * Copyright (C) 2013-2015 CESNET
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

#ifndef _DETECTION_RULES_H_
#define _DETECTION_RULES_H_

#include "hoststats.h"

#define DIR_FLAG_REQ   0x8   //Request
#define DIR_FLAG_RSP   0x4   //Response
#define DIR_FLAG_SF    0x2   //Single flow
#define DIR_FLAG_NRC   0x1   //Not recognized

#define TCP_FIN        0x1   //Finish bit flag
#define TCP_SYN        0x2   //Synchronize bit flag
#define TCP_RST        0x4   //Reset bit flag
#define TCP_PSH        0x8   //Push bit flag
#define TCP_ACK        0x10   //Acknowledgement bit flag
#define TCP_URG        0x20   //Urgent bit flag

// General detector
void check_new_rules(const hosts_key_t &addr, const hosts_record_t &rec);
// SSH detector
void check_new_rules_ssh(const hosts_key_t &addr, const hosts_record_t &rec);
// DNS detector
void check_new_rules_dns(const hosts_key_t &addr, const hosts_record_t &rec);

#endif
