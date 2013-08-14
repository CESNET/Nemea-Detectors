/**
 * \file dnsblacklistfilter.h
 * \brief Main module for DNSBlackListDetector -- header file.
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

/*
 * Copyright (C) 2013 CESNET
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

#ifndef DNSBLACKLISTFILTER_H
#define DNSBLACKLISTFILTER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../../../unirec/unirec.h"
#include "../../../common/cuckoo_hash_v2/cuckoo_hash.h"
#include "../../../common/cuckoo_hash/cuckoo_hash.h"

#define DNS_TABLE_SIZE 1000000
#define IP_TABLE_SIZE 1000000
#define THR_COUNT 2

/**
 * Structure of item with update for DNS table.
 */
typedef struct {
    /*@{*/
    char* dns; /**< URL to update */
    uint8_t bl; /**< Source blacklist of the URL */
    /*@}*/
} upd_item_t;

/**
 * Parameter structure for DNS checking thread.
 */
typedef struct {
    /*@{*/
    ur_template_t *input; /**< Template of input record. */
    ur_template_t *output; /**< Template of detection record */
    void *detection; /**< Detection record (will dynamically change) */
    const char* upd_path; /**< Path to blacklists source folder */
    cc_hash_table_t *dns_table; /**< Table with blacklisted domain names */
    cc_hash_table_v2_t *ip_table; /**< Table with blacklisted IPs gained from DNS thread */
    /*@}*/
} dns_params_t;

/**
 * Parameter structure for IP checking thread.
 */
typedef struct {
    /*@{*/
    ur_template_t *input; /**< Template of input record. */
    ur_template_t *output; /**< Template of detection record */
    void *detection; /**< Detection record (will dynamically change) */
    cc_hash_table_v2_t *ip_table; /**< Table with blacklisted IPs gained from DNS thread */
    /*@}*/
} ip_params_t;

#ifdef __cplusplus
}
#endif

#endif /* DNSBLACKLISTFILTER_H */