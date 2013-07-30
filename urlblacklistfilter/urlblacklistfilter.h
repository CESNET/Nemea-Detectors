/**
 * \file urlblacklistfilter.h
 * \brief URL blacklist detector for Nemea -- header file
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

#ifndef URLBLACKLISTFILTER_H
#define URLBLACKLISTFILTER_H

#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

#include "../../unirec/unirec.h"
#include "../../common/cuckoo_hash/cuckoo_hash.h"

/**
 * Constant returned if everything is ok.
 */
#define ALL_OK 0

/**
 * Initial size of the blacklist.
 */
#define BLACKLIST_DEF_SIZE 50000

/**
 * Consatnt returned by loading function if directory cannot be accessed
 */
#define BLIST_LOAD_ERROR -1

/**
 * Constant retuned by checking function if URL is prsent on blacklist.
 */
#define BLACKLISTED 1

/**
 * Constant retuned by checking function if URL is clear.
 */
#define URL_CLEAR 0

typedef struct {
    uint32_t url_hash;
    uint8_t bl;
} upd_item_t;

/*
 * Function for loading source files.
 */
int load_url(cc_hash_table_t& blacklist, std::string& path);

/*
 * Function for checking records.
 */
int check_blacklist(cc_hash_table_t& blacklist, ur_template_t* in, ur_template_t* out, const void* record, void* detect);

#ifdef __cplusplus
}
#endif

#endif /* URLBLACKLISTFILTER_H */
