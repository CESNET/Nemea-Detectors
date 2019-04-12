/**
 * \file urlblacklistfilter.h
 * \brief Module for detecting HTTP access to blacklisted URLs -- header file
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Filip Suster, <sustefil@fit.cvut.cz>
 * \date 2013-2018
 */

/*
 * Copyright (C) 2013,2014,2016,2018 CESNET
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
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <unirec/unirec.h>
/* include from nemea-common */
#include <prefix_tree.h>


/**
 * Constant returned if everything is ok.
 */
#define ALL_OK 0

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

/**
 * Allocation size for variable sized UniRec output template
 */
#define DETECTION_ALLOC_LEN 2048

#define WWW_PREFIX "www."

typedef struct __attribute__ ((__packed__)) {
    char blacklist_file[256];
    char watch_blacklists[8];
} url_config_t;

/**
 * Structure of item used in update operations.
 */
typedef struct {
    /*@{*/
    std::string url; /**< URL to update */
    uint64_t bl; /**< Source blacklist of the URL */
    /*@}*/
} url_elem_t;

typedef struct {
    uint64_t bl_id;
} url_info_t;

/**
 * Function for loading update files.
 */
int reload_blacklists(prefix_tree_t *tree, std::string &file);

/**
 * Function for checking records.
 */
int check_blacklist(prefix_tree_t *tree, ur_template_t *in, ur_template_t *out, const void *record, void *detect);

#ifdef __cplusplus
}
#endif

#endif /* URLBLACKLISTFILTER_H */
