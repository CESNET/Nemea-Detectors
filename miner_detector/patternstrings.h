/**
 * \file patternstrings.h
 * \brief Contains pattern string for nemea configurator for Nemea module detecting bitcoin miners.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \date 2016
 */

/*
 * Copyright (C) 2015 CESNET
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


#ifndef _IPBLACKLISTFILTER_PATTERN_H
#define _IPBLACKLISTFILTER_PATTERN_H

/**
 * String specifying pattern structure with default values.
 */
static char const *MODULE_CONFIG_PATTERN_STRING =
"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
"<configuration>"
    "<struct name=\"main struct\">"
        "<element type=\"optional\">"
            "<name>blacklist_file</name>"
            "<type size=\"256\">string</type>"
            "<default-value>-</default-value>"
        "</element>"
        "<element type=\"optional\">"
            "<name>whitelist_file</name>"
            "<type size=\"256\">string</type>"
            "<default-value>-</default-value>"
        "</element>"
        "<element type=\"optional\">"
            "<name>store_blacklist_file</name>"
            "<type size=\"256\">string</type>"
            "<default-value>-</default-value>"
        "</element>"
        "<element type=\"optional\">"
            "<name>store_whitelist_file</name>"
            "<type size=\"256\">string</type>"
            "<default-value>-</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>conn_timeout</name>"
            "<type>uint32_t</type>"
            "<default-value>10</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>read_timeout</name>"
            "<type>uint32_t</type>"
            "<default-value>10</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>timeout_active</name>"
            "<type>uint32_t</type>"
            "<default-value>300</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>timeout_inactive</name>"
            "<type>uint32_t</type>"
            "<default-value>60</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>check_period</name>"
            "<type>uint32_t</type>"
            "<default-value>60</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>stratum_check</name>"
            "<type size=\"8\">string</type>"
            "<default-value>false</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>score_treshold</name>"
            "<type>uint32_t</type>"
            "<default-value>7</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>suspect_db_size</name>"
            "<type>uint32_t</type>"
            "<default-value>1048576</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>suspect_db_stash_size</name>"
            "<type>uint32_t</type>"
            "<default-value>4</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>blacklist_db_size</name>"
            "<type>uint32_t</type>"
            "<default-value>1048576</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>blacklist_db_stash_size</name>"
            "<type>uint32_t</type>"
            "<default-value>4</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>whitelist_db_size</name>"
            "<type>uint32_t</type>"
            "<default-value>1048576</default-value>"
        "</element>"
        "<element type=\"required\">"
            "<name>whitelist_db_stash_size</name>"
            "<type>uint32_t</type>"
            "<default-value>4</default-value>"
        "</element>"
    "</struct>"
"</configuration>";

#endif
