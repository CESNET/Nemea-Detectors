/**
 * \file blacklist_downloader.h
 * \brief Header file for functions for downloading blackists from website.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2015
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

#ifndef _H_BLACKLIST_DOWN
#define _H_BLACKLIST_DOWN

#ifdef __cplusplus
extern "C" {
#endif


#include <regex.h>
#include <stdint.h>
#include <pthread.h>


/**
 * Blacklist downloader synchronization variable.
 */
uint8_t BLD_SYNC_FLAG;

/**
 * Mutex for synchronization.
 */
pthread_mutex_t BLD_SYNC_MUTEX;

/**
 *
 */
pthread_t BL_THREAD;

/**
 * Blacklist element structure.
 */
typedef struct {
   uint64_t id;
   char *id_name;
   char *source;
   uint8_t source_type;
   uint8_t bl_type;
} bl_down_blacklist_elem_t;


/**
 * Source type enum.
 */
enum bl_down_source_types {
    BL_STYPE_WEB,
    BL_STYPE_WARDEN
};

/**
 * Blacklist type enum. Max 256 items.
 */
enum bl_down_blaklist_types {
    BL_TYPE_MALWARE,
    BL_TYPE_CC_SERVER,
    BL_TYPE_SPAM,
    BL_TYPE_PHISH,
    BL_TYPE_TOR,
    BL_TYPE_DARKSPACE,
    BL_TYPE_PORTSCAN,
    BL_TYPE_BRUTEFORCE,
    BL_TYPE_PROBE,
    BL_TYPE_DOS,
    BL_TYPE_COPYRIGHT,
    BL_TYPE_WEBATTACK,
    BL_TYPE_OTHER
};

/**
 * Blaklists enum. Max 64 items.
 */
enum bl_down_blacklist_list {
  BL_MALWARE_DOMAINS,
  BL_ZEUS_TRACKER,
  BL_SPYEYE_TRACKER,
  BL_PALEVO_TRACKER,
  BL_FEODO_TRACKER,
  BL_SPAMHAUS,
  BL_PHISHTANK,
  BL_TOR,
  BL_WARDEN_DARKSPACE,
  BL_WARDEN_PORTSCAN,
  BL_WARDEN_BRUTEFORCE,
  BL_WARDEN_PROBE,
  BL_WARDEN_SPAM,
  BL_WARDEN_PHISH,
  BL_WARDEN_BOTNET,
  BL_WARDEN_DOS,
  BL_WARDEN_MALWARE,
  BL_WARDEN_COPYRIGHT,
  BL_WARDEN_WEBATTACK,
  BL_WARDEN_OTHER,
  BL_BLACKLIST_ELEM_COUNT    // Used as a count of blacklist elements, DO NOT remove, ADD new elements above it.
};

/**
 * Blacklist elements specification.
 */
static bl_down_blacklist_elem_t BL_ELEM_MALWARE_DOMAINS = {
   1ULL << BL_MALWARE_DOMAINS,
   (char *) "MALWARE_DOMAINS",
   (char *) "http://mirror2.malwaredomains.com/files/justdomains",
   BL_STYPE_WEB,
   BL_TYPE_MALWARE };
static bl_down_blacklist_elem_t BL_ELEM_ZEUS_TRACKER    = {
   1ULL << BL_ZEUS_TRACKER,
   (char *) "ZEUS_TRACKER",
   (char *) "https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",
   BL_STYPE_WEB,
   BL_TYPE_CC_SERVER };
static bl_down_blacklist_elem_t BL_ELEM_SPYEYE_TRACKER  = {
   1ULL << BL_SPYEYE_TRACKER,
   (char *) "SPYEYE_TRACKER",
   (char *) "https://spyeyetracker.abuse.ch/blocklist.php?download=ipblocklist",
   BL_STYPE_WEB,
   BL_TYPE_CC_SERVER };
static bl_down_blacklist_elem_t BL_ELEM_PALEVO_TRACKER  = {
   1ULL << BL_PALEVO_TRACKER,
   (char *) "PALEVO_TRACKER",
   (char *) "https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist",
   BL_STYPE_WEB,
   BL_TYPE_MALWARE };
static bl_down_blacklist_elem_t BL_ELEM_FEODO_TRACKER   = {
   1ULL << BL_FEODO_TRACKER,
   (char *) "FEODO_TRACKER",
   (char *) "https://feodotracker.abuse.ch/blocklist.php?download=ipblocklist",
   BL_STYPE_WEB,
   BL_TYPE_MALWARE };
static bl_down_blacklist_elem_t BL_ELEM_SPAMHAUS        = {
   1ULL << BL_SPAMHAUS,
   (char *) "SPAMHAUS",
   (char *) "http://www.spamhaus.org/drop/drop.txt",
   BL_STYPE_WEB,
   BL_TYPE_SPAM };
static bl_down_blacklist_elem_t BL_ELEM_PHISHTANK       = {
   1ULL << BL_PHISHTANK,
   (char *) "PHISHTANK",
   (char *) "http://data.phishtank.com/data/online-valid.csv",
   BL_STYPE_WEB,
   BL_TYPE_PHISH };
static bl_down_blacklist_elem_t BL_ELEM_TOR             = {
   1ULL << BL_TOR,
   (char *) "TOR",
   (char *) "http://torstatus.blutmagie.de/ip_list_exit.php",
   BL_STYPE_WEB,
   BL_TYPE_TOR };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_DARKSPACE = {
   1ULL << BL_WARDEN_DARKSPACE,
   (char *) "WARDEN_DARKSPACE",
   (char *) "darkspace",
   BL_STYPE_WARDEN,
   BL_TYPE_DARKSPACE };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_PORTSCAN = {
   1ULL << BL_WARDEN_PORTSCAN,
   (char *) "WARDEN_PORTSCAN",
   (char *) "portscan",
   BL_STYPE_WARDEN,
   BL_TYPE_PORTSCAN };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_BRUTEFORCE = {
   1ULL << BL_WARDEN_BRUTEFORCE,
   (char *) "WARDEN_BRUTEFORCE",
   (char *) "bruteforce",
   BL_STYPE_WARDEN,
   BL_TYPE_BRUTEFORCE };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_PROBE = {
   1ULL << BL_WARDEN_PROBE,
   (char *) "WARDEN_PROBE",
   (char *) "probe",
   BL_STYPE_WARDEN,
   BL_TYPE_PROBE };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_SPAM = {
   1ULL << BL_WARDEN_SPAM,
   (char *) "WARDEN_SPAM",
   (char *) "spam",
   BL_STYPE_WARDEN,
   BL_TYPE_SPAM };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_PHISH = {
   1ULL << BL_WARDEN_PHISH,
   (char *) "WARDEN_PHISH",
   (char *) "phishing",
   BL_STYPE_WARDEN,
   BL_TYPE_PHISH };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_BOTNET = {
   1ULL << BL_WARDEN_BOTNET,
   (char *) "WARDEN_BOTNET",
   (char *) "botnet_c_c",
   BL_STYPE_WARDEN,
   BL_TYPE_CC_SERVER };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_DOS = {
   1ULL << BL_WARDEN_DOS,
   (char *) "WARDEN_DOS",
   (char *) "dos",
   BL_STYPE_WARDEN,
   BL_TYPE_DOS };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_MALWARE = {
   1ULL << BL_WARDEN_MALWARE,
   (char *) "WARDEN_MALWARE",
   (char *) "malware",
   BL_STYPE_WARDEN,
   BL_TYPE_MALWARE };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_COPYRIGHT = {
   1ULL << BL_WARDEN_COPYRIGHT,
   (char *) "WARDEN_COPYRIGHT",
   (char *) "copyright",
   BL_STYPE_WARDEN,
   BL_TYPE_COPYRIGHT };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_WEBATTACK = {
   1ULL << BL_WARDEN_WEBATTACK,
   (char *) "WARDEN_WEBATTACK",
   (char *) "webattack",
   BL_STYPE_WARDEN,
   BL_TYPE_WEBATTACK };
static bl_down_blacklist_elem_t BL_ELEM_WARDEN_OTHER = {
   1ULL << BL_WARDEN_OTHER,
   (char *) "WARDEN_OTHER",
   (char *) "other",
   BL_STYPE_WARDEN,
   BL_TYPE_OTHER };


/**
 * Blacklist elements array. (For easy manipulation)
 */
static bl_down_blacklist_elem_t *BL_ELEM_AR[] = {
   &BL_ELEM_MALWARE_DOMAINS,
   &BL_ELEM_ZEUS_TRACKER,
   &BL_ELEM_SPYEYE_TRACKER,
   &BL_ELEM_PALEVO_TRACKER,
   &BL_ELEM_FEODO_TRACKER,
   &BL_ELEM_SPAMHAUS,
   &BL_ELEM_PHISHTANK,
   &BL_ELEM_TOR,
   &BL_ELEM_WARDEN_DARKSPACE,
   &BL_ELEM_WARDEN_PORTSCAN,
   &BL_ELEM_WARDEN_BRUTEFORCE,
   &BL_ELEM_WARDEN_PROBE,
   &BL_ELEM_WARDEN_SPAM,
   &BL_ELEM_WARDEN_PHISH,
   &BL_ELEM_WARDEN_BOTNET,
   &BL_ELEM_WARDEN_DOS,
   &BL_ELEM_WARDEN_MALWARE,
   &BL_ELEM_WARDEN_COPYRIGHT,
   &BL_ELEM_WARDEN_WEBATTACK,
   &BL_ELEM_WARDEN_OTHER,
};


/**
 * Update modes enum.
 */
enum BLDOWNLOADER_UPDATE_MODE {
   DEFAULT_UPDATE_MODE,
   DIFF_UPDATE_MODE
};



/**
 * Structure for passing arguments to blacklist downloader.
 */
typedef struct {
   uint64_t sites;
   char *file;
   char *comment_ar;
   char **reg_pattern;
   int num;
   int delay;
   int update_mode;
   uint8_t *use_regex;
   int line_max_length;
   int el_max_length;
   int el_max_count;
} bl_down_args_t;


/**
 * Structure for storing commands.
 */
typedef struct {
   char **ar;
   char cnt;
} bl_down_cmd_t;

/**
 * Structure for storing buffers.
 */
typedef struct {
   char *file;
   char *line;
   char **el_ar[2];
   uint32_t *blf_ar[2];
   int line_max_length;
   int el_max_length;
   int el_max_count;
} bl_down_buf_t;

/**
 * Structure for storing information about warden receiver scripts.
 */
typedef struct {
   int count;
   char *fnames[64];
} bl_down_warden_recv_scripts_t;


/**
 * Configure structure for blacklist downloader
 */
typedef struct {
   bl_down_cmd_t cmd;
   int delay;
   char *comment_ar;
   regex_t *preg;
   uint8_t *use_regex;
   int update_mode;
   uint64_t lut_id[64];
   bl_down_buf_t buf;
   bl_down_warden_recv_scripts_t warden_scripts;
} bl_down_config_t;


/**
 * Source code of Warden receiver.
 */
static char *BL_WARDEN_RECV_FILE_PL_SOURCE_CODE =
   (char*) // To stop C++ complaining about deprecated conversion
   "#!/usr/bin/perl -w\n"
   "# Copyright (C) 2011-2012 Cesnet z.s.p.o\n"
   "# Use of this source is governed by a BSD-style license, see LICENSE file.\n"
   "use strict;\n"
   "my $warden_path = '/opt/warden-client';\n"
   "require $warden_path . '/lib/WardenClientReceive.pm';\n"
   "my $req_type = $ARGV[0];\n"
   "my @new_events = WardenClientReceive::getNewEvents($warden_path, $req_type);\n"
   "no warnings 'uninitialized';\n"
   "foreach (@new_events) { print $$_[6] . \"\\n\"; }\n"
   "exit 0;\n";

/**
 * Warden sources bundle.
 */
static const uint64_t BL_WARDEN_SOURCES = 1LLU << BL_WARDEN_DARKSPACE  |
                                   1LLU << BL_WARDEN_PORTSCAN   |
                                   1LLU << BL_WARDEN_BRUTEFORCE |
                                   1LLU << BL_WARDEN_PROBE      |
                                   1LLU << BL_WARDEN_SPAM       |
                                   1LLU << BL_WARDEN_PHISH      |
                                   1LLU << BL_WARDEN_BOTNET     |
                                   1LLU << BL_WARDEN_DOS        |
                                   1LLU << BL_WARDEN_MALWARE    |
                                   1LLU << BL_WARDEN_COPYRIGHT  |
                                   1LLU << BL_WARDEN_WEBATTACK  |
                                   1LLU << BL_WARDEN_OTHER;


uint8_t bl_translate_to_id(char *str, uint64_t *sites);
int bl_down_init(bl_down_args_t *args);
void bld_finalize();
void bld_lock_sync();
void bld_unlock_sync();

#ifdef __cplusplus
}
#endif

#endif
