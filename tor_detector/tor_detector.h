/**
 * \file tor_detector.c
 * \brief Nemea module for detecting TOR exit nodes.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2014
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



#define ALLOC_STEP_COUNT 50
#define MAX_DYN_SIZE 1024
#define UPDATE_DELAY_TIME 3600

const char *TOR_FLAGS_FIELD_STRING = ",TOR_FLAGS";
char *UPDATE_FILE_NAME = "update.txt";
char *BLACKLIST_URL    = "http://torstatus.blutmagie.de/ip_list_exit.php";


typedef struct {
   ip_addr_t *ip_ar;
   int count;
   int allocated;
} tor_list_t;


