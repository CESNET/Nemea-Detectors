/**
 * \file sip_detector.h
 * \brief Saves SIP statistics to memory and periodically saves them to stats.txt.
 * \author Nikolas Jisa <jisaniko@fit.cvut.cz>
 * \author Katerina Pilatova <xpilat05@stud.fit.vutbr.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2013,2014 CESNET
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

#ifndef _SIP_DETECTOR_H
#define	_SIP_DETECTOR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <execinfo.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <unirec/unirec.h>
#include <libtrap/trap.h>

#include <nemea-common.h>

#include "sip_constants.h"
#include "sip_ip_entry.h"
#include "sip_stats.h"


/* Structure with information about module. */
trap_module_info_t module_info = {
   "sip-detector module", // Module name
   "Module for detecting SIP attacks.\n"// Module description
   "Interfaces:\n"
   "    Inputs: 1 (flow records)\n"
   "    Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};

/**
 * \brief Entry point of the application.
 */
int main(int argc, char** argv);

/**
 * \brief Save ip_entries in ht_ips to file.
 * 
 * \param ht_ips Pointer to hash table to save
 *
 * Files are saved to (SIP_STATISTICS_DIRECTORY). Their names are (SIP_STATISTICS_FILE_NAME_PREFIX)(starttime of program)(SIP_STATISTICS_TIME_SEPARATOR)(time of file generation)(SIP_STATISTICS_FILE_NAME_SUFFIX).
 */
void sip_detector_save_statistics(cc_hash_table_v2_t* ht_ips);

/**
 * \brief Process via.
 *
 * \param ht_ips Pointer to hash table to update
 * \param tmplt Pointer to structure with format of the unirec data
 * \param data Pointer to unirec data
 *
 * Processes via field of the unirec message. Parsing is done via regular expressions (regex.h) and the regular expression is SIP_VIA_PATTERN.
 */
void sip_detector_process_via(cc_hash_table_v2_t* ht_ips, ur_template_t* tmplt, const void* data);

/**
 * \brief Print CSV header line to file.
 *
 * \param file Pointer to (opened) file where to save the header line.
 */
void sip_ip_entry_print_header(FILE* file);

/**
 * \brief Print accepted message (rather for debugging).
 *
 * \param file Pointer to (opened) file where to save the message
 * \param tmplt Pointer to structure with format of the unirec data
 * \param data Pointer to unirec data
 * \param data_size Size of the data
 */
void sip_detector_print_accepted_msg(FILE* file, ur_template_t* tmplt, const void* data, uint16_t data_size);

/**
 * \brief Update Request/Response counters.
 *
 * \param tmplt Pointer to structure with format of the unirec data
 * \param data Pointer to unirec data
 */
void sip_detector_update_counters(ur_template_t* tmplt, const void* data);

#ifdef __cplusplus
}
#endif

#endif
