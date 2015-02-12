/**
 * \file sip_constants.h
 * \brief General macros of sip_detector
 * \author Nikolas Jíša <jisaniko@fit.cvut.cz>
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
#ifndef _SIP_CONSTANTS_H
#define _SIP_CONSTANTS_H

#ifdef	__cplusplus
extern "C" {
#endif

#define SIP_IP_STR_MAX_LEN 100
#define SIP_NAME_MAX_LEN 250
#define SIP_CALL_ID_MAX_LEN 250
#define SIP_VIA_MAX_LEN 250

/**
 * Number of sip_ip_entries for which to initialize the hash table.
 */
#define SIP_IP_ENTRIES_NUM 250000

/**
 * Maximum number of ip addresses that can be stored in one sip_circle_array_ips.
 */
#define SIP_MAX_DIFF_IPS 5

/**
 * Maximum number of names that can be stored in one sip_circle_array_names.
 */
#define SIP_MAX_DIFF_NAMES 5

/**
 * Maximum number of sip_calls that can be stored in one sip_circle_array_calls.
 */
#define SIP_MAX_DIFF_CALLS 5

/**
 * Regular expression (POSIX Extended)  against which to match via.
 */
#define SIP_VIA_PATTERN "SIP/2.0/(UDP|TCP) ([[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3}\\.[[:digit:]]{1,3})"

/**
 * Directory where to create files with statistics.
 */
#define SIP_STATISTICS_DIRECTORY "statistics"

/**
 * File name prefix of files with statistics.
 */
#define SIP_STATISTICS_FILE_NAME_PREFIX "statistics/"

/**
 * File name suffix of files with statistics.
 */
#define SIP_STATISTICS_FILE_NAME_SUFFIX ".csv"

/**
 * Maximum length of file name path isn't automatically checked with SIP_STATISTICS_DIRECTORY, SIP_STATISTICS_FILE_NAME_PREFIX, SIP_STATISTICS_FILE_NAME_SUFFIX and SIP_STATISTICS_TIME_MAX_LEN.
 */
#define SIP_STATISTICS_FILE_NAME_MAX_LEN 100

/**
 * Maximum length of time string (for file names of files with statistics).
 */
#define SIP_STATISTICS_TIME_MAX_LEN 25

/**
 * Format of time (for file names of files with statistics).
 */
#define SIP_STATISTICS_TIME_FORMAT "%Y_%m_%d_%H_%M_%S"

/**
 * Character to separate start time and end time in file name of file with statistics.
 */
#define SIP_STATISTICS_TIME_SEPARATOR "-"

/**
 * How often to save statistics to a new file [s].
 */
#define SIP_ALARM_PERIOD 1800

#ifdef __cplusplus
}
#endif

#endif
