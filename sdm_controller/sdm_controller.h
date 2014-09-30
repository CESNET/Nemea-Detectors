/**
 * \file sdm_controller.h
 * \brief Header file for sdm_controller nemea module.
 * \author Matej Vido, xvidom00@stud.fit.vutbr.cz
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

#ifndef __SDM_CONTROLLER_H__
#define __SDM_CONTROLLER_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define DEFAULT_TIMEOUT 60 //number of seconds to capture
#define DEFAULT_PACKETS 10000 //number of packets to capture

#define MAX_ID_LENGTH UINT8_MAX
#define TIME_STR_LENGTH 20 //time in format YYYY-MM-DD-hh:mm:ss
#define MAX_EVENT_TYPE_LENGTH 20

//new detector add here
enum detectors {
   HOSTSTATS,
   DNS_AMPLIFICATION,
   SLOWTHREAT,
   SIP,
   DETECTORS_NUMBER,
};

/**
 * \brief Function sets value and converts to string IP address of attacker or of victim,
 *        if attacker's is not available.
 *
 * @param   in_template    Pointer to template of input interface.
 * @param   in_rec         Pointer to input record.
 * @param   ip_str         Pointer to memory where IP address in string form will be inserted.
 * @param   ip_value       Pointer to memory where IP value will be inserted.
 * @param   attck_id       Id of unirec field where attacker's IP is stored.
 * @param   victim_id      Id of unirec field where victim's IP is stored.
 * 
 * @return 0 on success.
 *         1 on failure.
 */
int get_correct_ip_str_and_value(ur_template_t * in_template, const void * in_rec, char *ip_str, ip_addr_t *ip_value, unsigned attck_id, unsigned victim_id);

/**
 * \brief Function converts unirec timestamp to string.
 *
 * @param   in_template    Pointer to template of input interface.
 * @param   in_rec         Pointer to input record.
 * @param   time_str       Pointer to memory where time string will be stored.
 * @param   timestamp_id   Id of unirec field where timestamp is stored.
 *
 * @return 0 on success.
 *         1 on failure.
 */
int get_time_str(ur_template_t * in_template, const void * in_rec, char *time_str, unsigned timestamp_id);

/**
 * \brief Main thread function.
 */
void *read_from_detector(void *arg);

#ifdef __cpluplus
}
#endif

#endif
