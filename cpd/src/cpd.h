/**
 * \file cpd.h
 * \brief API for using CPD methods
 * \author Tomas Cejka <cejkat@cesnet.cz>
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
#ifndef _CPD_H
#define _CPD_H

struct cpd_method {
   const char *name;
   union cpd_privs *priv;
   double (*compute_next)(union cpd_privs *, double);
   void (*reset)(union cpd_privs *);
   double threshold;
};

#define CPD_METHODS_COUNT_DEFAULT   4
extern uint32_t cpd_methods_count;

void cpd_set_alert_callback(void (*cpd_alert_callback)(const char *method_name, double new_value, double xn, double threshold));

/**
 * \brief Initialize 3 default methods.
 *
 * Default methods are 1) COUNT (compares current value with thresholt)
 * 2) CUSUM (Page's CUSUM with probability computed according to probability
 * of normalized value with mean and variation from sliding window of size n)
 * 3) Non-parametric CUSUM (NP-CUSUM) 4) EWMA
 *
 * \param [in] thresholds     array with 4 double values for thresholds of methods
 * \param [in] npcusum_historical_est  1st parameter for NP-CUSUM
 * \param [in] npcusum_attact_est      2nd parameter for NP-CUSUM
 * \param [in] npcusum_tuning          3rd parameter for NP-CUSUM
 * \param [in] ewma_factor					1st parameter for EWMA - factor, must be power of 2 (Factor to use for the scaled up internal value. The maximum value of averages can be ULONG_MAX/(factor*weight).)
 * \param [in] ewma_weight					2nd parameter for EWMA - weight, must be power of 2 (how fast history decays)
 * \return pointer to methods initialized configuration
 */
struct cpd_method *cpd_default_init_methods(double *thresholds, double npcusum_historical_est, double npcusum_attack_est, double npcusum_tuning,
		uint32_t factor, uint32_t weight);

void cpd_run_methods(double new_value, struct cpd_method *methods, uint32_t methods_num);

void cpd_free_methods(struct cpd_method *methods, uint32_t methods_num);

#endif

