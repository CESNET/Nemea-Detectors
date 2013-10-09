/**
 * \file cpd.c
 * \brief Change-point detection module.
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
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <libtrap/trap.h>
#include "linux_ewma.h"

#include "cpd_common.h"
#include "cpd.h"
#ifdef SDM_CPD
//#define SDM_CPD_CREATEDATA
#ifdef SDM_CPD_CREATEDATA
#include <time.h>
#endif
#endif

#define M_SQRT2   1.41421356237309504880   /* sqrt(2) */
#define M_SQRT1_2   0.70710678118654752440   /* 1/sqrt(2) */

uint32_t cpd_methods_count = CPD_METHODS_COUNT_DEFAULT;

void (*cpd_alert_callback)(const char *method_name, double new_value, double xn, double threshold) = NULL;

struct cpd_np_cusum_priv {
   double previous; /**< Previous value */
   double hist_est; /**< Historical estimate of E(Xn) */
   #ifndef SDM_CPD
   double attack_est; /**< An estimate of E(Xn) under attact */
   double tuning;   /**< Tuning parameter */
   #endif
   double tuned_attack_est;   /**< Tuning * atta_est */
};

struct cpd_count_priv {
   double previous;
};

struct cpd_cusum_priv {
   double previous;
};

struct cpd_ewma_priv {
   struct ewma config;
};

union cpd_privs {
   struct cpd_np_cusum_priv np_cusum;
   struct cpd_count_priv counter;
   struct cpd_cusum_priv cusum;
   struct cpd_ewma_priv ewma;

   /* add others here */
};

/**
 * \defgroup np_cusum Non-parametric CUSUM (NP-CUSUM) method
 * @{
 */
double cpd_np_cusum(union cpd_privs *privs, double current_val)
{
   struct cpd_np_cusum_priv *p = &privs->np_cusum;
   double current;

   /* main formula */
   current = p->previous + current_val - p->hist_est - p->tuned_attack_est;
   current = MAX(0, current);

   p->previous = current;
   return current;
}

void cpd_np_cusum_init(union cpd_privs **priv, double hist_est, double attack_est, double tuning)
{
   if (priv == NULL) {
      fprintf(stderr, "Bad priv pointer, initialization was not successful.");
      return;
   }
   (*priv) = calloc(1, sizeof(union cpd_privs));
   (*priv)->np_cusum.hist_est = hist_est;
   #ifndef SDM_CPD
   (*priv)->np_cusum.attack_est = attack_est;
   (*priv)->np_cusum.tuning = tuning;
   #endif
   (*priv)->np_cusum.tuned_attack_est = attack_est * tuning;
}

void cpd_np_cusum_reset(union cpd_privs *privs)
{
   struct cpd_np_cusum_priv *p = &privs->np_cusum;
   p->previous = 0;
}
/**
 * @}
 */

/**
 * \defgroup page_cusum Page's CUSUM method
 * @{
 */
static sd_meanvar_data_t cusum_sd_data;

static inline double prob0(double current_val)
{
   double mean = 0;
   double var = 1;
   double varsq = 1;
   double x = current_val;
   SD_MEANVAR_ADD(&cusum_sd_data, current_val);
   if (cusum_sd_data.var == 0) {
      cusum_sd_data.var = 0.00000000001;
   }
   /* normalize current_val */
   x = (current_val - cusum_sd_data.mean) / sqrt(cusum_sd_data.var);

   /* get probability from: exp(-((x-mean)^2)/2*varsq) / sqrt(2*pi*varsq) */
   return M_SQRT1_2 * (M_SQRT2/2) * exp(-(pow(x - mean,2)/(2*varsq)))/var;
}

static inline double prob1(double current_val)
{
  return (1 - prob0(current_val));
}

double cpd_cusum(union cpd_privs *privs, double current_val)
{
   struct cpd_cusum_priv *p = &privs->cusum;
   double current;

   /* main formula */
   double prob0val = prob0(current_val);
   current = p->previous + log((1-prob0val)/prob0val);
   current = MAX(0, current);

   p->previous = current;
   return current;
}

void cpd_cusum_init(union cpd_privs **priv)
{
   if (priv == NULL) {
      fprintf(stderr, "Bad priv pointer, initialization was not successful.");
      return;
   }
   (*priv) = calloc(1, sizeof(union cpd_privs));
   SD_MEANVAR_INIT(&cusum_sd_data, 10);
}

void cpd_cusum_reset(union cpd_privs *privs)
{
   struct cpd_cusum_priv *p = &privs->cusum;
   p->previous = 0;
}
/**
 * @}
 */

/**
 * \defgroup counter Simple counter method
 * @{
 */
double cpd_count(union cpd_privs *privs, double current_val)
{
   struct cpd_count_priv *p = &privs->counter;

   /* main formula */
   p->previous = current_val;
   return current_val;
}

void cpd_count_init(union cpd_privs **priv)
{
   if (priv == NULL) {
      fprintf(stderr, "Bad priv pointer, initialization was not successful.");
      return;
   }
   (*priv) = calloc(1, sizeof(union cpd_privs));
}

void cpd_count_reset(union cpd_privs *privs)
{
}
/**
 * @}
 */

/**
 * \defgroup cpd_ewma   Using Exponential Weighted Moving Average for
 * Change-Point Detection
 * @{
 */
double cpd_ewma(union cpd_privs *privs, double current_val)
{
   struct cpd_ewma_priv *p = &privs->ewma;
   double difference, ewma_stat;
   ewma_add(&p->config, (unsigned long) current_val);
   ewma_stat = (double) ewma_read(&p->config);
   difference = abs(current_val - ewma_stat);
#ifdef DEBUG
   printf("\tEWMA: average: %f, abs.difference: %f\n",
         current_val, ewma_stat, difference);

#endif
   return difference;
}

void cpd_ewma_init(union cpd_privs **priv, uint32_t factor, uint32_t weight)
{
   struct cpd_ewma_priv *p;
   if (priv == NULL) {
      fprintf(stderr, "Bad priv pointer, initialization was not successful.");
      return;
   }
   (*priv) = calloc(1, sizeof(union cpd_privs));
   p = &(*priv)->ewma;
   ewma_init(&p->config, factor, weight);
}

void cpd_ewma_reset(union cpd_privs *privs)
{
   struct cpd_ewma_priv *p = &privs->ewma;
   p->config.internal = 0;
}
/**
 * @}
 */

void cpd_run_methods(double new_value, struct cpd_method *methods, uint32_t methods_num)
{
   int i;
   double xn;
   //printf("new value accepted: %f\n", new_value);
   for (i=0; i<methods_num; ++i) {
      xn = methods[i].compute_next(methods[i].priv, new_value);
#ifdef DEBUG
      printf("\t%s method, new statistic: %f threshold: %f\n",
            methods[i].name, xn, methods[i].threshold);
#endif
      if (ABS(xn) >= methods[i].threshold) {
         methods[i].reset(methods[i].priv);
         //fprintf(stderr, "%s: ALERT!!!\n", methods[i].name);
         if (cpd_alert_callback != NULL) {
            cpd_alert_callback(methods[i].name, new_value, xn, methods[i].threshold);
         } else {
            printf("ALERT: %s method, current value: %f statistic: %f threshold: %f\n",
                  methods[i].name, new_value, xn, methods[i].threshold);
         }
      }
   }
}

void cpd_free_methods(struct cpd_method *methods, uint32_t methods_num)
{
   int i;
   for (i=0; i<methods_num; ++i) {
      free(methods[i].priv);
   }
}

struct cpd_method *cpd_default_init_methods(double *thresholds, double npcusum_historical_est, double npcusum_attack_est, double npcusum_tuning,
      uint32_t ewma_factor, uint32_t ewma_weight)
{
   struct cpd_method *methods = (struct cpd_method *) malloc(sizeof(*methods) * cpd_methods_count);
   if (methods == NULL) {
      return (NULL);
   }

   methods[0].name = "COUNT";
   methods[0].compute_next = cpd_count;
   methods[0].reset = cpd_count_reset;
   methods[0].threshold = thresholds[0];
   cpd_count_init(&methods[0].priv);

   methods[1].name = "CUSUM";
   methods[1].compute_next = cpd_cusum;
   methods[1].reset = cpd_cusum_reset;
   methods[1].threshold = thresholds[1];
   cpd_cusum_init(&methods[1].priv);

   methods[2].name = "NP-CUSUM";
   methods[2].compute_next = cpd_np_cusum;
   methods[2].reset = cpd_np_cusum_reset;
   methods[2].threshold = thresholds[2];
   cpd_np_cusum_init(&methods[2].priv, npcusum_historical_est, npcusum_attack_est, npcusum_tuning);

   methods[3].name = "EWMA";
   methods[3].compute_next = cpd_ewma;
   methods[3].reset = cpd_ewma_reset;
   methods[3].threshold = thresholds[3];
   cpd_ewma_init(&methods[3].priv, ewma_factor, ewma_weight);

   return methods;
}

#ifdef TESTCPD_C
int main(int argc, char **argv)
{
   FILE *history = NULL;
   uint32_t *ent = NULL;
   sd_meanvar_data_t slidingwindow;
   uint32_t i;
   double values[] = {
      4,5,7,4,4,2,6,2,2,3,13,13,10,16,15,19,16,11,17,15
   };
   double thresholds[] = {
      10, 10, 10, 10
   };

   /* initialization of methods */
   struct cpd_method *methods = cpd_default_init_methods(thresholds, 5, 15, 0.0001, 16, 16);

   SD_MEANVAR_INIT(&slidingwindow, 3);

   history = fopen("history.log", "w");
   fprintf(history, "#mean meansq var entropy\n");
   for (i=0; i<10; ++i) {
      cpd_run_methods(values[i], methods, cpd_methods_count);
      SD_MEANVAR_ADD(&slidingwindow, values[i]);
      ent_reset(&ent);
      ent_put_data(ent, (char *) &values[i], sizeof(*values));
      fprintf(history, "%f\t%f\t%f\t%f\n", values[i], slidingwindow.mean, slidingwindow.var, ent_get_entropy(ent));
      fflush(history);
   }
   fclose(history);
   ent_free(&ent);

   SD_MEANVAR_FREE(&slidingwindow);

   cpd_free_methods(methods, cpd_methods_count);
   free(methods);

   return 0;
}
#endif


