/**
 * \file sliding_window.h
 * \brief Computation of statistics from sliding window
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
#ifndef _SLIDING_WINDOW_H
#define _SLIDING_WINDOW_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifndef DEBUG
#ifndef NDEBUG
#define NDEBUG
#endif
#endif

#include <assert.h>

/**
 * \defgroup slidingwindow
 * @{
 */

#define SD_MEANVAR_DATA_ELTYPE double

/**
 * Switch of dynamic allocation.
 *
 * if SD_MEANVAR_USE_ALLOC is set to 0, we must manually set
 * (data)->history before SD_MEANVAR_ADD!!!
 */
#define SD_MEANVAR_USE_ALLOC 1

#if (SD_MEANVAR_USE_ALLOC == 1)
#define SD_HIST_ALLOC(data, elementcount) (data)->history = calloc(1, 2 * elementcount * sizeof((data)->history[0]));
#else
#define SD_HIST_ALLOC(data, elementcount) memset(data, 0, elementcount * sizeof((data)->history[0]));
#endif

/**
 * Internal data for one sliding window.
 */
struct sd_meanvar_data {
   SD_MEANVAR_DATA_ELTYPE mean, meansq, sum, sumsq, var;
   uint32_t mvidx, size;
   uint32_t used_counter;
   SD_MEANVAR_DATA_ELTYPE *history;
};
typedef struct sd_meanvar_data sd_meanvar_data_t;

/**
 * \brief Macro for initialization of array according to size.
 *
 * \param [in,out] data   Pointer to sd_meanvar_data_t.
 */
#define SD_MEANVAR_INIT(data, elementcount) do { \
  SD_HIST_ALLOC(data, elementcount); \
  (data)->size = elementcount; \
  (data)->mean = 0; \
  (data)->mvidx = elementcount - 1; \
  (data)->meansq = 0; \
  (data)->sum = 0; \
  (data)->sumsq = 0; \
  (data)->used_counter = 0; \
} while (0);

/**
 * \brief Macro for compute new mean and variance from sliding window.
 *
 * \param [in,out] data    Should be pointer to sd_meanvar_data_t
 * \param [in] value       new value to add into storage, replacing oldest one
 */
#define SD_MEANVAR_ADD(data, value) do { \
  assert((data)->history != NULL); \
  if ((data)->used_counter < (data)->size) { \
     (data)->used_counter++; \
  } \
  /* reset index to 0 if it overflows the number of elements */ \
  (data)->mvidx = ((++((data)->mvidx)) >= (data)->size? 0 : ((data)->mvidx));  \
  /* E(X) */  \
  (data)->sum -= (data)->history[(data)->mvidx]; \
  (data)->history[(data)->mvidx] = value; \
  (data)->sum += value; \
  (data)->mean = ((data)->sum / (data)->used_counter); \
  /* E(X^2) */  \
  (data)->mvidx += (data)->size; \
  (data)->sumsq -= (data)->history[(data)->mvidx]; \
  (data)->history[(data)->mvidx] = pow(value,2); \
  (data)->sumsq += (data)->history[(data)->mvidx]; \
  (data)->meansq = ((data)->sumsq / (data)->used_counter); \
  (data)->history[(data)->mvidx] = pow(value,2); \
  (data)->var = (data)->meansq - pow((data)->mean,2); \
  (data)->mvidx -= (data)->size; \
} while (0);

/**
 * Reset history and start again.
 * \param [in,out] data    Should be pointer to sd_meanvar_data_t
 */
#define SD_MEANVAR_RESET(data) do { \
   (data)->used_counter = 0; \
   (data)->sum = 0; \
   (data)->sumsq = 0; \
} while (0);

#define SD_MEANVAR_FREE(data) do { \
   if ((data)->history != NULL) { \
      free((data)->history); \
      (data)->history = NULL; \
   } \
} while (0);

/**
 * @}
 */

#endif

