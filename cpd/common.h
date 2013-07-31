/**
 * \file common.h
 * \brief Common functions and macros for CPD module etc
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
#ifndef _COMMON_H_CPD
#define _COMMON_H_CPD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

/**
 * \defgroup minmax
 * @{
 */

#ifndef MAX
#define MAX(a, b) (((a)>(b))?(a):(b))
#endif
#ifndef MIN
#define MIN(a, b) (((a)<(b))?(a):(b))
#endif
#ifndef ABS
#define ABS(a) (((a)>=0)?(a):(-(a)))
#endif

/**
 * @}
 */

/**
 * \defgroup slidingwindow
 * @{
 */

#define SD_MEANVAR_DATA_ELTYPE double

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
  (data)->size = elementcount; \
  (data)->history = calloc(1, 2 * elementcount * sizeof((data)->history[0])); \
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

#define SD_MEANVAR_FREE(data) do { \
   if ((data)->history != NULL) { \
      free((data)->history); \
      (data)->history = NULL; \
   } \
} while (0);

/**
 * @}
 */

/**
 * \defgroup entropy
 * @{
 */
void ent_reset();

double ent_get_entropy(unsigned char *data, uint32_t data_size, double last_entropy);

void ent_free();
/**
* @}
*/

#endif

