/**
 * \file entropy.c
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

#include <stdint.h>
#include <math.h>
#include <string.h>
#include "entropy.h"


/**
 * \defgroup entropy
 * @{
 */

#define ENT_DATA_SIZE 257
#define ENT_DATA_TOT_IND (ENT_DATA_SIZE - 1)

static uint32_t *ent_probs = NULL;
static uint32_t ent_total;

void ent_reset(uint32_t **ent_data)
{
   uint32_t **d = (uint32_t **) ent_data;
   if ((*d) == NULL) {
      (*d) = (uint32_t *) calloc(1, ENT_DATA_SIZE*sizeof(uint32_t));
   }
   memset((*d), 0, ENT_DATA_SIZE*sizeof((*ent_data)[0]));
}

void ent_put_data(uint32_t *ent_data, unsigned char *data, uint32_t data_size)
{
   uint32_t i;
   uint32_t *d = (uint32_t *) ent_data;
   for (i=0; i<data_size; ++i) {
      d[data[i]]++;
      d[ENT_DATA_TOT_IND]++;
   }
}

/**
 * \brief Compute entropy from given data in data with size
 * \param [in] data           pointer to data - source of entropy
 * \param [in] data_size      length of data
 * \param [in] last_entropy   previous result of get_entropy, for first call
 * give 0.0
 * \return new entropy
 */
double ent_get_entropy(uint32_t *ent_data)
{
   double p, entropy = 0.0;
   uint32_t i;
   uint32_t ent_total = *((uint32_t *) ent_data + ENT_DATA_TOT_IND);
   uint32_t *ent_probs = (uint32_t *) ent_data;

   for(i=0; i<256; i++) {
      if (ent_probs[i] == 0) continue;
      p = (double) ent_probs[i] / (double) ent_total;
      entropy -= p*log2(p);
   }

   return entropy;
}

void ent_free(uint32_t **d)
{
   if ((*d) != NULL) {
      free(*d);
      (*d) = NULL;
   }
}

/**
* @}
*/

