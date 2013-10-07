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
#include "cpd_common.h"
#ifdef HAVE_OMP_H
#include <omp.h>
#endif
#include "../../../common/cuckoo_hash_v2/cuckoo_hash.h"


/**
 * \defgroup entropy
 * @{
 */

#define ENT_DATA_SIZE 257
#define ENT_DATA_TOT_IND (ENT_DATA_SIZE - 1)

static uint32_t ent_total;

/* precomputed logarithms */
static float logarg[] =
#include "log2s.x"
static float logres[] =
#include "plog2s.data"
/* ---------------------- */

void ent_reset(uint32_t **ent_data)
{
   uint32_t **d = (uint32_t **) ent_data;
   if ((*d) == NULL) {
      (*d) = (uint32_t *) calloc(1, ENT_DATA_SIZE*sizeof(uint32_t));
   }
   memset((*d), 0, ENT_DATA_SIZE*sizeof((*ent_data)[0]));
}

void ent_put_data(uint32_t *ent_data, char *data, uint32_t data_size)
{
   uint32_t i;
   int32_t *d = (int32_t *) ent_data;
   for (i=0; i<data_size; ++i) {
      d[(unsigned char) data[i]]++;
      d[ENT_DATA_TOT_IND]++;
   }
}

void ent_put_data_hash(uint32_t *ent_data, char *data, uint32_t data_size)
{
   uint32_t i;
   uint32_t *d = (uint32_t *) ent_data;
   for (i=0; i<data_size; ++i) {
      d[(unsigned char) data[i]]++;
      d[ENT_DATA_TOT_IND]++;
   }
}

static int logargs_compar(const void *a, const void *b)
{
   if (*((float *)a) == *((float *) b)) {
      return 0;
   } else if (*((float *) a) < *((float *) b)) {
      return -1;
   } else {
      return 1;
   }
}

#ifdef DEBUG
uint64_t ent_cache_miss = 0;
uint64_t ent_cache_hit = 0;
#endif

static inline double ent_compute_entropy(uint32_t nmemb, uint32_t total)
{
	double p = (double) nmemb / (double) ent_total;
   float fp = ((int)(p * 1000000.0 + (p<0? -0.5 : 0.5))) / 1000000.0;
   float *pcr; ///< precomputed result
	pcr = (float *) bsearch(&fp, logarg, (sizeof(logarg) / sizeof(*logarg)),
			sizeof(*logarg), logargs_compar);
	if (pcr == NULL) {
#ifdef DEBUG
		ent_cache_miss++;
#endif
		return p*log2(p);
	} else {
#ifdef DEBUG
		ent_cache_hit++;
#endif
		return logres[pcr - logarg];
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
   double entropy = 0.0;
   uint32_t i;
   uint32_t ent_total = *((uint32_t *) ent_data + ENT_DATA_TOT_IND);
   uint32_t *ent_probs = (uint32_t *) ent_data;

   for(i=0; i<256; i++) {
      if (ent_probs[i] == 0) continue;
		entropy -= ent_compute_entropy(ent_probs[i], ent_total);
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

/**
 * \defgroup cuckoohashentropy
 * @{
 */
typedef struct ent_hash_private {
	unsigned int table_size;
	unsigned int data_size;
	unsigned int key_length;
	cc_hash_table_v2_t hashtable;
} ent_hash_priv_t;

/**
 * \param [in] table_size	number of entries
 * \param [in] key_length	size of data in bytes for entropy computing (e.g. TCP dst port ~ 2)
 */
ent_hash_t *ent_hash_init(unsigned int table_size, unsigned int key_length)
{
	ent_hash_priv_t *priv = (ent_hash_priv_t *) calloc(1, sizeof(ent_hash_priv_t));
	priv->table_size = table_size;
	priv->key_length = key_length;
	ht_init_v2(&priv->hashtable, table_size, sizeof(uint32_t), key_length);
	return ((void *) priv);
}

/**
 * \param [in] inst	private data
 * \param [in] data	data for entropy computing, size should be equal to key_length from ent_hash_init()
 */
void ent_hash_put_data(ent_hash_t *inst, char *data)
{
	ent_hash_priv_t *priv = (ent_hash_priv_t *) inst;
	uint32_t counter = 0;
	int index = ht_get_index_v2(&priv->hashtable, data);
	if (index == -1) {
		ht_insert_v2(&priv->hashtable, data, (void *) &counter);
	} else {
		/* key already exists, increment counter */
		*((uint32_t *) priv->hashtable.data[index]) += 1;
	}
}

double ent_hash_get_entropy(ent_hash_t *ent_data) {
	ent_hash_priv_t *priv = (ent_hash_priv_t *) ent_data;
	uint32_t i;
	uint32_t total = 0;
	double entropy = 0.0;
	for (i=0; i<priv->table_size; ++i) {
		if ((priv->hashtable.ind[i].valid == 1) &&
				(*((uint32_t *) priv->hashtable.data[priv->hashtable.ind[i].index]) > 0)) {
			total++;
		}
	}
	for (i=0; i<priv->table_size; ++i) {
		if ((priv->hashtable.ind[i].valid == 1) &&
				(*((uint32_t *) priv->hashtable.data[priv->hashtable.ind[i].index]) > 0)) {
			entropy -= ent_compute_entropy(*((uint32_t *) priv->hashtable.data[priv->hashtable.ind[i].index]), total);
		}
	}
	return entropy;
}

void ent_hash_reset(ent_hash_t *ent_data)
{
	ent_hash_priv_t *priv = (ent_hash_priv_t *) ent_data;
	ht_clear_v2(&priv->hashtable);
}

void ent_hash_free(ent_hash_t **ent_data)
{
	ent_hash_priv_t *priv = *((ent_hash_priv_t **) ent_data);
	ht_destroy_v2(&priv->hashtable);
	free(priv);
	(*ent_data) = NULL;
}

/**
 * @}
 */

/**
 * \defgroup superhashentropy
 * @{
 */

#include "../../../common/super_fast_hash/super_fast_hash.h"

typedef struct ent_shash_private {
	unsigned int table_size;
	unsigned int data_size;
	unsigned int key_length;
	uint32_t *hashtable;
	uint64_t data_count;
} ent_shash_priv_t;

/**
 * \param [in] table_size	number of entries
 * \param [in] key_length	size of data in bytes for entropy computing (e.g. TCP dst port ~ 2)
 */
ent_shash_t *ent_shash_init(unsigned int table_size, unsigned int key_length)
{
	ent_shash_priv_t *priv = (ent_shash_priv_t *) calloc(1, sizeof(ent_shash_priv_t));
	priv->table_size = table_size;
	priv->key_length = key_length;
	priv->hashtable = (uint32_t *) calloc(table_size, sizeof(uint32_t));
	return ((void *) priv);
}

/**
 * \param [in] inst	private data
 * \param [in] data	data for entropy computing, size should be equal to key_length from ent_shash_init()
 */
void ent_shash_put_data(ent_shash_t *inst, char *data)
{
	ent_shash_priv_t *priv = (ent_shash_priv_t *) inst;
	uint32_t key = SuperFastHash(data, priv->key_length);
	priv->hashtable[key % priv->table_size]++;
	priv->data_count++;
}

double ent_shash_get_entropy(ent_shash_t *ent_data) {
	ent_shash_priv_t *priv = (ent_shash_priv_t *) ent_data;
	uint32_t i;
	double entropy = 0.0;
	for (i=0; i<priv->table_size; ++i) {
		if (priv->hashtable[i] > 0) {
			entropy -= ent_compute_entropy(priv->hashtable[i], priv->data_count);
		}
	}
	return entropy;
}

void ent_shash_reset(ent_shash_t *ent_data)
{
	ent_shash_priv_t *priv = (ent_shash_priv_t *) ent_data;
	memset(priv->hashtable, 0, priv->table_size * sizeof(*priv->hashtable));
	priv->data_count = 0;
}

void ent_shash_free(ent_shash_t **ent_data)
{
	ent_shash_priv_t *priv = *((ent_shash_priv_t **) ent_data);
	if (priv->hashtable != NULL) {
		free(priv->hashtable);
	}
	free(priv);
	(*ent_data) = NULL;
}

/**
 * @}
 */
