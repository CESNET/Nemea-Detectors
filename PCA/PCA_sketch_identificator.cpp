/**
 * \file PCA_sketch_identificator.c
 * \brief Module for detection of network anomalies using PCA and sketch
 *        subspaces - identification part.
 * \author Pavel Krobot <xkrobo01@stud.fit.vutbr.cz>
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
#include <signal.h>
#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

#include "PCA_sketch.h"

using namespace std;

#define USE_JOINT_MATRIX_OP
#define VERBOSE_MSG
//#define DEBUG

// ******** TEMPORARY:  IN FUTURE SHOULD BE IN "common.h ***********************
/*
 * SuperFastHash by Paul Hsieh
 * http://www.azillionmonkeys.com/qed/hash.html
 */

#include <stdint.h>
#undef get16bits
#if (defined(__GNUC__) && defined(__i386__)) || defined(__WATCOMC__) \
  || defined(_MSC_VER) || defined (__BORLANDC__) || defined (__TURBOC__)
#define get16bits(d) (*((const uint16_t *) (d)))
#endif

#if !defined (get16bits)
#define get16bits(d) ((((uint32_t)(((const uint8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const uint8_t *)(d))[0]) )
#endif

uint32_t SuperFastHash(const char *data, int len, int seed) {
   uint32_t hash = len + seed, tmp;
   int rem;

    if (len <= 0 || data == NULL) return 0;

    rem = len & 3;
    len >>= 2;

    /* Main loop */
    for (;len > 0; len--) {
        hash  += get16bits (data);
        tmp    = (get16bits (data+2) << 11) ^ hash;
        hash   = (hash << 16) ^ tmp;
        data  += 2*sizeof (uint16_t);
        hash  += hash >> 11;
    }

    /* Handle end cases */
    switch (rem) {
        case 3: hash += get16bits (data);
                hash ^= hash << 16;
                hash ^= data[sizeof (uint16_t)] << 18;
                hash += hash >> 11;
                break;
        case 2: hash += get16bits (data);
                hash ^= hash << 11;
                hash += hash >> 17;
                break;
        case 1: hash += *data;
                hash ^= hash << 10;
                hash += hash >> 1;
    }

    /* Force "avalanching" of final 127 bits */
    hash ^= hash << 3;
    hash += hash >> 5;
    hash ^= hash << 4;
    hash += hash >> 17;
    hash ^= hash << 25;
    hash += hash >> 6;

    return hash;
}

// ***************** END OF TEMPORARY ******************************************

// Struct with information about module
trap_module_info_t module_info = {
   // Module name
   "Module for anomaly detection using PCA and sketch subspaces.\n",
   // Module description
   "  This module detecting network anomalies in flow time series.\n"
   ""
   "Interfaces:\n"
   "  Inputs (1):\n"
   "    >> 1. UniRec (SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,"
                     "TIME_LAST,PACKETS,BYTES,TCP_FLAGS)\n"
   "        - flows from network traffic.\n\n"
   "  Outputs (2):\n"
   "    << 1. UniRec (TIME_FIRST,TIME_LAST):\n"
   "        - preliminary information about time in witch an anomaly(-ies) "
               "occuring.\n"
   "    << 2. UniRec (SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,"
                     "TIME_LAST,PACKETS,BYTES,TCP_FLAGS)\n"
   "        -  flow(s) responsible for an anomaly(-ies)\n",
   1, // Number of input interfaces
   2, // Number of output interfaces
};

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);


uint32_t get_row_in_sketch (ur_template_t *tmplt, const void *rec, int seed)
{
   uint64_t tmp_addr_part;
   uint64_t hash_key[4];
   int hk_size;

   memset(hash_key, 0, sizeof(hash_key));
   if (ip_is4(ur_get_ptr(tmplt, rec, UR_SRC_IP))){ // IPv4
      tmp_addr_part = ip_get_v4_as_int(ur_get_ptr(tmplt, rec, UR_SRC_IP)) & V4_HASH_KEY_MASK;
      hash_key[0] |= tmp_addr_part << (V4_BIT_LENGTH); // left aligment on 64 bits of uint64_t
      tmp_addr_part = ip_get_v4_as_int(ur_get_ptr(tmplt, rec, UR_DST_IP)) & V4_HASH_KEY_MASK;
      hash_key[0] |= tmp_addr_part << (V4_BIT_LENGTH - V4_HASH_KEY_PART);
      hk_size = sizeof(hash_key[0]);
   } else { // IPv6
     #if V6_HASH_KEY_PART == V6_BIT_PART_LENGTH
      hash_key[0] = ur_get(tmplt, rec, UR_SRC_IP).ui64[0];
      hash_key[1] = ur_get(tmplt, rec, UR_DST_IP).ui64[0];
      hk_size = sizeof(hash_key[0]) * 2;
     #elif V6_HASH_KEY_PART == V6_BIT_PART_LENGTH*2
      hash_key[0] = ur_get(tmplt, rec, UR_SRC_IP).ui64[0];
      hash_key[1] = ur_get(tmplt, rec, UR_SRC_IP).ui64[1];
      hash_key[2] = ur_get(tmplt, rec, UR_DST_IP).ui64[0];
      hash_key[3] = ur_get(tmplt, rec, UR_DST_IP).ui64[1];
      hk_size = sizeof(hash_key);
     #elseif V6_HASH_KEY_PART < V6_BIT_PART_LENGTH
      tmp_addr_part = ur_get(tmplt, rec, UR_SRC_IP).ui64[0] & V6_HASH_KEY_MASK;
      hash_key[0] |= tmp_addr_part;
      tmp_addr_part = ur_get(tmplt, rec, UR_DST_IP).ui64[0] & V6_HASH_KEY_MASK;
      hash_key[0] |= tmp_addr_part >> V6_HASH_KEY_PART;
      hash_key[1] |= tmp_addr_part << (V6_BIT_PART_LENGTH - V6_HASH_KEY_PART);
      hk_size = sizeof(hash_key[0]) * 2;
     #else // V6_HASH_KEY_PART > V6_BIT_PART_LENGTH
      hash_key[0] = ur_get(tmplt, rec, UR_SRC_IP).ui64[0];
      tmp_addr_part = ur_get(tmplt, rec, UR_SRC_IP).ui64[1] & V6_HASH_KEY_MASK;
      hash_key[1] |= tmp_addr_part;
      tmp_addr_part = ur_get(tmplt, rec, UR_DST_IP).ui64[0];
      hash_key[1] |= tmp_addr_part >> (V6_HASH_KEY_PART % 64);
      hash_key[2] |= tmp_addr_part << (V6_BIT_PART_LENGTH - (V6_HASH_KEY_PART % 64));
      tmp_addr_part = ur_get(tmplt, rec, UR_DST_IP).ui64[1] & V6_HASH_KEY_MASK;
      hash_key[2] |= tmp_addr_part >> (V6_HASH_KEY_PART % 64);
      hash_key[3] |= tmp_addr_part << (V6_BIT_PART_LENGTH - (V6_HASH_KEY_PART % 64));
      hk_size = sizeof(hash_key);
     #endif
   }
   return SuperFastHash((char *)hash_key, hk_size, seed) % SKETCH_SIZE;
}

/**
 * \brief Provedure computes standard deviation from vector (1st version).
 *
 * Provedure computes standard deviation from vector in two different ways - two
 * versions (according to: http://www.mathworks.com/help/matlab/ref/std.html).
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation (float *vector_ptr, unsigned int vector_size)
{
   float sum=0;
//  SINCE VALUES_ARE_MEAN_CENTERED - HAVE_ZERO_MEAN >> Simplier version:
   for (int i = 0; i < vector_size; i++){
      sum += vector_ptr[i] * vector_ptr[i];
   }
//   printf("\tSUM: %f ---------------------------\n", sum);
   return sqrt(sum / vector_size);
}
/**
 * \brief Provedure computes standard deviation from vector (2nd version).
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation_v2(float *vector_ptr, unsigned int vector_size)
{
   float sum = 0, tmp;
   float mean = 0;

   for (int i = 0; i < vector_size; i++){
      mean += vector_ptr[i];
   }
//   printf("MEAN: %f ---------------------------\n", mean);
   mean /= vector_size;

   for (int i = 0; i < vector_size; i++){
      tmp = vector_ptr[i] - mean;
      sum += tmp * tmp;
   }
//   printf("\tSUM: %f ---------------------------\n", sum);

//   return sqrt(sum / (vector_size));
   return sqrt(sum / (vector_size-1));
}



/**
 * \brief Procedure computes entropy of one sketch row
 * \param[in] sketch_row Pointer to sketch row which values will be processed.
 * \param[in] row_length Length of processed row.
 * \param[in] packet_count Total count of all packets in flows in processed row.
 * \return Entropy of one sketch row.
 */
float compute_entropy (uint32_t *sketch_row, unsigned int row_length, uint64_t packet_count)
{
   float entropy = 0.0;
   for (int i = 0; i < row_length; i++)
   {
      if (sketch_row[i] > 0){
         float p = (float) sketch_row[i] / packet_count;
         entropy -= p * log2(p);
      }
   }
   return entropy;
}

// ***************** MATRIX OPERATIONS *****************************************
/**
 * \brief Procedure transforms columns of matrix to have zero mean
 * \param[in,out] matrix_ptr Pointer to matrix which should be normalized.
 */
void transform_matrix_zero_mean (real_2d_array *matrix_ptr)
{
   float mean;

   for (int i = 0; i < matrix_ptr->cols(); i++){
      mean = 0;
      for (int j = 0; j < matrix_ptr->rows(); j++){
         mean += (*matrix_ptr)(j, i);
      }
      mean /= matrix_ptr->rows();
      for (int j = 0; j < matrix_ptr->rows(); j++){
         (*matrix_ptr)(j,i) -= mean;
      }
   }
}

/**
 * \brief Procedure transforms submatrix of matrix to have unit energy.
 *
 * Procedure transforms submatrix of "matrix_ptr", defined by column
 * "start_index" and "last_index", to unit energy (last_index is first which
 * IS NOT affected)
 * \param[in,out] matrix_ptr Pointer to matrix which contains submatrix which
 * should be normalized.
 * \param[in] start_index First column of submatrix (column of matrix from
 * matrix_ptr).
 * \param[in] last_index Last column of submatrix (first column which is not
 * affected) (column of matrix from matrix_ptr).
 */
void  transform_submatrix_unit_energy (real_2d_array *matrix_ptr,
                                       int start_index,
                                       int last_index)
{
   float energy_of_submatrix = 0;

   for (int i = start_index; i < last_index; i++){
      for (int j = 0; j < matrix_ptr->rows(); j++){
         energy_of_submatrix += (*matrix_ptr)(j,i) * (*matrix_ptr)(j,i);
      }
   }
   energy_of_submatrix /= (matrix_ptr->rows() *  (last_index-start_index));

   for (int i = start_index; i < last_index; i++){
      for (int j = 0; j < matrix_ptr->rows(); j++){
         (*matrix_ptr)(j,i) /= energy_of_submatrix;
      }
   }
}

// ***************

float multiply_and_norm (float **A_matrix_ptr,
                     unsigned int A_matrix_size,
                     real_2d_array *B_matrix_ptr,
                     unsigned int row_selector)
{
   uint16_t y;
   float row_sum;
   float sum = 0;;

   for (int i = 0; i < A_matrix_size; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < A_matrix_size; j++){
         row_sum += A_matrix_ptr[y][j] * (*B_matrix_ptr)(row_selector,j);
      }

      sum += row_sum * row_sum;
   }
   return sqrt(sum);
}
/**
 * \brief Procedure multiplies submatrix of matrix and same submatrix
 * transposed.
 *
 * Procedure multiplies submatrix of "matrix_ptr" defined by first column (index
 *  0) and parameter (column_delimiter) with the same submatrix transposed.
 * \param[in] matrix_ptr Source matrix.
 * \param[in] column_delimiter Specifies size of submatrix (column count).
 * \param[out] result_ptr Pointer to square matrix for result - size is
 *  calculated from matrix dimensions.
 */
void multiply_submatrix_by_transposed_submatrix (real_2d_array *matrix_ptr,
                                                 uint16_t column_delimiter,
                                                 float **result_ptr)
{
   uint16_t x,y;
   float row_sum;

   for (int i = 0; i < (matrix_ptr->rows() * matrix_ptr->rows()); i++){
      row_sum = 0;

      x = i / matrix_ptr->rows();
      y = i % matrix_ptr->rows();

      for (int j = 0; j < column_delimiter; j++){
         row_sum += (*matrix_ptr)(x,j) * (*matrix_ptr)(y,j);
      }

      result_ptr[x][y] = row_sum;
   }
}

/**
 * \brief Procedure multiplies matrix and transposed row of another matrix.
 * Procedure multiplies first matrix and transposed row of second matrix defined
 * by parameter (row_selector).
 * \param[in] A_matrix_ptr Pointer to first square matrix.
 * \param[in] A_matrix_size Size of first matrix.
 * \param[in] B_matrix_ptr Pointer to second matrix, which contains row, which
 * is used as column vector (transposed row).
 * \param[in] row_selector Specifies row of B_matrix_ptr.
 * \param[out] result_ptr Pointer to vector for result - size is calculated from
 *  matrix dimensions.
 */
void multiply_matrix_by_transposed_line (float **A_matrix_ptr,
                                         unsigned int A_matrix_size,
                                         real_2d_array *B_matrix_ptr,
                                         unsigned int row_selector,
                                         float *result_ptr)
{
   uint16_t y;
   float row_sum;

   for (int i = 0; i < A_matrix_size; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < A_matrix_size; j++){
         row_sum += A_matrix_ptr[y][j] * (*B_matrix_ptr)(row_selector,j);
      }

      result_ptr[i] = row_sum;
   }
}

/**
 * \brief Procedure which multiplies matrix by vector.
 *
 * Procedure multiplies source matrix by column of second matrix (vector).
 * Return result in third.
 * \param[in] A_matrix_ptr Pointer to first matrix (A).
 * \param[in] B_matrix_ptr Pointer to second matrix (B).
 * \param[in] B_matrix_column Value which specifies column of second matrix (B).
 * \param[out] result Pointer to vector for result - size is calculated from
 *  matrix dimensions.
 */
void multiply_matrix_column_vector (real_2d_array *A_matrix_ptr,
                                    real_2d_array *B_matrix_ptr,
                                    unsigned int B_matrix_column,
                                    float *result)
{
   float row_sum;
//  if (A_matrix_ptr->cols()==B_matrix_ptr->rows()){ //check if matrixes have proper size
   for (int i = 0; i < A_matrix_ptr->rows(); i++){
      row_sum = 0;
      for (int j = 0; j < A_matrix_ptr->cols(); j++){
         row_sum += (*A_matrix_ptr)(i,j) * (*B_matrix_ptr)(j,B_matrix_column);
      }
      result[i] = row_sum;
   }
//  }
}

/**
 * \brief Procedure computes norm of vector
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Returns real (float) value.
 */
float norm_of_vector (float *vector_ptr, unsigned int vector_size)
{
   float sum = 0;

   for (int i = 0; i < vector_size; i++){
      sum += vector_ptr[i] * vector_ptr[i];
   }

   return sqrt(sum);
}

/**
 * \brief Procedure divides vector by value.
 *
 * Procedure divides vector by value - overwrite original vector.
 * \param[in] vector_ptr Pointer to vector which should by divided.
 * \param[in] vector_size Size of vector which should by divided.
 * \param[in] Real (float) value by which should be vector divided.
 */
void divide_vector_by_value (float *vector_ptr, unsigned int vector_size, float divider)
{
   for (int i = 0; i < vector_size; i++){
      vector_ptr[i] /= divider;
   }
}

/**
 * \brief Procedure substitutes square matrix from identity matrix of same size.
 * Overwrites original matrix.
 * \param[in,out] matrix_ptr Pointer to matrix.
 * \param[in] matrix_size Size of matrix.
 */
void substitute_from_identity_matrix (float **matrix_ptr, unsigned int matrix_size)
{
   for (int i = 0; i < matrix_size; i++){
      matrix_ptr[i][i] = 1 - matrix_ptr[i][i];
      for (int j = 0; j < i; j++){
         matrix_ptr[i][j] = 0 - matrix_ptr[i][j];
      }
      for (int j = i+1; j < matrix_size; j++){
         matrix_ptr[i][j] = 0 - matrix_ptr[i][j];
      }
   }
}

// ***************

///**
// * \brief Procedure multiplies square matrix with column vector (float array).
// * \param[in] A_matrix_ptr Pointer to square matrix.
// * \param[in] A_matrix_size Size of square matrix.
// * \param[in] B_matrix_ptr Pointer to vector - size is calculated from
// *  A_matrix dimensions (must correspond).
// * \param[out] result_ptr Pointer to vector for result - size is calculated from
// *  A_matrix dimensions.
// */
//void multiply_matrix_by_vector (float **A_matrix_ptr,
//                                unsigned int A_matrix_size,
//                                float *B_matrix_ptr,
//                                float *result_ptr)
//{
//   uint16_t y;
//   float row_sum;
//
//   for (int i = 0; i < A_matrix_size; i++){
//      row_sum = 0;
//
//      y = i;
//
//      for (int j = 0; j < A_matrix_size; j++){
//         row_sum += A_matrix_ptr[y][j] * B_matrix_ptr[j];
//      }
//
//      result_ptr[i] = row_sum;
//   }
//}
//
///**
// * \brief Procedure multiplies matrix and transposed another matrix - overloaded
// *  for different parameters (2x).
// * \param[in] A_matrix_ptr Pointer to first matrix.
// * \param[in] B_matrix_ptr Pointer to second matrix (will be transposed in
// * computation).
// * \param[out] result_ptr Pointer to matrix for result.
// */
//void multiply_matrix_by_transposed_matrix (float **A_matrix_ptr,
//                                           unsigned int A_rows,
//                                           unsigned int A_columns,
//                                           float **B_matrix_ptr,
//                                           unsigned int B_rows_t,
//                                           float **result_ptr)
//{
//   uint16_t x,y;
//   float row_sum;
//
//   for (int i = 0; i < A_rows * B_rows_t; i++){
//      row_sum = 0;
//
//      x = i / (A_rows);
//      y = i % (A_rows);
//
//      for (int j = 0; j < B_rows_t; j++){
//         row_sum += A_matrix_ptr[x][j] * B_matrix_ptr[y][j];
//      }
//
//      result_ptr[x][y] = row_sum;
//   }
//}
///**
//*/
//void multiply_matrix_by_transposed_matrix (float (*A_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES],
//                                           float (*result_ptr)[NUMBER_OF_FEATURES][NUMBER_OF_FEATURES])
//{
//   uint16_t x,y;
//   float row_sum;
//
//   for (int i = 0; i < NUMBER_OF_FEATURES * NUMBER_OF_FEATURES; i++){
//      row_sum = 0;
//
//      x = i / NUMBER_OF_FEATURES;
//      y = i % NUMBER_OF_FEATURES;
//
//      for (int j = 0; j < NUMBER_OF_FEATURES*SKETCH_SIZE; j++){
//         row_sum += (*A_matrix_ptr)[j][x] * (*A_matrix_ptr)[j][y];
//      }
//
//      (*result_ptr)[x][y] = row_sum;
//   }
//}
///**
// * \brief Procedure multiplies two matrices - overloaded for different
// * parameters (4x).
// * \param[in] A_matrix_ptr Pointer to first matrix.
// * \param[in] B_matrix_ptr Pointer to second matrix (will be transposed in
// * computation).
// * \param[out] result_ptr Pointer to matrix for result.
// */
//void multiply_matrices (float (*A_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE],
//                        uint8_t (*B_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES],
//                        float (*result_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES])
//{
//   uint16_t x,y;
//   float row_sum;
//
//   for (int i = 0; i < NUMBER_OF_FEATURES*SKETCH_SIZE * NUMBER_OF_FEATURES; i++){
//      row_sum = 0;
//
//      x = i / NUMBER_OF_FEATURES;
//      y = i % NUMBER_OF_FEATURES;
//
//      for (int j = 0; j < NUMBER_OF_FEATURES*SKETCH_SIZE; j++){
//         row_sum += (*A_matrix_ptr)[x][j] * (unsigned int) (*B_matrix_ptr)[j][y];
//      }
//
//      (*result_ptr)[x][y] = row_sum;
//   }
//}
///**
//*/
//void multiply_matrices (uint8_t (*A_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES],
//                        float (*B_matrix_ptr)[NUMBER_OF_FEATURES][NUMBER_OF_FEATURES],
//                        float (*result_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES])
//{
//   uint16_t x,y;
//   float row_sum;
//
//   for(int i = 0; i < NUMBER_OF_FEATURES*SKETCH_SIZE * NUMBER_OF_FEATURES; i++){
//      row_sum = 0;
//
//      x = i / NUMBER_OF_FEATURES;
//      y = i % NUMBER_OF_FEATURES;
//
//      for (int j = 0; j < NUMBER_OF_FEATURES; j++){
//         row_sum += (unsigned int)(*A_matrix_ptr)[x][j] * (*B_matrix_ptr)[j][y];
//      }
//
//      (*result_ptr)[x][y] = row_sum;
//   }
//}
///**
//*/
//void multiply_matrices (float (*A_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE],
//                        float (*B_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE],
//                        float (*result_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE])
//{
//   uint16_t x, y;
//   float row_sum;
//
//   for (int i = 0; i < NUMBER_OF_FEATURES*SKETCH_SIZE * NUMBER_OF_FEATURES*SKETCH_SIZE; i++){
//      row_sum = 0;
//
//      x = i / (NUMBER_OF_FEATURES*SKETCH_SIZE);
//      y = i % (NUMBER_OF_FEATURES*SKETCH_SIZE);
//      for (int j = 0; j < NUMBER_OF_FEATURES*SKETCH_SIZE; j++){
//         row_sum += (*A_matrix_ptr)[x][j] * (*B_matrix_ptr)[j][y];
//      }
//
//      (*result_ptr)[x][y] = row_sum;
//   }
//}
/////**
////*/
//void multiply_matrices (float (*A_matrix_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE],
//                        real_2d_array *B_matrix_ptr,
//                        unsigned int row_selector,
//                        float (*result_ptr)[NUMBER_OF_FEATURES*SKETCH_SIZE])
//{
//   uint16_t y;
//   float row_sum;
//
//   for(int i = 0; i < NUMBER_OF_FEATURES*SKETCH_SIZE; i++){
//      row_sum = 0;
//
//      y = i;
//
//      for (int j = 0; j < NUMBER_OF_FEATURES*SKETCH_SIZE; j++){
//         row_sum += (*A_matrix_ptr)[y][j] * (*B_matrix_ptr)[row_selector][j];
//      }
//
//      (*result_ptr)[i] = row_sum;
//   }
//}
// ***************** END OF MATRIX OPERATIONS **********************************
int main(int argc, char **argv)
{
   int ret;
   trap_ifc_spec_t ifc_spec;

   int verbose = 0;

   int need_more_timebins = WORKING_TIMEBIN_WINDOW_SIZE;
   uint8_t timebin_init_flag = 1;
   uint32_t start_of_actual_flow;
   uint32_t timebin_counter; // counted from zero
   uint32_t round_timebin_counter; // counted from zero
   uint32_t start_of_next_timebin;

      //   void (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(type1 *, type2, ...);
   uint32_t (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(const char *, int , int );
    ptrHashFunc[0] = SuperFastHash;
    ptrHashFunc[1] = SuperFastHash;
    ptrHashFunc[2] = SuperFastHash;
    ptrHashFunc[NUMBER_OF_HASH_FUNCTION - 1] = SuperFastHash;

   uint32_t row_in_sketch;

   static uint32_t sip_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][ADDRESS_SKETCH_WIDTH];
   static uint32_t dip_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];
   static uint32_t sp_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];
   static uint32_t dp_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];

   static uint64_t packet_counts [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE];

   real_2d_array data_matrices[NUMBER_OF_HASH_FUNCTION]; // >> float

   uint16_t normal_subspace_size;

   float ***lin_op_c_residual;
   lin_op_c_residual = new float **[NUMBER_OF_HASH_FUNCTION];
   for (int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
      lin_op_c_residual[i] = new float *[NUMBER_OF_FEATURES * SKETCH_SIZE];

      for (int j = 0; j < NUMBER_OF_FEATURES * SKETCH_SIZE; j++){
         lin_op_c_residual[i][j] = new float [NUMBER_OF_FEATURES * SKETCH_SIZE];
      }
   }

   vector <void *> actual_flows;

   uint8_t **theta;
   theta = new uint8_t *[NUMBER_OF_FEATURES * SKETCH_SIZE];
   for (int i = 0; i < NUMBER_OF_FEATURES * SKETCH_SIZE; i++){
      theta[i] = new uint8_t[NUMBER_OF_FEATURES];
   }



      // ***** TRAP initialization *****
   // Let TRAP library parse command-line arguments and extract its parameters
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   // ***** END OF TRAP initialization *****

//   verbose = (trap_get_verbose_level() >= 0);
/*
   // Parse remaining parameters
   char opt;
   while ((opt = getopt(argc, argv, "c:n")) != -1) {
      switch (opt) {
         case 'c':
            max_records = atoi(optarg);
            if (max_records == 0) {
               fprintf(stderr, "Invalid maximal number of records.\n");
               return 2;
            }
            break;
         case 'n':
            send_eof = 0;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 2;
      }
   }

   if (optind >= argc) {
      fprintf(stderr, "Wrong number of parameters.\nUsage: %s -i trap-ifc-specifier [-n] [-c NUM] nfdump-file\n", argv[0]);
      return 2;
   }
*/

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec templates & allocate memory for output records *****
   // From ../../nfreader/nfdump_reader.c
   ur_template_t *in_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
                                                "TIME_LAST,PACKETS,BYTES,"
                                                "TCP_FLAGS");
//                                                "TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD");
   ur_template_t *out_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
                                                "TIME_LAST,PACKETS,BYTES,"
                                                "TCP_FLAGS");
//                                                "TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD");


   void *out_rec = ur_create(out_preliminary_tmplt, 0);

   // ***** END OF Create UniRec templates & allocate memory for output records *****

   // ***** Main processing loop *****
   while (!stop) {
   // ***** Get input data *****
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_get_data(TRAP_MASK_ALL, &in_rec, &in_rec_size, TRAP_WAIT);
      // Handle possible errors
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_static_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected"
                    " size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(in_tmplt), in_rec_size);
            break;
         }
      }
   // ***** END OF Get input data *****

   // ***** Process the data *****

     // *** Timebin division (sampling) based on TIMEBIN_SIZE ***
      start_of_actual_flow = (ur_get(in_tmplt, in_rec, UR_TIME_FIRST)) >> 32;

      if (timebin_init_flag){ // initialization of counters with first flow
        #ifdef VERBOSE_MSG
         printf("Starting first initialization...");
        #endif
         timebin_init_flag = 0;
         start_of_next_timebin = start_of_actual_flow + TIMEBIN_SIZE;
         timebin_counter = 0; // "human-like timebin" = timebin_counter + 1
         round_timebin_counter = timebin_counter;
        #ifdef ININT_DATA_MATRIX
         for (int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
            // init_data_matrix_from_file(&data_matrices[i], file_path);
         }
         timebin_counter = WORKING_TIMEBIN_WINDOW_SIZE;
         round_timebin_counter = timebin_counter % WORKING_TIMEBIN_WINDOW_SIZE;
        #endif

        #ifdef VERBOSE_MSG
         printf("... DONE.\n");
        #endif
        #ifdef VERBOSE_MSG
         printf("Start of %u. timebin in %u----------------",timebin_counter,start_of_next_timebin);
        #endif
      }

      // *** One timebin completed ***
      if (start_of_actual_flow > start_of_next_timebin){// end of actual timebin, start of new one
        #ifdef VERBOSE_MSG
         printf("--- one timebin received.\n");
        #endif

         --need_more_timebins;


         // *** Start detection (& identification) ***
         if (!need_more_timebins){
            anomaly_detetected = 0;

            need_more_timebins++;
               // *** Identification if an anomaly occured ***
               static float theta_residual[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES];
               static float tmp[NUMBER_OF_FEATURES][NUMBER_OF_FEATURES];
               static float tmp2[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES];
               static float tmp4[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE];
               static float tmp3[NUMBER_OF_FEATURES*SKETCH_SIZE][NUMBER_OF_FEATURES*SKETCH_SIZE];
               static float h_vector[5][NUMBER_OF_FEATURES*SKETCH_SIZE];
               uint8_t flip_index, stored_flip_index, switching_addition;
               uint8_t anomalous_flows_hash_values [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE];
               uint16_t arg_min, hit_ttl;
               float min, tmp_norm;

               memset(anomalous_flows_hash_values, 0, sizeof(anomalous_flows_hash_values[0][0]) * NUMBER_OF_HASH_FUNCTION * SKETCH_SIZE);
               for (int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
                 #ifdef VERBOSE_MSG //verbose
                  printf ("Starting identification for hash function %i ...\n", i);
                 #endif
                  switching_addition = 0;
                  flip_index = 0;
                  arg_min = 0;
                  min = REALLY_BIG_REAL_NUMBER; // ugly :-/switching_addition = 0
                 #ifdef VERBOSE_MSG //verbose
                  printf ("\tComputing %i h-vectors & finding 1. arg-min: \n", NUMBER_OF_FEATURES*SKETCH_SIZE);
                 #endif
                  // computing h* vectors
                  for (int j = 0; j < NUMBER_OF_FEATURES*SKETCH_SIZE; j++){
                     flip_index = 0;
                     arg_min = 0;
                     min = REALLY_BIG_REAL_NUMBER; // ugly :-/
                     memset(theta, 0, sizeof(theta[0][0]) * NUMBER_OF_FEATURES*SKETCH_SIZE * NUMBER_OF_FEATURES);
                     theta[(1 - 1) * SKETCH_SIZE + j][0] = 1;
                     theta[(2 - 1) * SKETCH_SIZE + j][1] = 1;
                     theta[(3 - 1) * SKETCH_SIZE + j][2] = 1;
                     theta[(4 - 1) * SKETCH_SIZE + j][3] = 1;

                     multiply_matrices(&lin_op_c_residual[i], &theta, &theta_residual);
                     multiply_matrix_by_transposed_matrix(&theta_residual, &tmp);
                     multiply_matrices(&theta, &tmp, &tmp2);
                     multiply_matrix_by_transposed_matrix(&tmp2, &theta_residual, &tmp3);
                     multiply_matrices(&tmp3, &lin_op_c_residual[i], &tmp4);
                     substitute_matrices(&identity_matrix, &tmp4);
                     multiply_matrix_by_transposed_line(&tmp4, &data_matrices[i], round_timebin_counter, &h_vector[flip_index]);
                     // finding arg min
                     multiply_matrix_by_vector(&lin_op_c_residual[i], &h_vector[flip_index], &h_vector[5]);
                     tmp_norm = norm_of_vector(&h_vector[5]);
                     if(tmp_norm < min){
                        min = tmp_norm;
                        arg_min = j;
                        stored_flip_index = flip_index;
                        flip_index = (++flip_index & 0x01) + switching_addition;
                     }
                  }
                 #ifdef VERBOSE_MSG //verbose
                  printf ("\t\tnew arg-min is: %i\n", arg_min);
                 #endif
                  ++anomalous_flows_hash_values[i][arg_min % NUMBER_OF_FEATURES];

                  while(min >= NORM_AMOUNT_INDETIFICATION_THRESHOLD &&
                        anomalous_flows_hash_values[i][arg_min] < IDENTIFICATION_TTL){
                    #ifdef VERBOSE_MSG //verbose
                     printf ("\tComputing %i h-vectors & finding next argmin:\n", NUMBER_OF_FEATURES*SKETCH_SIZE);
                    #endif
                     switching_addition = (switching_addition + 2) & 0x02;
                     flip_index = switching_addition;
                     arg_min = 0;
                     min = REALLY_BIG_REAL_NUMBER; // ugly :-/

                     for (int j = 0; j < NUMBER_OF_FEATURES*SKETCH_SIZE; j++){
                        memset(theta, 0, sizeof(theta[0][0]) * NUMBER_OF_FEATURES*SKETCH_SIZE * 4);
                        theta[(1 - 1) * SKETCH_SIZE + j][0] = 1;
                        theta[(2 - 1) * SKETCH_SIZE + j][1] = 1;
                        theta[(3 - 1) * SKETCH_SIZE + j][2] = 1;
                        theta[(4 - 1) * SKETCH_SIZE + j][3] = 1;

                        multiply_matrices(&lin_op_c_residual[i], &theta, &theta_residual);
                        multiply_matrix_by_transposed_matrix(&theta_residual, &tmp);
                        multiply_matrices(&theta, &tmp, &tmp2);
                        multiply_matrix_by_transposed_matrix(&tmp2, &theta_residual, &tmp3);
                        multiply_matrices(&tmp3, &lin_op_c_residual[i], &tmp4);
                        substitute_matrices(&identity_matrix, &tmp4);
                        multiply_matrix_by_vector(&tmp4, &h_vector[stored_flip_index], &h_vector[flip_index]);
                        // finding arg min
                        multiply_matrix_by_vector(&lin_op_c_residual[i], &h_vector[flip_index], &h_vector[5]);
                        tmp_norm = norm_of_vector(&h_vector[5]);
                        if(tmp_norm < min){
                           min = tmp_norm;
                           arg_min = j;
                           stored_flip_index = flip_index;
                           flip_index = (++flip_index & 0x01) + switching_addition;
                        }
                     }
                    #ifdef VERBOSE_MSG //verbose
                     printf ("\t\tnew arg-min is: %i\n", arg_min);
                    #endif
                     ++anomalous_flows_hash_values[i][arg_min % NUMBER_OF_FEATURES];
                  }
                 #ifdef VERBOSE_MSG //verbose
                  printf ("\n\tAll flow's hash-values (arg-mins) for hash function %i were found\n", i);
                 #endif
               }
                 #ifdef VERBOSE_MSG
                  printf ("\tRe-hashing flows...\n");
                 #endif
                  for (vector <void *>::iterator it = actual_flows.begin(); it != actual_flows.end(); ++it){
                     int i = 0;
//                     printf("Vector size: %i\n", actual_flows.size());
                     while (i < NUMBER_OF_HASH_FUNCTION){
//                       printf("CHECK: %i\n", i);
                        row_in_sketch = get_row_in_sketch(in_tmplt, *it, seeds[i]);
                        i++; //  TMP
                        if (anomalous_flows_hash_values[i][row_in_sketch]){
//                           i++;
                           if (i == NUMBER_OF_HASH_FUNCTION){
                             #ifdef VERBOSE_MSG
//                              printf ("\t\tAnomalous flow found in timebin %u ... sending ...", timebin_counter);
                             #endif
                               trap_send_data(1, *it, ur_rec_static_size(in_tmplt), TRAP_WAIT);
                             #ifdef VERBOSE_MSG
//                              printf ("...DONE.\n", i);
                             #endif
                              ur_free(*it);
//                              actual_flows.erase(it);
                           }
                        } else {
                           ur_free(*it);
//                           actual_flows.erase(it);
                           i = NUMBER_OF_HASH_FUNCTION; // == break;
                        }
                     }
                  }
                  actual_flows.clear();
            // *** END OF Identification if an anomaly occured ***
           #ifdef VERBOSE_MSG
            printf ("...identification DONE.\n");
           #endif
            }
            // *** END OF Merging results ***
         }
         // *** END OF detection (& identification) ***
         ++timebin_counter;
         start_of_next_timebin += TIMEBIN_SIZE;
         round_timebin_counter = timebin_counter % WORKING_TIMEBIN_WINDOW_SIZE;

        #ifdef VERBOSE_MSG //verbose
         printf("\n\nStart of %u. timebin in %u----------------",timebin_counter,start_of_next_timebin);
        #endif

         if (!actual_flows.empty()){

            for (vector <void *>::iterator it = actual_flows.begin(); it != actual_flows.end(); ++it){
               ur_free(*it);
            }
            actual_flows.clear();
         }

      }
      //   *** END OF One timebin completed ***

      // store flow from actual timebin
      actual_flows.push_back(ur_cpy_alloc(in_tmplt, in_rec));

     //   *** END OF Timebin division ***

   // ***** END OF Process the data *****
   }
   // ***** END OF Main processing loop *****

   // ***** Cleanup *****
   for (int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){

      for (int j = 0; j < NUMBER_OF_FEATURES * SKETCH_SIZE; j++){
         delete [] lin_op_c_residual[i][j];
      }

      delete [] lin_op_c_residual[i];
   }
   delete [] lin_op_c_residual;

   for (vector<void *>::iterator it = actual_flows.begin(); it != actual_flows.end(); ++it){
      ur_free(*it);
   }
   actual_flows.clear();

   for (int i = 0; i < NUMBER_OF_FEATURES * SKETCH_SIZE; i++){
      delete [] theta[i];
   }
   delete [] theta;

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free(out_preliminary_rec);

   ur_free_template(in_tmplt);
   ur_free_template(out_preliminary_tmplt);
   // ***** END OF Cleanup *****

   return 0;
}
// END OF PCA_sketch_identificator.c
