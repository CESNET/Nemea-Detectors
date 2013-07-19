/**
 * \file PCA_sketch.c
 * \brief Module for detection of network anomalies using PCA and sketch
 *        subspaces.
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
#include "alglib/dataanalysis.h"

using namespace std;
using namespace alglib;


#define DEBUG
//#define DEBUG_OUT
   #ifdef DEBUG_OUT
      #include <inttypes.h>
   #endif
//#define VALIDATION_IDENTIF
//#define VALIDATION
   #if defined VALIDATION || defined VALIDATION_IDENTIF
      #include <fstream>
      #include <iostream>
      #include <limits>
      ofstream output;
   #endif

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

/*
 * Procedure for handling signals SIGTERM and SIGINT
 */
void signal_handler (int signal)
{
   if (trap_get_verbose_level() > 0)
      printf("Signal received\n");
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1; // breaks the main loop
      trap_terminate(); // interrupt a possible waiting in recv/send functions
   }
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
         float p = (float)sketch_row[i] / packet_count;
         entropy -= p * log2(p);
      }
   }
   return entropy;
}

// ***************** MATRIX OPERATIONS *****************************************
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
  float energy_of_submatrix;

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

/**
 * \brief Procedure transforms columns of matrix to have zero mean
 * \param[in,out] matrix_ptr Pointer to matrix which should be normalized.
 */
void transform_matrix_zero_mean (real_2d_array *matrix_ptr)
{
   float mean;

   for (int i = 0; i < matrix_ptr->cols(); i++){
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
 * \brief Procedure which multiplies matrix by vector.
 *
 * Procedure multiply source matrix by column of second matrix (vector). Return
 * result in third.
 * \param[in] A_matrix_ptr Pointer to first matrix (A).
 * \param[in] B_matrix_ptr Pointer to second matrix (B).
 * \param[in] B_matrix_column Value which specifies column of second matrix (B).
 * \param[out] result Pointer to vector in which should be stored result.
 */
void multiply_matrix_column_vector (real_2d_array *A_matrix_ptr,
                                    real_2d_array *B_matrix_ptr,
                                    unsigned int B_matrix_column,
                                    float (*result)[WORKING_TIMEBIN_WINDOW_SIZE])
{
   float row_sum;
//  if (A_matrix_ptr->cols()==B_matrix_ptr->rows()){ //check if matrixes have proper size
   for (int i = 0; i < WORKING_TIMEBIN_WINDOW_SIZE; i++){
      row_sum = 0;
      for (int j = 0; j < A_matrix_ptr->cols(); j++){
         row_sum += (*A_matrix_ptr)(i,j) * (*B_matrix_ptr)(j,B_matrix_column);
      }
      (*result)[i] = row_sum;
   }
//  }
}

/**
 * \brief Procedure computes norm of vector - overloaded for different
 * parameters (2x).
 * \param[in] vector_ptr Pointer to vector.
 * \return Returns real (float) value.
 */
float norm_of_vector (float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE])
{
   float sum = 0;

   for (int i = 0; i < WORKING_TIMEBIN_WINDOW_SIZE; i++){
      sum += (*vector_ptr)[i] * (*vector_ptr)[i];
   }

   return sqrt(sum);
}
/**
*/
float norm_of_vector (float (*vector_ptr)[4*SKETCH_SIZE])
{
   float sum = 0;

   for (int i = 0; i < 4*SKETCH_SIZE; i++){
      sum += (*vector_ptr)[i] * (*vector_ptr)[i];
   }

   return sqrt(sum);
}

/**
 * \brief Procedure divides vector by value.
 *
 * Procedure divides vector by value - overwrite original vector.
 * \param[in] vector_ptr Pointer to vector which should by divided.
 * \param[in] Real (float) value by which should be vector divided.
 */
void divide_vector_by_value (float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE], float divider)
{
   for (int i = 0; i < WORKING_TIMEBIN_WINDOW_SIZE; i++){
      (*vector_ptr)[i] /= divider;
   }
}

/**
 * \brief Provedure computes standard deviation from vector (1st version).
 *
 * Provedure computes standard deviation from vector in two different ways - two
 * versions (according to: http://www.mathworks.com/help/matlab/ref/std.html).
 * \param[in] vector_ptr Pointer to vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation (float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE])
{
   float sum=0;
//  SINCE VALUES_ARE_MEAN_CENTERED - HAVE_ZERO_MEAN >> Simplier version:
   for (int i = 0; i < WORKING_TIMEBIN_WINDOW_SIZE; i++){
      sum += (*vector_ptr)[i] * (*vector_ptr)[i];
   }

   return sum / WORKING_TIMEBIN_WINDOW_SIZE;
}
/**
 * \brief Provedure computes standard deviation from vector (2nd version).
 * \param[in] vector_ptr Pointer to vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation_v2(float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE])
{
   float sum = 0, tmp;
   float mean = 0;
   for (int i = 0; i < WORKING_TIMEBIN_WINDOW_SIZE; i++){
      mean+=(*vector_ptr)[i];
   }
   mean /= WORKING_TIMEBIN_WINDOW_SIZE;
//  SINCE VALUES_ARE_MEAN_CENTERED - HAVE_ZERO_MEAN >> Simplier version:
   for (int i = 0; i < WORKING_TIMEBIN_WINDOW_SIZE; i++){
      tmp = (*vector_ptr)[i] - mean;
      sum += tmp * tmp;
   }

   return sum / (WORKING_TIMEBIN_WINDOW_SIZE-1) ;
}

/**
 * \brief Procedure substitutes two matrices.
 *
 * Procedure substitutes second matrix from first. Stores result in second.
 * \param[in] A_matrix_ptr Pointer to first matrix.
 * \param[in,out] B_matrix_result_ptr Pointer to secod and result matrix.
 */
void substitute_matrix (uint8_t (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
                        float (*B_matrix_result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE])
{
   for (int i = 0; i < 4*SKETCH_SIZE; i++){
      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         (*B_matrix_result_ptr)[i][j] = (*A_matrix_ptr)[i][j]  - (*B_matrix_result_ptr)[i][j];
      }
    }
}

/**
 * \brief Procedure multiplies submatrix of matrix and transposed submatrix
 * of the same matrix.
 *
 * Procedure multiplies submatrix of "matrix_ptr" defined by first column (index
 *  0) and parameter (column_delimiter) with the same submatrix transposed.
 * \param[in] matrix_ptr Source matrix.
 * \param[in] column_delimiter Specifies size of submatrix (column count).
 * \param[out] result_ptr Pointer to matrix for result.
 */
void multiply_submatrix_by_transposed_submatrix (real_2d_array *matrix_ptr,
                                                 unsigned int column_delimiter,
                                                 float (*result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE])
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

      (*result_ptr)[x][y] = row_sum;
   }
}

/**
 * \brief Procedure multiplies matrix and transposed row of another matrix.
 * Procedure multiplies first matrix and transposed row of second matrix defined
 * by parameter (row_selector).
 * \param[in] A_matrix_ptr Pointer to first matrix.
 * \param[in] B_matrix_ptr Pointer to second matrix, which contains row, which
 * is used as column vector (transposed row).
 * \param[in] row_selector Specifies row of B_matrix_ptr.
 * \param[out] result_ptr Pointer to vector for result.
 */
void multiply_matrix_by_transposed_line (float (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
                                         real_2d_array *B_matrix_ptr, unsigned int row_selector,
                                         float (*result_ptr)[4*SKETCH_SIZE])
{
   uint16_t y;
   float row_sum;

   for (int i = 0; i < 4*SKETCH_SIZE; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         row_sum += (*A_matrix_ptr)[y][j] * (*B_matrix_ptr)[row_selector][j];
      }

      (*result_ptr)[i] = row_sum;
   }
}

/**
 * \brief Procedure multiplies matrix and transposed another matrix - overloaded
 *  for different parameters (2x).
 * \param[in] A_matrix_ptr Pointer to first matrix.
 * \param[in] B_matrix_ptr Pointer to second matrix (will be transposed in
 * computation).
 * \param[out] result_ptr Pointer to matrix for result.
 */
void multiply_matrix_by_transposed_matrix (float (*A_matrix_ptr)[4*SKETCH_SIZE][4],
                                           float (*B_matrix_ptr)[4*SKETCH_SIZE][4],
                                           float (*result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE])
{
   uint16_t x,y;
   float row_sum;

   for (int i = 0; i < 4*SKETCH_SIZE * 4*SKETCH_SIZE; i++){
      row_sum = 0;

      x = i / (4*SKETCH_SIZE);
      y = i % (4*SKETCH_SIZE);

      for (int j = 0; j < 4; j++){
         row_sum += (*A_matrix_ptr)[x][j] * (*B_matrix_ptr)[y][j];
      }

      (*result_ptr)[x][y] = row_sum;
   }
}
/**
*/
void multiply_matrix_by_transposed_matrix (float (*A_matrix_ptr)[4*SKETCH_SIZE][4],
                                           float (*result_ptr)[4][4])
{
   uint16_t x,y;
   float row_sum;

   for (int i = 0; i < 4 * 4; i++){
      row_sum = 0;

      x = i / 4;
      y = i % 4;

      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         row_sum += (*A_matrix_ptr)[j][x] * (*A_matrix_ptr)[j][y];
      }

      (*result_ptr)[x][y] = row_sum;
   }
}
/**
 * \brief Procedure multiplies two matrices - overloaded for different
 * parameters (4x).
 * \param[in] A_matrix_ptr Pointer to first matrix.
 * \param[in] B_matrix_ptr Pointer to second matrix (will be transposed in
 * computation).
 * \param[out] result_ptr Pointer to matrix for result.
 */
void multiply_matrices (float (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
                        uint8_t (*B_matrix_ptr)[4*SKETCH_SIZE][4],
                        float (*result_ptr)[4*SKETCH_SIZE][4])
{
   uint16_t x,y;
   float row_sum;

   for (int i = 0; i < 4*SKETCH_SIZE * 4; i++){
      row_sum = 0;

      x = i / 4;
      y = i % 4;

      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         row_sum += (*A_matrix_ptr)[x][j] * (unsigned int) (*B_matrix_ptr)[j][y];
      }

      (*result_ptr)[x][y] = row_sum;
   }
}
/**
*/
void multiply_matrices (uint8_t (*A_matrix_ptr)[4*SKETCH_SIZE][4],
                        float (*B_matrix_ptr)[4][4],
                        float (*result_ptr)[4*SKETCH_SIZE][4])
{
   uint16_t x,y;
   float row_sum;

   for(int i = 0; i < 4*SKETCH_SIZE * 4; i++){
      row_sum = 0;

      x = i / 4;
      y = i % 4;

      for (int j = 0; j < 4; j++){
         row_sum += (unsigned int)(*A_matrix_ptr)[x][j] * (*B_matrix_ptr)[j][y];
      }

      (*result_ptr)[x][y] = row_sum;
   }
}
/**
*/
void multiply_matrices (float (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
                        float (*B_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
                        float (*result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE])
{
   uint16_t x, y;
   float row_sum;

   for (int i = 0; i < 4*SKETCH_SIZE * 4*SKETCH_SIZE; i++){
      row_sum = 0;

      x = i / (4*SKETCH_SIZE);
      y = i % (4*SKETCH_SIZE);
      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         row_sum += (*A_matrix_ptr)[x][j] * (*B_matrix_ptr)[j][y];
      }

      (*result_ptr)[x][y] = row_sum;
   }
}
/**
*/
void multiply_matrices (float (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
                        real_2d_array *B_matrix_ptr,
                        unsigned int row_selector,
                        float (*result_ptr)[4*SKETCH_SIZE])
{
   uint16_t y;
   float row_sum;

   for(int i = 0; i < 4*SKETCH_SIZE; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         row_sum += (*A_matrix_ptr)[y][j] * (*B_matrix_ptr)[row_selector][j];
      }

      (*result_ptr)[i] = row_sum;
   }
}
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
   uint32_t start_of_next_timebin;
// !!!CHANGE  uint32_t start_of_next_timebin = 0;

   vector <void *> actual_flows;

   uint64_t tmp_addr_part;
   uint64_t hash_key[4];
   int hk_size;

   uint32_t row_in_sketch;

   static uint32_t sip_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][ADDRESS_SKETCH_WIDTH];
   static uint32_t dip_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];
   static uint32_t sp_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];
   static uint32_t dp_sketches[NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];

   static uint64_t packet_counts [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE];

   real_2d_array data_matrices[NUMBER_OF_HASH_FUNCTION];
    for (int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
       data_matrices[i].setlength(WORKING_TIMEBIN_WINDOW_SIZE, SKETCH_SIZE*4);
    }
   real_2d_array principal_components;
	real_1d_array eigenvalues;
   ae_int_t info;

   uint16_t normal_subspace_size;

   static float lin_op_c_residual[NUMBER_OF_HASH_FUNCTION][4*SKETCH_SIZE][4*SKETCH_SIZE];
   static uint8_t identity_matrix[4*SKETCH_SIZE][4*SKETCH_SIZE];
    memset(identity_matrix, 0, sizeof(identity_matrix[0][0]) * 4*SKETCH_SIZE * 4*SKETCH_SIZE);
    for (int j = 0; j < 4*SKETCH_SIZE; j++){
       identity_matrix[j][j] = 1;
    }

   static float mapped_data[4*SKETCH_SIZE];
   float phi [3];
   float lambda,SPE,h0,delta_SPE;
   uint8_t anomaly_detetected;
   static uint8_t theta [4*SKETCH_SIZE][4];

//   void (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(type1 *, type2, ...);
   uint32_t (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(const char *, int , int );
    ptrHashFunc[0] = SuperFastHash;
    ptrHashFunc[1] = SuperFastHash;
    ptrHashFunc[2] = SuperFastHash;
    ptrHashFunc[NUMBER_OF_HASH_FUNCTION - 1] = SuperFastHash;

   // ***** TRAP initialization *****
   // Let TRAP library parse command-line arguments and extract its parameters
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      fprintf(stderr, "ERROR in parsing of parameters for TRAP: %s\n",
              trap_last_error_msg);
      return 1;
   }

   verbose = (trap_get_verbose_level() >= 0);
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
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      return 2;
   }

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   // ***** END OF TRAP initialization *****

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);


   // ***** Create UniRec templates & allocate memory for output records *****
   // From ../../nfreader/nfdump_reader.c
   ur_template_t *in_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
                                                "TIME_LAST,PACKETS,BYTES,"
                                                "TCP_FLAGS");
   ur_template_t *out_preliminary_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
                                                "TIME_LAST,PACKETS,BYTES,"
                                                "TCP_FLAGS");
//   ur_template_t *out_detailed_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
//                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
//                                                "TIME_LAST,PACKETS,BYTES,"
//                                                "TCP_FLAGS");

   void *out_preliminary_rec = ur_create(out_preliminary_tmplt, 0);
//   void *out_detailed_rec = ur_create(out_detailed_tmplt, 0);

   // ***** END OF Create UniRec templates & allocate memory for output records *****
   // ***** Main processing loop *****
   while (!stop) {
   // ***** Get input data *****
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from any input interface, wait until data are available
      ret = trap_get_data(TRAP_MASK_ALL, &in_rec, &in_rec_size, TRAP_WAIT);
      if (ret == TRAP_E_TERMINATED) {
         break; // Module was terminated while waiting for data (e.g. by Ctrl-C)
      } else if (ret != TRAP_E_OK) {
         // Some error ocurred
         fprintf(stderr, "Error: trap_get_data() returned %i (%s)\n", ret,
                 trap_last_error_msg);
         break;
      }

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
         timebin_init_flag = 0;
         start_of_next_timebin = start_of_actual_flow + TIMEBIN_SIZE;
         timebin_counter = 0; // "human-like timebin" = timebin_counter + 1

         memset(sip_sketches, 0, sizeof(sip_sketches[0][0][0]) * NUMBER_OF_HASH_FUNCTION * SKETCH_SIZE * ADDRESS_SKETCH_WIDTH);
         memset(dip_sketches, 0, sizeof(dip_sketches[0][0][0]) * NUMBER_OF_HASH_FUNCTION * SKETCH_SIZE * ADDRESS_SKETCH_WIDTH);
         memset(sp_sketches, 0, sizeof(sp_sketches[0][0][0]) * NUMBER_OF_HASH_FUNCTION * SKETCH_SIZE * PORT_SKETCH_WIDTH);
         memset(dp_sketches, 0, sizeof(dp_sketches[0][0][0]) * NUMBER_OF_HASH_FUNCTION * SKETCH_SIZE * PORT_SKETCH_WIDTH);
         memset(packet_counts, 0, sizeof(packet_counts[0][0]) * NUMBER_OF_HASH_FUNCTION * SKETCH_SIZE);
               #ifdef DEBUG
                  printf("Start of %u. timebin in %u------------------------------"
                        "--------------\n",timebin_counter,start_of_next_timebin);
               #endif
      }

      if(start_of_actual_flow>start_of_next_timebin){
         --need_more_timebins;
         for(int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
            for(int j = 0; j < SKETCH_SIZE; j++){
//               //// !!! OVERFLOW timebin_counter
//               printf("[%i] [%i] [%i]\n",i, (timebin_counter-1) % WORKING_TIMEBIN_WINDOW_SIZE,j);
               data_matrices[i](timebin_counter % WORKING_TIMEBIN_WINDOW_SIZE,j) =
                  compute_entropy(sip_sketches[i][j],ADDRESS_SKETCH_WIDTH,packet_counts[i][j]);
               data_matrices[i](timebin_counter % WORKING_TIMEBIN_WINDOW_SIZE,j+SKETCH_SIZE) =
                  compute_entropy(sp_sketches[i][j],PORT_SKETCH_WIDTH,packet_counts[i][j]);
               data_matrices[i](timebin_counter % WORKING_TIMEBIN_WINDOW_SIZE,j+SKETCH_SIZE*2) =
                  compute_entropy(dip_sketches[i][j],ADDRESS_SKETCH_WIDTH,packet_counts[i][j]);
               data_matrices[i](timebin_counter % WORKING_TIMEBIN_WINDOW_SIZE,j+SKETCH_SIZE*3) =
                  compute_entropy(dp_sketches[i][j],PORT_SKETCH_WIDTH,packet_counts[i][j]);
            }
         }
//          *** Start detection (& identification) part ***
         if(!need_more_timebins){
            anomaly_detetected = 0;

            need_more_timebins++;
            for(int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
               printf("Detection...\n");

               // preprocess_data_matrix( parametr timebin_to_find-in);
               //    *** Matrix normalization ***
               transform_matrix_zero_mean(&data_matrices[i]);
               transform_submatrix_unit_energy(&data_matrices[i],0,SKETCH_SIZE);
               transform_submatrix_unit_energy(&data_matrices[i],SKETCH_SIZE,2*SKETCH_SIZE);
               transform_submatrix_unit_energy(&data_matrices[i],2*SKETCH_SIZE,3*SKETCH_SIZE);
               transform_submatrix_unit_energy(&data_matrices[i],3*SKETCH_SIZE,4*SKETCH_SIZE);
               //    *** END OF Matrix normalization
               //    *** Computing of PCA ***
               pcabuildbasis(data_matrices[i], data_matrices[i].rows(), data_matrices[i].cols(), info, eigenvalues, principal_components);
               //    *** END OF Computing of PCA ***
               //    *** Finding of normal subspace size ***
               #ifdef NORMAL_SUBSPACE_SIZE
                  normal_subspace_size = NORMAL_SUBSPACE_SIZE;
               #elif defined NSS_BY_PERCENTAGE
                  float variance_threshold, sum_variance=0;

                  for(int j = 0; j < eigenvalues.length(); j++){
                     sum_variance += eigenvalues(j);
                  }
                  variance_threshold = sum_variance * NSS_BY_PERCENTAGE;
                  //data_matrices[i].cols() == eigenvalues.length() == 4*SKETCH_SIZE
                  normal_subspace_size=eigenvalues.length();
                  while(sum_variance > variance_threshold){
                     sum_variance -= eigenvalues(--normal_subspace_size);
                  }
                  normal_subspace_size++;
               #else//NO NSS_BY_PERCENTAGE or NO NORMAL_SUBSPACE_SIZE
// real_1d_array>>float                 real_1d_array data2pc_projection;
//                     data2pc_projection.setlength(WORKING_TIMEBIN_WINDOW_SIZE);
                  static float delta2pc_projection[WORKING_TIMEBIN_WINDOW_SIZE];
                  float norm, delta;

                  normal_subspace_size = 0;
                  int wj = 0;
                  while(!normal_subspace_size && wj<4*SKETCH_SIZE){
                     multiply_matrix_column_vector(&data_matrices[i], &principal_components, wj, &data2pc_projection);
                     norm=norm_of_vector(&data2pc_projection);
                     divide_vector_by_value(&data2pc_projection, norm);

                     delta=sqrt(vector_standard_deviation_v2(&data2pc_projection));
                     for(k = 0; k < WORKING_TIMEBIN_WINDOW_SIZE; k++){//"Delta" test
                        if(fabs(data2pc_projection[wj]) >= NSS_BY_DELTA_TEST*delta){
//                        if(data2pc_projection(j) >= NSS_BY_DELTA_TEST * delta
//                        || data2pc_projection(j) <= -NSS_BY_DELTA_TEST * delta){
                           normal_subspace_size = wj;
                        }
                     }
                     wj++;
                  }
               #endif //Normal subspace size definition
               printf("Normal subspace size (by count of principal components): %u\n",normal_subspace_size);
               //    *** END OF Finding of normal subspace size ***
               //    *** Computiing of linear operator C-residual (performs linear projection onto the anomaly subspace) ***
               multiply_submatrix_by_transposed_submatrix(&principal_components,normal_subspace_size,&lin_op_c_residual[i]);
               substitute_matrix(&identity_matrix,&lin_op_c_residual[i]);
               //    *** END OF Computing of linear operator C-residual ***
               //    *** Detecting anomalies by "SPE" test ****
               phi[0]=0;
               phi[1]=0;
               phi[2]=0;

               for(int j = normal_subspace_size; j < 4*SKETCH_SIZE; j++){
                  lambda=eigenvalues(j);
                  phi[0] += lambda;
                  lambda *= lambda;
                  phi[1] += lambda;
                  lambda *= lambda;
                  phi[2] += lambda;
               }
               h0 = 1 - ((2 * phi[0] * phi[2]) / (3.0 * phi[1] * phi[1]));
               delta_SPE = phi[0] * pow((
                     ((ALPHA_PERCENTILE_95 * sqrt(2.0 * phi[1] * h0 * h0)) / phi[0])
                     + 1 + ((phi[1] * h0 * (h0-1.0)) / (phi[0] * phi[0])) ) ,(1.0/h0));

               multiply_matrix_by_transposed_line(&lin_op_c_residual[i], &data_matrices[i],
                                                  timebin_counter%WORKING_TIMEBIN_WINDOW_SIZE, &mapped_data);
               SPE = norm_of_vector(&mapped_data);
               SPE *= SPE;

               if(SPE > delta_SPE){
                  anomaly_detetected++;
                  printf("!!! Anomaly in timebin %u !!!\n", timebin_counter);
               } else {
                  printf("NO Anomaly in timebin %u.\n", timebin_counter);
               }
               //    *** Detecting anomalies by "SPE" test ****
            }
            //    *** END OF detection (& identification) part ***
            if (anomaly_detetected >= NUMBER_OF_TRUE_DETECTION_THRESHOLD){
               // Fill output record
               ur_set(out_preliminary_tmplt, out_preliminary_rec, UR_TIME_FIRST,
                      (uint64_t) (start_of_actual_flow - TIMEBIN_SIZE) << 32 );
               ur_set(out_preliminary_tmplt, out_preliminary_rec, UR_TIME_LAST,
                      (uint64_t) start_of_actual_flow << 32 );
               ur_set(out_preliminary_tmplt, out_preliminary_rec, UR_SRC_PORT,0);
               ur_set(out_preliminary_tmplt, out_preliminary_rec, UR_DST_PORT,0);
               // Send record to interface 0, if ifc is not ready, wait at most 10ms
               printf("Sending data: %i - size: %u \n",
                      trap_send_data(0, out_preliminary_rec, ur_rec_static_size(out_preliminary_tmplt), TRAP_WAIT),
                      ur_rec_static_size(out_preliminary_tmplt));
//               trap_send_data(1, out_preliminary_rec, ur_rec_static_size(out_preliminary_tmplt), TRAP_WAIT);
//               trap_send_data(2, out_preliminary_rec, ur_rec_static_size(out_preliminary_tmplt), TRAP_WAIT);
               printf("ANOMALY DETECTED IN TIMEBIN:%u >> TIME: %u - %u!\n",
                      timebin_counter, start_of_next_timebin - TIMEBIN_SIZE, start_of_next_timebin);
            }
            #ifdef IDENTIFICATION
            //    *** Merging results & identification if an anomaly occured ***
            printf(" Threshold: %i\n", NUMBER_OF_TRUE_DETECTION_THRESHOLD);
            if (anomaly_detetected >= NUMBER_OF_TRUE_DETECTION_THRESHOLD)
            {
               static float theta_residual[4*SKETCH_SIZE][4];
               static float tmp[4][4];
               static float tmp2[4*SKETCH_SIZE][4];
               static float tmp4[4*SKETCH_SIZE][4*SKETCH_SIZE];
               static float tmp3[4*SKETCH_SIZE][4*SKETCH_SIZE];
               static float h_vectors[4*SKETCH_SIZE][4*SKETCH_SIZE];
               printf("Identification\n");
               for(int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
                  for(int j = 0; j < SKETCH_SIZE; j++){
                     printf("%i\n",j);
                     memset(theta, 0, sizeof(theta[0][0])*4*SKETCH_SIZE*4);
                     theta[(1-1)*SKETCH_SIZE+j][0]=1;
                     theta[(2-1)*SKETCH_SIZE+j][1]=1;
                     theta[(3-1)*SKETCH_SIZE+j][2]=1;
                     theta[(4-1)*SKETCH_SIZE+j][3]=1;
                     multiply_matrices(&lin_op_c_residual[i], &theta, &theta_residual);
                     printf("C-residual.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("C-residual.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4*SKETCH_SIZE; vk++){
                                 output<<lin_op_c_residual[i][vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                        output.open("Theta.txt");
//                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4; vk++){
                                 output<<(unsigned int) theta[vj][vk]<<"\t";
//                                 printf("%k\t",theta[i][k]);
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                        output.open("Theta-residual.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4; vk++){
                                 output<<theta_residual[vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                     multiply_matrix_by_transposed_matrix(&theta_residual, &tmp);
                     printf("Trest-x-Tres.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("TresT-x-Tres.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4; vj++){
                              for(int vk = 0; vk < 4; vk++){
                                 output<<tmp[vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                        output.open("Theta2.txt");
//                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4; vk++){
                                 output<<(unsigned int) theta[vj][vk]<<"\t";
//                                 printf("%k\t",theta[i][k]);
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                     multiply_matrices(&theta, &tmp, &tmp2);
                     printf("2t.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("2T-x-TresT.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4; vk++){
                                 output<<tmp2[vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                     multiply_matrix_by_transposed_matrix(&tmp2, &theta_residual, &tmp3);
                     printf("3t.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("3thetas.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4*SKETCH_SIZE; vk++){
                                 output<<tmp3[vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                     multiply_matrices(&tmp3, &lin_op_c_residual[i], &tmp4);
                     printf("4t.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("4thetas-x-cres.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4*SKETCH_SIZE; vk++){
                                 output<<tmp4[vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                     substitute_matrix(&identity_matrix, &tmp4);
                     printf("sub.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("Substitution.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              for(int vk = 0; vk < 4*SKETCH_SIZE; vk++){
                                 output<<tmp4[vj][vk]<<"\t";
                              }
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                     printf("CHECK\n");
                     multiply_matrix_by_transposed_line(&tmp4, &data_matrices[i], j, &h_vectors[j]);
                     printf("vec.txt\n");
                     #ifdef VALIDATION_IDENTIF
                     {
                        output.open("h_vec.txt");
                        output.precision(numeric_limits< double >::digits10);
                        if(i == 0){
                           for(int vj = 0; vj < 4*SKETCH_SIZE; vj++){
                              output<<h_vectors[0][vj];
                              output<<"\n";
                           }
                        }
                        output.close();
                     }
                     #endif
                  }
               }
            }
            #endif
//               // trap_send(start_of_next_timebin-TIMEBIN_SIZE,start_of_next_timebin) - mezi tìmito èasy
         }// *** END OF detection (& identification) part ***
         ++timebin_counter;
         start_of_next_timebin += TIMEBIN_SIZE;
               #ifdef DEBUG
                  printf("Start of %u. timebin in %u------------------------------"
                        "--------------\n",timebin_counter,start_of_next_timebin);
               #endif
               #ifdef DEBUG_OUT
                  printf("\t\t\t\t%u\n",ip_get_v4_as_int(ur_get_ptr(in_tmplt, (void *) actual_flows[checker-1], UR_SRC_IP)));
               #endif
         #ifdef IDENTIFICATION
         for (vector<void *>::iterator it = actual_flows.begin(); it != actual_flows.end(); ++it){
            ur_free(*it);
         }
         actual_flows.clear();
         #endif

         memset(sip_sketches, 0, sizeof(sip_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH);
         memset(dip_sketches, 0, sizeof(dip_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH);
         memset(sp_sketches, 0, sizeof(sp_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*PORT_SKETCH_WIDTH);
         memset(dp_sketches, 0, sizeof(dp_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*PORT_SKETCH_WIDTH);
         memset(packet_counts, 0, sizeof(packet_counts[0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE);
      } // *** END OF Timebin division ***
      // *** Flow reading & structure filling ***
      #ifdef IDENTIFICATION
      //    *** Store flow from actual timebin ***
      actual_flows.push_back(ur_cpy_alloc(in_tmplt, in_rec));

            #ifdef DEBUG_OUT
               if(actual_flows.size()==checker)
               {
                  printf("%u. Timebin - %i. flow srcIP: %u\n",timebin_counter+1,i,ip_get_v4_as_int(ur_get_ptr(in_tmplt, in_rec, UR_SRC_IP)));
         //         stop=1;
               }
            #endif
      //    *** END OF Store flow from actual timebin ***
      #endif
      //    *** Getting HashKey ***
      memset(hash_key,0,sizeof(hash_key));
      if(ip_is4(ur_get_ptr(in_tmplt,in_rec,UR_SRC_IP))){
         tmp_addr_part = ip_get_v4_as_int(ur_get_ptr(in_tmplt, in_rec, UR_SRC_IP)) & V4_HASH_KEY_MASK;
         hash_key[0] |= tmp_addr_part << (V4_BIT_LENGTH); // left aligment on 64 bits of uint64_t
         tmp_addr_part = ip_get_v4_as_int(ur_get_ptr(in_tmplt, in_rec, UR_DST_IP)) & V4_HASH_KEY_MASK;
         hash_key[0] |= tmp_addr_part << (V4_BIT_LENGTH - V4_HASH_KEY_PART);
      } else {
//         if(V6_HASH_KEY_PART == V6_BIT_PART_LENGTH){
         #if V6_HASH_KEY_PART == V6_BIT_PART_LENGTH
            hash_key[0] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0];
            hash_key[1] = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0];
            hk_size = sizeof(hash_key[0])*2;
//         } else if(V6_HASH_KEY_PART == V6_BIT_PART_LENGTH*2) {
         #elif V6_HASH_KEY_PART == V6_BIT_PART_LENGTH*2
            hash_key[0] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0];
            hash_key[1] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[1];
            hash_key[2] = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0];
            hash_key[3] = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[1];
            hk_size = sizeof(hash_key);
//         } else if(V6_HASH_KEY_PART < V6_BIT_PART_LENGTH) {
         #elseif V6_HASH_KEY_PART < V6_BIT_PART_LENGTH
            tmp_addr_part = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0] & V6_HASH_KEY_MASK;
            hash_key[0] |= tmp_addr_part;
            tmp_addr_part = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0] & V6_HASH_KEY_MASK;
            hash_key[0] |= tmp_addr_part >> V6_HASH_KEY_PART;
            hash_key[1] |= tmp_addr_part << (V6_BIT_PART_LENGTH - V6_HASH_KEY_PART);
            hk_size = sizeof(hash_key[0])*2;
//         } else { // V6_HASH_KEY_PART > V6_BIT_PART_LENGTH
         #else // V6_HASH_KEY_PART > V6_BIT_PART_LENGTH
            hash_key[0] = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[0];
            tmp_addr_part = ur_get(in_tmplt, in_rec, UR_SRC_IP).ui64[1] & V6_HASH_KEY_MASK;
            hash_key[1] |= tmp_addr_part;
            tmp_addr_part = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[0];
            hash_key[1] |= tmp_addr_part >> (V6_HASH_KEY_PART % 64);
            hash_key[2] |= tmp_addr_part << (V6_BIT_PART_LENGTH - (V6_HASH_KEY_PART % 64));
            tmp_addr_part = ur_get(in_tmplt, in_rec, UR_DST_IP).ui64[1] & V6_HASH_KEY_MASK;
            hash_key[2] |= tmp_addr_part >> (V6_HASH_KEY_PART % 64);
            hash_key[3] |= tmp_addr_part << (V6_BIT_PART_LENGTH - (V6_HASH_KEY_PART % 64));
            hk_size = sizeof(hash_key);
//         }
         #endif
      }
      //    *** END OF Getting HashKey ***
      //    *** Adding feature occurrence in all sketches ***
      for(int i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
         row_in_sketch = SuperFastHash((char *)hash_key, hk_size, seeds[i]) % SKETCH_SIZE;
         sip_sketches[i][row_in_sketch]
                     [SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_SRC_IP),
                                   sizeof(ur_get(in_tmplt, in_rec, UR_SRC_IP)), SEED_DEFAULT) % ADDRESS_SKETCH_WIDTH]
                     += ur_get(in_tmplt, in_rec, UR_PACKETS);
         dip_sketches[i][row_in_sketch]
                     [SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_DST_IP),
                                   sizeof(ur_get(in_tmplt, in_rec, UR_DST_IP)), SEED_DEFAULT) % ADDRESS_SKETCH_WIDTH]
                     += ur_get(in_tmplt, in_rec, UR_PACKETS);
         sp_sketches[i][row_in_sketch]
                    [SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_SRC_PORT),
                                  sizeof(ur_get(in_tmplt, in_rec, UR_SRC_IP)), SEED_DEFAULT) % PORT_SKETCH_WIDTH]
                    += ur_get(in_tmplt, in_rec, UR_PACKETS);
         dp_sketches[i][row_in_sketch]
                    [SuperFastHash((char *)ur_get_ptr(in_tmplt, in_rec, UR_DST_PORT),
                                  sizeof(ur_get(in_tmplt, in_rec, UR_DST_IP)), SEED_DEFAULT) % PORT_SKETCH_WIDTH]
                    += ur_get(in_tmplt, in_rec, UR_PACKETS);
         packet_counts[i][row_in_sketch] += ur_get(in_tmplt, in_rec, UR_PACKETS);
      }
         //    *** END OF Adding feature occurrence in all sketches ***
         // *** END OF flow reading & structure filling ***

//////      // Read FOO and BAR from input record and compute their sum
//////      uint32_t baz = ur_get(in_tmplt, in_rec, UR_FOO) +
//////                     ur_get(in_tmplt, in_rec, UR_BAR);
//////
//////      // Fill output record
//////      ur_set(out_tmplt, out_rec, UR_FOO, ur_get(in_tmplt, in_rec, UR_FOO));
//////      ur_set(out_tmplt, out_rec, UR_BAR, ur_get(in_tmplt, in_rec, UR_BAR));
//////      ur_set(out_tmplt, out_rec, UR_BAZ, baz);


      // Send record to interface 0, if ifc is not ready, wait at most 10ms
//////      trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), 10000);
   // ***** END OF Process the data *****

   }

   // Send terminating signal to output interface
   char dummy[1] = {0};
   trap_send_data(0, dummy, 1, TRAP_WAIT);

   // ***** Cleanup *****
   for (vector<void *>::iterator it = actual_flows.begin(); it != actual_flows.end(); ++it){
      ur_free(*it);
   }
   actual_flows.clear();
   trap_finalize();
   ur_free(out_preliminary_rec);
//   ur_free(out_detailed_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_preliminary_tmplt);
//   ur_free_template(out_detailed_tmplt);
   // ***** END OF Cleanup *****
   return 0;
}

