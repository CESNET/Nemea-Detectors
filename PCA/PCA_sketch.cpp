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

#define DEBUG
//#define DEBUG_OUT
   #ifdef DEBUG_OUT
      #include <inttypes.h>
   #endif
//#define VALIDATION
   #ifdef VALIDATION
      #include <fstream>
      #include <iostream>
      #include <limits>
      ofstream output;
   #endif
uint32_t SuperFastHash (const char *data, int len, int seed) {
   uint32_t hash = len + seed, tmp;
   int rem;

         #ifdef DEBUG_OUT
            uint64_t *data2=data;
            printf("%" PRIu64 "\n", data2[0]);
         #endif

         #ifdef DEBUG_OUT
            uint64_t *data2=data;

            printf("HashKey: ");
            for(int i=0;i<(len/8);i++){
               printf("%016llX:", data2[i]);
            }
//            printf("%" PRIu64 "\n", data2[0]);
            printf("\nLen: %i\n", len);
         #endif

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
   "Module for anomaly detection using PCA and sketch subspaces.",// Module name
   // Module description
   "This module detecting network anomalies in data flows.\n"
   ""
   "Interfaces:\n"
   "   Inputs: 1 UniRec (ur_basic_flow_t)\n"
   "   Outputs: 2:\n"
   "     \t1.UniRec - information about time in witch an anomaly(-ies) "
                                                                  "occuring.\n"
   "     \t2.UniRec - flow(s) responsible for an anomaly(-ies)",
   1, // Number of input interfaces
   2, // Number of output interfaces
};


static int stop = 0;

/*
 * Procedure for handling signals SIGTERM and SIGINT
 */
void signal_handler(int signal)
{
   if (trap_get_verbose_level() > 0)
      printf("Signal received\n");
   if (signal == SIGTERM || signal == SIGINT) {
      stop = 1; // this breaks the main loop
      trap_terminate(); // this interrupt a possible waiting in recv/send functions
   }
}

/**
 * \brief Procedure for computing entropy of one sketch row
 * \param[in] uint32_t pointer to sketch row which values will be processed.
 * \param[in] Length of processed row.
 * \param[in] Total count of all packets in flows in processed row.
 * \return Entropy of one sketch row.
 */
float compute_entropy(uint32_t *sketch_row, unsigned int row_length, uint64_t packet_count)
{
   float entropy = 0.0;
   for (int i = 0; i < row_length; i++)
   {
      if(sketch_row[i] >0){
         float p = (float)sketch_row[i] / packet_count;
         entropy -= p * log2(p);
      }
   }
   return entropy;
}

// ***************** MATRIX OPERATIONS *****************************************
/**
 * \brief Procedure for transforming submatrix of matrix to have unit energy.
 *
 * Procedure transform submatrix of "matrix_ptr" defined by column "start_index"
 * and "last_index" to unit energy (last_index is first which is not affected)
 * \param[in,out] alglib::real_2d_array pointer to matrix which should be normalized.
 * \param[in] Start index - first column of submatrix.
 * \param[in] Last index - last column of submatrix (first column which is not
 * affected).
 */
void  transform_submatrix_unit_energy(real_2d_array *matrix_ptr, int start_index, int last_index)
{
  float energy_of_submatrix;

  for(int i = start_index; i < last_index; i++){
      for(int j = 0; j < matrix_ptr->rows(); j++){
         energy_of_submatrix+=(*matrix_ptr)(j,i)*(*matrix_ptr)(j,i);
      }
  }
  energy_of_submatrix/=(matrix_ptr->rows()*(last_index-start_index));

  for(int i = start_index; i < last_index; i++){
      for(int j = 0; j < matrix_ptr->rows(); j++){
         (*matrix_ptr)(j,i)/=energy_of_submatrix;
      }
   }
}

/**
 * \brief Procedure which transforms columns of matrix to have zero mean
 * \param[in,out] alglib::real_2d_array pointer to matrix which should be normalized.
 */
void transform_matrix_zero_mean(real_2d_array *matrix_ptr)
{
   float mean;

   for(int i = 0; i < matrix_ptr->cols(); i++){
      for(int j = 0; j < matrix_ptr->rows(); j++){
         mean+=(*matrix_ptr)(j, i);
      }
      mean/=matrix_ptr->rows();
      for(int j = 0; j < matrix_ptr->rows(); j++){
         (*matrix_ptr)(j,i)-=mean;
      }
   }
}

/**
 * \brief Procedure which multyply matrix by vector.
 *
 * Procedure multiply source matrix by column of second matrix (vector). Return
 * result in third.
 * \param[in] alglib::real_2d_array pointer to first matrix (A).
 * \param[in] alglib::real_2d_array pointer to second matrix (B).
 * \param[in] integer value which specifies column of second matrix (B).
 * \param[out] alglib::real_1d_array pointer to matrix in which should be stored
 * result of A * B[:PARAM3].
 */
void multiply_matrix_column_vector (real_2d_array *A_matrix_ptr,real_2d_array *B_matrix_ptr, unsigned int B_matrix_column, real_1d_array *result)
{ //A*B=result
   float row_sum;

//  if(A_matrix_ptr->cols()==B_matrix_ptr->rows()){ //check if matrixes have proper size
   for(int i = 0; i < result->length(); i++){
      row_sum=0;
      for (int j = 0; j < A_matrix_ptr->cols(); j++){
         row_sum += (*A_matrix_ptr)(i,j) * (*B_matrix_ptr)(j,B_matrix_column);
      }
      (*result)(i) = row_sum;
   }
//  }
}
/**
 * \brief Procedure which compute norm of vector.
 * \param[in] alglib::real_1d_array pointer to vector.
 * \return Returns real (float) value norm of vector.
 */
float norm_of_vector(real_1d_array *vector_ptr)
{
   float sum=0;

   for(int i = 0; i < vector_ptr->length(); i++){
      sum += (*vector_ptr)(i) * (*vector_ptr)(i);
   }

   return sqrt(sum);
}
/**
 * \brief Procedure which divide vector by value.
 *
 * Procedure divide vector by value - overwrite original vector.
 * \param[in] alglib::real_1d_array pointer to vector which should by divided.
 * \param[in] Real (float) value by which should be vector divided.
 */
void divide_vector_by_value(real_1d_array *vector_ptr, float divider)
{
   for(int i = 0; i < vector_ptr->length(); i++){
      (*vector_ptr)(i) /= divider;
   }
}

/**
 * \brief Procedure which divide vector by value.
 *
 * Procedure divide vector by value - overwrite original vector.
 * \param[in] alglib::real_1d_array pointer to vector which should by divided.
 * \param[in] Real (float) value by which should be vector divided.
 */
float mean_value_from_vector_power2(real_1d_array *vector_ptr)
{
   float sum=0;
//  SINCE VALUES_ARE_MEAN_CENTERED - HAVE_ZERO_MEAN >> Simplier version:
   for(int i = 0; i < vector_ptr->length(); i++){
      sum += (*vector_ptr)(i) * (*vector_ptr)(i);
   }

   return sum / vector_ptr->length();
}

float mean_value_from_vector_power2_v2(real_1d_array *vector_ptr)
{
   float sum=0, tmp;
   float mean=0;
   for(int i = 0; i < vector_ptr->length(); i++){
      mean+=(*vector_ptr)(i);
   }
   mean /= vector_ptr->length();
//  SINCE VALUES_ARE_MEAN_CENTERED - HAVE_ZERO_MEAN >> Simplier version:
   for(int i = 0; i < vector_ptr->length(); i++){
      tmp = (*vector_ptr)(i) - mean;
      sum += tmp * tmp;
   }

   return sum / (vector_ptr->length()-1) ;
}

/**
 * \brief Procedure which multiply submatrix of matrix and transposed submatrix
 * of the same matrix.
 *
 * Procedure multiply submatrix of "matrix_ptr" defined by column "0" and
 * "column_delimiter" with the same submatrix transposed.
 * \param[in] Source matrix.
 * \param[in] Column delimiter - specifies size of submatrix (column count).
 * \param[out] 2D array of float for result.
 */
void multiply_submatrix_by_transposed_submatrix (real_2d_array *matrix_ptr, unsigned int column_delimiter, float (*result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE])
{
   uint16_t x,y;
   float row_sum;

   for(int i = 0; i < (matrix_ptr->rows() * matrix_ptr->rows()); i++){
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
 * \brief Substitute second matrix from first. Stores result in second.
 *
 * \param[in] Pointer to First matrix.
 * \param[in,out] Pointer to secod and result matrix.
 */
void substitute_matrix (uint8_t (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE], float (*B_matrix_result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE])
{
   for(int i = 0; i < 4 * SKETCH_SIZE; i++){
      for (int j = 0; j < 4 * SKETCH_SIZE; j++){
         (*B_matrix_result_ptr)[i][j] = (*A_matrix_ptr)[i][j]  - (*B_matrix_result_ptr)[i][j];
      }
    }
}

/**
 * \brief Procedure which multiply matrix and transposed row of another matrix.
 *
 * Procedure multiply matrix and transposed row of "B_matrix_ptr" defined by
 * row_selector.
 * \param[in] Pointer to first matrix.
 * \param[in] Pointer to second matrix, which contains row, which is used as
 * column vector (transposed row).
 * \param[in] Row delimiter - specifies row of B_matrix_ptr.
 * \param[out] alglib::real_1d:array pointer to vector for result.
 */
void multiply_matrix_by_transposed_line (float (*A_matrix_ptr) [4*SKETCH_SIZE][4*SKETCH_SIZE],
                                         real_2d_array *B_matrix_ptr, unsigned int row_selector,
                                         real_1d_array *result_ptr)
{
   uint16_t y;
   float row_sum;

   for(int i = 0; i < 4*SKETCH_SIZE; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < 4*SKETCH_SIZE; j++){
         row_sum += (*A_matrix_ptr)[y][j] * (*B_matrix_ptr)[row_selector][j];
      }

      (*result_ptr)(i) = row_sum;
   }
}
// ***************** END OF MATRIX OPERATIONS **********************************
int main(int argc, char **argv)
{
   #ifdef DEBUG_OUT
      int checker=5;
   #endif
   int ret;
   trap_ifc_spec_t ifc_spec;

   int i,j,k;

   int need_more_timebins=WORKING_TIMEBIN_WINDOW_SIZE;
   uint8_t timebin_init_flag=1;
   uint32_t start_of_actual_flow;
   uint32_t timebin_counter; // counted from zero
   uint32_t start_of_next_timebin=0;

   vector <char *> actual_flows;

   uint64_t tmp_addr_part; // for IPv4
   uint64_t hash_key [4];
   int hk_size;

   uint32_t row_in_sketch;

   static uint32_t sip_sketches [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][ADDRESS_SKETCH_WIDTH];
   static uint32_t dip_sketches [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];
   static uint32_t sp_sketches [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];
   static uint32_t dp_sketches [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE][PORT_SKETCH_WIDTH];

   static uint64_t packet_counts [NUMBER_OF_HASH_FUNCTION][SKETCH_SIZE];

   real_2d_array data_matrices[NUMBER_OF_HASH_FUNCTION];
   for(i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
      data_matrices[i].setlength(WORKING_TIMEBIN_WINDOW_SIZE,SKETCH_SIZE*4);
   }
   real_2d_array principal_components;
	real_1d_array eigenvalues;
   ae_int_t info;

   uint16_t normal_subspace_size;

   static uint8_t identity_matrix [4*SKETCH_SIZE][4*SKETCH_SIZE];
   memset(identity_matrix, 0, sizeof(identity_matrix[0][0])*4*SKETCH_SIZE*4*SKETCH_SIZE);
   for(j = 0; j < 4 * SKETCH_SIZE; j++){
      identity_matrix[j][j]=1;
   }


//   void (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(type1 *, type2, ...);
   uint32_t (*ptrHashFunc [NUMBER_OF_HASH_FUNCTION])(const char *, int , int );
   ptrHashFunc [0] = SuperFastHash;
   ptrHashFunc [1] = SuperFastHash;
   ptrHashFunc [2] = SuperFastHash;
   ptrHashFunc [NUMBER_OF_HASH_FUNCTION - 1] = SuperFastHash;

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

   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      fprintf(stderr, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      return 2;
   }

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);


   // ***** Create UniRec templates *****
   // From ../../nfreader/nfdump_reader.c
   ur_template_t *in_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,"
                                                "DST_PORT,PROTOCOL,TIME_FIRST,"
                                                "TIME_LAST,PACKETS,BYTES,"
                                                "TCP_FLAGS");
   //   ur_template_t *work_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,TIME_FIRST,PACKETS");
//////   ur_template_t *out_tmplt = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS");

   // Allocate memory for output record
//   void *work_rec = ur_create(work_tmplt, 0);
//////   void *out_rec = ur_create(out_tmplt, 0);

   // ***** Main processing loop *****
//   printf("Size of sketches is: %u\n", sizeof(address_sketches[0][0][0])*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION+
//                                       sizeof(port_sketches[0][0][0])*SKETCH_SIZE*PORT_SKETCH_WIDTH*2*NUMBER_OF_HASH_FUNCTION);
//   stop=1;
   // Read data from input, process them and write to output
   while (!stop) {
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

      // PROCESS THE DATA

      // *** Timebin division (sampling) based on TIMEBIN_SIZE (in seconds) ***
      start_of_actual_flow = (ur_get(in_tmplt,in_rec,UR_TIME_FIRST))>>32;

      if(timebin_init_flag){ // initialization of counters with first flow
         timebin_init_flag = 0;
         start_of_next_timebin = start_of_actual_flow + TIMEBIN_SIZE;
         timebin_counter = 0; // "human-like timebin" = timebin_counter + 1

         memset(sip_sketches, 0, sizeof(sip_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH);
         memset(dip_sketches, 0, sizeof(dip_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH);
         memset(sp_sketches, 0, sizeof(sp_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*PORT_SKETCH_WIDTH);
         memset(dp_sketches, 0, sizeof(dp_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*PORT_SKETCH_WIDTH);
         memset(packet_counts, 0, sizeof(packet_counts[0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE);
               #ifdef DEBUG
                  printf("Start of %u. timebin in %u------------------------------"
                        "--------------\n",timebin_counter,start_of_next_timebin);
               #endif
      }

      if(start_of_actual_flow>start_of_next_timebin){
         --need_more_timebins;
         for(i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
            for(j = 0; j < SKETCH_SIZE; j++){
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
         // *** Start detection (& identification) part ***
         if(!need_more_timebins){
            need_more_timebins++;
            for(i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
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
               #ifdef VALIDATION
               {
                  output.open("DataMatrix.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < data_matrices[i].rows(); j++){
                        for(k = 0; k < data_matrices[i].cols(); k++){
                           output<<data_matrices[i](j,k)<<"\t";
                        }
                        output<<"\n";
                     }
                  }
                  output.close();
               }
               #endif
               pcabuildbasis(data_matrices[i], data_matrices[i].rows(), data_matrices[i].cols(), info, eigenvalues, principal_components);
               //    *** END OF Computing of PCA ***
               #ifdef VALIDATION
               {
                  output.open("PrincipalComponents.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < principal_components.rows(); j++){
                        for(k = 0; k < principal_components.cols(); k++){
                           output<<principal_components(j,k)<<"\t";
                        }
                        output<<"\n";
                     }
                  }
                  output.close();
                  output.open("Eigenvalues.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < eigenvalues.length(); j++){
                        output<<eigenvalues(j)<<"\t";
                     }
                  }
                  output.close();
               }
               #endif
               //    *** Finding of normal subspace size ***
               #ifdef NORMAL_SUBSPACE_SIZE
                  normal_subspace_size=NORMAL_SUBSPACE_SIZE;
               #elif defined NSS_BY_PERCENTAGE
                  float variance_threshold,sum_variance=0;

                  for(j = 0; j < eigenvalues.length(); j++){
                     sum_variance+=eigenvalues(j);
                  }
                  variance_threshold=sum_variance*NSS_BY_PERCENTAGE;
                  //data_matrices[i].cols() == eigenvalues.length() == 4*SKETCH_SIZE
                  normal_subspace_size=eigenvalues.length();
                  while(sum_variance>variance_threshold){
                     sum_variance-=eigenvalues(--normal_subspace_size);
                  }
                  normal_subspace_size++;
               #else//NO NSS_BY_PERCENTAGE or NO NORMAL_SUBSPACE_SIZE
                  real_1d_array data2pc_projection;
                     data2pc_projection.setlength(WORKING_TIMEBIN_WINDOW_SIZE);
                  float norm, delta;

                  normal_subspace_size=0;
                  j=0;
                  #ifdef VALIDATION
                  {
                     multiply_matrix_column_vector(&data_matrices[i],&principal_components,j,&data2pc_projection);
                     output.open("Data2PC.txt");
                     output.precision(numeric_limits< double >::digits10);
                     if(i == 0){
                        for(j = 0; j < data2pc_projection.length(); j++){
                           output<<data2pc_projection(j)<<"\n";
                        }
                     }
                     norm=norm_of_vector(&data2pc_projection);
                     output<<norm;
                     output.close();
                     divide_vector_by_value(&data2pc_projection,norm);
                     output.open("Divided.txt");
                     output.precision(numeric_limits< double >::digits10);
                     if(i == 0){
                        for(j = 0; j < data2pc_projection.length(); j++){
                           output<<data2pc_projection(j)<<"\n";
                        }
                     }
                     output.close();
                     delta=sqrt(mean_value_from_vector_power2_v2(&data2pc_projection));
                     cout<<delta<<"\n";
                  }
                  #endif
                  while(!normal_subspace_size && j<4*SKETCH_SIZE){
                     multiply_matrix_column_vector(&data_matrices[i],&principal_components,j,&data2pc_projection);
                     norm=norm_of_vector(&data2pc_projection);
                     divide_vector_by_value(&data2pc_projection,norm);

                     delta=sqrt(mean_value_from_vector_power2_v2(&data2pc_projection));
                     for(k = 0; k < data2pc_projection.length();k++){//"Delta" test
                        if(fabs(data2pc_projection(j))>=NSS_BY_DELTA_TEST*delta){
//                        if(data2pc_projection(j) >= NSS_BY_DELTA_TEST * delta
//                        || data2pc_projection(j) <= -NSS_BY_DELTA_TEST * delta){
                           normal_subspace_size=j;
                        } //<if>
                     } //<for j>
                     j++;
                  }
               #endif //Normal subspace size definition
               printf("Normal subspace size (by count of principal components): %u\n",normal_subspace_size);
               #ifdef VALIDATION
               {
                  output.open("NormalPCs.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < principal_components.rows(); j++){
                        for(k = 0; k < normal_subspace_size; k++){
                           output<<principal_components(j,k)<<"\t";
                        }
                        output<<"\n";
                     }
                  }
                  output.close();
               }
               #endif
               //    *** END OF Finding of normal subspace size ***
               //    *** Computiing of linear operator C-residual (performs linear projection onto the anomaly subspace) ***
               static float lin_op_c_residual [4*SKETCH_SIZE][4*SKETCH_SIZE];

               multiply_submatrix_by_transposed_submatrix(&principal_components,normal_subspace_size,&lin_op_c_residual);
               #ifdef VALIDATION
               {
                  output.open("lin_op_c.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < 4*SKETCH_SIZE; j++){
                        for(k = 0; k < 4*SKETCH_SIZE; k++){
                           output<<lin_op_c_residual[j][k]<<"\t";
                        }
                        output<<"\n";
                     }
                  }
                  output.close();

               }
               #endif
               substitute_matrix(&identity_matrix,&lin_op_c_residual);
               #ifdef VALIDATION
               {
                  output.open("lin_op_c_residual.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < 4*SKETCH_SIZE; j++){
                        for(k = 0; k < 4*SKETCH_SIZE; k++){
                           output<<lin_op_c_residual[j][k]<<"\t";
                        }
                        output<<"\n";
                     }
                  }
                  output.close();
               }
               #endif
               //    *** END OF Computing of linear operator C-residual ***

               float phi [3] = {0,0,0};
               float lambda,SPE,h0,delta_SPE;
               real_1d_array mapped_data;
               mapped_data.setlength(4*SKETCH_SIZE);

               for(j = normal_subspace_size; j < 4*SKETCH_SIZE; j++){
                  lambda=eigenvalues(j);
                  phi[0] += lambda;
                  lambda *= lambda;
                  phi[1] += lambda;
                  lambda *= lambda;
                  phi[2] += lambda;
               }
               h0 = 1 - ((2 * phi[0] * phi[2]) / (3.0 * phi[1] * phi[1]));
               delta_SPE = phi[0] * pow((
                     ((ALPHA_PERCENTILE_99 * sqrt(2.0 * phi[1] * h0 * h0)) / phi[0])
                     + 1 + ((phi[1] * h0 * (h0-1.0)) / (phi[0] * phi[0])) ) ,(1.0/h0));

               multiply_matrix_by_transposed_line(&lin_op_c_residual, &data_matrices[i],
                                                  timebin_counter%WORKING_TIMEBIN_WINDOW_SIZE, &mapped_data);
               #ifdef VALIDATION
               {
                  output.open("mappedData.txt");
                  output.precision(numeric_limits< double >::digits10);
                  if(i == 0){
                     for(j = 0; j < mapped_data.length(); j++){
                        output<<mapped_data(j)<<"\n";
                     }
                  }
                  norm=norm_of_vector(&mapped_data);
                  output<<norm;
                  output.close();
               }
               stop=1;
               break;
               #endif
               SPE = norm_of_vector(&mapped_data);
               SPE*=SPE;

               if(SPE>delta_SPE){
                  printf("!!! Anomaly in timebin %u !!!\n", timebin_counter);
               } else {
                  printf("NO Anomaly in timebin %u.\n", timebin_counter);
               }

               //// detection_by_SPE_test();
            }
            // merge_results();
            // IF DETECTED:
            //>YES> proceed_with_identification >> merge results from all re-hashing >>
            // sending identificated & merged flows
            // drop_actual_flows ... proceed with another timebin
         }// *** END OF detection (& identification) part ***

         // !!!TODO overflow?
         ++timebin_counter;
         start_of_next_timebin += TIMEBIN_SIZE;
               #ifdef DEBUG
                  printf("Start of %u. timebin in %u------------------------------"
                        "--------------\n",timebin_counter,start_of_next_timebin);
               #endif
               #ifdef DEBUG_OUT
                  printf("\t\t\t\t%u\n",ip_get_v4_as_int(ur_get_ptr(in_tmplt, (void *) actual_flows[checker-1], UR_SRC_IP)));
               #endif

         for (vector<char *>::iterator it = actual_flows.begin(); it != actual_flows.end(); ++it){
            ur_free((void *)*it);
         }
         actual_flows.clear();

         memset(sip_sketches, 0, sizeof(sip_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH);
         memset(dip_sketches, 0, sizeof(dip_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*ADDRESS_SKETCH_WIDTH);
         memset(sp_sketches, 0, sizeof(sp_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*PORT_SKETCH_WIDTH);
         memset(dp_sketches, 0, sizeof(dp_sketches[0][0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE*PORT_SKETCH_WIDTH);
         memset(packet_counts, 0, sizeof(packet_counts[0][0])*NUMBER_OF_HASH_FUNCTION*SKETCH_SIZE);
      } // *** END OF Timebin division ***
      // *** Flow reading & structure filling ***
      //    *** Store flow from actual timebin ***
      actual_flows.push_back((char *)ur_cpy_alloc(in_tmplt, in_rec));
            #ifdef DEBUG_OUT
               if(actual_flows.size()==checker)
               {
                  printf("%u. Timebin - %i. flow srcIP: %u\n",timebin_counter+1,i,ip_get_v4_as_int(ur_get_ptr(in_tmplt, in_rec, UR_SRC_IP)));
         //         stop=1;
               }
            #endif
      //    *** END OF Store flow from actual timebin ***
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
      for(i = 0; i < NUMBER_OF_HASH_FUNCTION; i++){
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
   }

   // ***** Cleanup *****

   // Do all necessary cleanup before exiting
   trap_finalize();
//////   ur_free(out_rec);
   ur_free_template(in_tmplt);
//////   ur_free_template(out_tmplt);

   return 0;
}

