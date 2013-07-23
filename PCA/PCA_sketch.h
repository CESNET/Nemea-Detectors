/**
 * \file PCA_sketch.h
 * \brief !!!TODO...
 * \author Pavel Krobot <xkrobo01@stud.fit.vutbr.cz>
 * \date 2013
 */
#ifndef _PCA_SKETCH_H_
#define _PCA_SKETCH_H_

#define PREPROCESS_DATA
//#define IDENTIFICATION

#define V4_BIT_LENGTH 32 // Number of bits of IPv4 address length
#define V6_BIT_PART_LENGTH 64 // Number of bits of one array field of IPv6 address

#define V4_HASH_KEY_PART 21 // Number of bits of IPv4 address used for creating HashKey (source & destination)
#define V4_HASH_KEY_MASK 0xFFFFF800 // Must correspond with V4_HASH_KEY_PART.
#define V6_HASH_KEY_PART 48 // Number of bits of IPv6 address used for creating HashKey (source & destination)
#define V6_HASH_KEY_MASK 0xFFFFFFFFFFFF0000 // Must correspond with V6_HASH_KEY_PART. If V6_HASH_KEY_PART > 64,
                                            // V6_HASH_KEY_MASK is for 64 - V6_HASH_KEY_PART

#define SKETCH_SIZE 256 // (2^9) - For better performance it should be power
                           // of 2 since the value is used for modulus
#define ADDRESS_SKETCH_WIDTH 4096 // (2^12) - For better performance it should
                                // be power of 2 since the value is used for modulus
#define PORT_SKETCH_WIDTH 4096 // (2^12) - For better performance it should
                                // be power of 2 since the value is used for modulus

#define NUMBER_OF_FEATURES 4

#define NUMBER_OF_HASH_FUNCTION 4

#define SEED_DEFAULT 0

#define TIMEBIN_SIZE 30 // Size of single timebin in seconds

#define WORKING_TIMEBIN_WINDOW_SIZE 8 // For better performance it should
                                // be power of 2 since the value is used for modulus

//#define STD_DEV 0.35355339 // 1/sqrt(WORKING_TIMEBIN_WINDOW_SIZE)
#define STD_DEV_VERSION2

#define PREPROCESS_DATA_DEV_MULTIPLIER 3

//#define NORMAL_SUBSPACE_SIZE_FIXED 10
//#define NSS_BY_PERCENTAGE 0.95
#define NSS_BY_DELTA_TEST 3

#define ALPHA_PERCENTILE_95 1.645
//   #define ALPHA_PERCENTILE_99 2.326

#define NUMBER_OF_TRUE_DETECTION_THRESHOLD NUMBER_OF_HASH_FUNCTION-4

#define REALLY_BIG_REAL_NUMBER 999999.9

#define NORM_AMOUNT_INDETIFICATION_THRESHOLD 1.0
#define IDENTIFICATION_TTL 4 // maximum of how many times could be found same index

int seeds[NUMBER_OF_HASH_FUNCTION] = {       5,
                                            37,
                                           719,
                                         18181};

//void  transform_submatrix_unit_energy (real_2d_array *matrix_ptr, int start_index, int last_index);
//
//void transform_matrix_zero_mean (real_2d_array *matrix_ptr);
//
//void multiply_matrix_column_vector (real_2d_array *A_matrix_ptr, real_2d_array *B_matrix_ptr, unsigned int B_matrix_column,
//                                    float (*result)[WORKING_TIMEBIN_WINDOW_SIZE]);
//
//float norm_of_vector (float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE]);
//
//float norm_of_vector (float (*vector_ptr)[4*SKETCH_SIZE]);
//
//void divide_vector_by_value (float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE], float divider);
//
//float vector_standard_deviation (float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE]);
//
//float vector_standard_deviation_v2(float (*vector_ptr)[WORKING_TIMEBIN_WINDOW_SIZE]);
//
//void substitute_matrix (uint8_t (*A_matrix_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE],
//                        float (*B_matrix_result_ptr)[4*SKETCH_SIZE][4*SKETCH_SIZE]);

//...453
#endif
