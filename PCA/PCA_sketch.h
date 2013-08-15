/**
 * \file PCA_sketch.h
 * \brief !!!TODO...
 * \author Pavel Krobot <xkrobo01@stud.fit.vutbr.cz>
 * \date 2013
 */
#ifndef _PCA_SKETCH_H_
#define _PCA_SKETCH_H_

//#define OFFLINE_MODE
//#define AUTO_INITIALIZATION
#define DEFAULT_PATH_TO_DATA "/data/xkrobo01/dm_rows/256_7"
//#define OUTPUT_FOLDER "/data/xkrobo01/dm_rows/06/"
#define OUTPUT_FOLDER "./dm_rows/"
#define OUTPUT_FILE_NAME "pca_dm_row_HF"

#define NEW_TIMEBIN_DIVISION

//#define PREPROCESS_DATA
#define PREPROCESS_DATA_DEV_MULTIPLIER 3

#define V4_BIT_LENGTH 32 // Number of bits of IPv4 address length
#define V6_BIT_PART_LENGTH 64 // Number of bits of one array field of IPv6 address

#define V4_HASH_KEY_PART 21 // Number of bits of IPv4 address used for creating HashKey (source & destination)
#define V4_HASH_KEY_MASK 0xFFFFF800 // Must correspond with V4_HASH_KEY_PART.
#define V6_HASH_KEY_PART 48 // Number of bits of IPv6 address used for creating HashKey (source & destination)
#define V6_HASH_KEY_MASK 0xFFFFFFFFFFFF0000 // Must correspond with V6_HASH_KEY_PART. If V6_HASH_KEY_PART > 64,
                                            // V6_HASH_KEY_MASK is for 64 - V6_HASH_KEY_PART
#define TIMEBIN_SIZE 300 // Size of single timebin in seconds

#define WORKING_TIMEBIN_WINDOW_SIZE (7*288) // For better performance it should
                                // be power of 2 since the value is used for modulus

#define SKETCH_SIZE 256 // For better performance it should be power of 2

#define ADDRESS_SKETCH_WIDTH 4096 // (2^12) - For better performance it should
                                // be power of 2 since the value is used for modulus
#define PORT_SKETCH_WIDTH 4096 // (2^12) - For better performance it should
                                // be power of 2 since the value is used for modulus

#define NUMBER_OF_HASH_FUNCTION 4

#define NUMBER_OF_FEATURES 4
#define DATA_MATRIX_WIDTH (NUMBER_OF_FEATURES * SKETCH_SIZE)

#define SEED_DEFAULT 0

#define USE_JOINT_MATRIX_OP

//#define STD_DEV 0.35355339 // 1/sqrt(WORKING_TIMEBIN_WINDOW_SIZE)
#define STD_DEV_VERSION2

//#define NORMAL_SUBSPACE_SIZE_FIXED 10
//#define NSS_BY_PERCENTAGE 0.90
#define NSS_BY_DELTA_TEST 3

#define ALPHA_PERCENTILE_95 1.645
//#define ALPHA_PERCENTILE_99 2.326

#define NUMBER_OF_TRUE_DETECTION_THRESHOLD NUMBER_OF_HASH_FUNCTION-1

#define REALLY_BIG_REAL_NUMBER 999999.9

#define NORM_AMOUNT_INDETIFICATION_THRESHOLD 1.0
#define IDENTIFICATION_TTL 4 // maximum of how many times could be found same index

#define VERBOSE_MSG
#ifdef VERBOSE_MSG
   #define STATUS_MSG(stream,msg) stream << msg << flush;
#else
   #define STATUS_MSG(stream,msg) ;
#endif

//#define LOG_DST cout
#define LOG_DST log // name of "ofstream" variable
#define LOG_TO_FILE "PCA_sketch-log"

int seeds[NUMBER_OF_HASH_FUNCTION] = {       5,
                                            37,
                                           719,
                                         18181};

#endif
