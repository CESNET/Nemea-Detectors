#ifndef _PCA_SKETCH_H_
#define _PCA_SKETCH_H_

#define SKETCH_SIZE 512
#define SKETCH_WIDTH 4096 // For better performance it should be power of 2 since the value is used for modulus

#define NUMBER_OF_FEATURES 4

#define NUMBER_OF_HASH_FUNCTION 4

#define TIMEBIN_SIZE 30 // Size of single timebin in seconds

#define WORKING_TIMEBIN_WINDOW_SIZE 100

enum features_order
{
   FSRCIP=0,
   FSRCPORT,
   FDSTIP,
   FDSTPORT
};

#endif
