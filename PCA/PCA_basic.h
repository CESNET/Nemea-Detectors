/**
 * \file PCA_basic.h
 * \brief !!!TODO...
 * \author Pavel Krobot <xkrobo01@stud.fit.vutbr.cz>
 * \date 2013
 */
#ifndef _PCA_BASIC_H_
#define _PCA_BASIC_H_

#include <string>
#include <vector>

using namespace std;

//#define REALLY_BIG_REAL_NUMBER 999999.9
//#define NORM_AMOUNT_INDETIFICATION_THRESHOLD 1.0
//#define IDENTIFICATION_TTL 4 // maximum of how many times could be found same index

#define VERBOSE_MSG
#ifdef VERBOSE_MSG
   #define STATUS_MSG(stream,msg) stream << msg << flush;
#else//VERBOSE_MSG
   #define STATUS_MSG(stream,msg) ;
#endif//VERBOSE_MSG



#define DEFAULT_PATH_TO_SETTINGS "settings.txt"

//#define DEFAULT_UNIREC_SPECIFIER "TIMESLOT,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT"
#define DEFAULT_UNIREC_SPECIFIER "TIME_FIRST,LINK_BIT_FIELD,FLOWS,PACKETS,BYTES,ENTROPY_SRCIP,ENTROPY_DSTIP,ENTROPY_SRCPORT,ENTROPY_DSTPORT"
#define DEFAULT_UNIREC_SPECIFIER_DETECTION "TIME_FIRST,LINK_BIT_FIELD"

#define DEFAULT_LINK_COUNT 0
#define DEFAULT_LINK_NAMES "" //every link name HAVE TO BE ENDED by "," (even last). Example: "link1,l2,lin3,"

#define DEFAULT_WORKING_TIMEBIN_WINDOW_SIZE (288*3) // For better performance it should

#define DEFAULT_TIMESLOT_INCREMENT 5
#define DEFAULT_RCV_OUT_OF_TIMEBIN_TOLERANCE 2 //defines "out of expected" tolerance for incoming timeslots of records

#define DEFAULT_PREPROCESSING_FLAG 1
#define DEFAULT_TDM_MATCH_VERSION TDM_ANY
//#define DEFAULT_TDM_SELECTOR ((uint64_t) 0b11111111110000000000)
#define DEFAULT_TDM_SELECTOR ((uint64_t) 0xffffffffffffffc0)

#define DEFAULT_AGREG_UNIT_CNT 7 //FLOWS,PACKETS,BYTES,E-SRCIP,E-DSTIP,E-SRCPORT,E-DSTPORT

#define SETTINGS_COMMENTARY_CHARACTER "#"

//#define LOG_DST cout
#define LOG_DST log // name of "ofstream" variable
#define LOG_TO_FILE "PCA_basic-log"
#define ANOMALY_LOG_NAME "PCA-detector-anomaly_log.txt"

#define USE_JOINT_MATRIX_OP

#define PREPROCESS_DATA_DEV_MULTIPLIER 3

//#define STD_DEV 0.35355339 // 1/sqrt(DEFAULT_WORKING_TIMEBIN_WINDOW_SIZE)
#define STD_DEV_VERSION2

//#define NSS_FIXED 2
#define NSS_BY_PERCENTAGE 0.90
//#define NSS_BY_DELTA_TEST 5

//#define SPE_TESTING 0 //value is index in A_PERCENTILES
#ifdef SPE_TESTING
	#define A_PERCENTILE_DEF_CNT 3
#endif//SPE_TESTING

#define DEFAULT_DETECTION_THRESHOLD 5//stdandard deviation multiplier

#define MASK_BIT(selector) (1 << selector)


//#define MULTI_TEST
#ifdef MULTI_TEST
	#ifdef NSS_BY_DELTA_TEST
		#define NSS_DEF_CNT 7
	#else//NSS_BY_DELTA_TEST
		#define NSS_DEF_CNT 3
	#endif//NSS_BY_DELTA_TEST

	#define DELTA_TESTNIG_CNT 5

	#ifdef SPE_TESTING
		#define DETECTION_TEST_CNT DELTA_TESTNIG_CNT + A_PERCENTILE_DEF_CNT
	#else//SPE_TESTING
		#define DETECTION_TEST_CNT DELTA_TESTNIG_CNT
	#endif//SPE_TESTING

	#define STARTING_DETECTION_THRESOLD 3
	#define DETECTION_THRESHOLD_INCREMENT 1

	#define NSS_BY_PERCT_MULTIPLER(i) (float)(NSS_BY_PERCENTAGE + (i) * 0.05)

	#define DETECTION_THRESHOLD_MULTIPLIER(i) (float)(STARTING_DETECTION_THRESOLD + ((float)(i) * DETECTION_THRESHOLD_INCREMENT))
#endif//MULTI_TEST

#ifdef SPE_TESTING
float A_PERCENTILES[5] = {0.841621, 1.036433, 1.281552, 1.644854, 2.326348};
const char *A_PERC_NAMES [] =
{
	"80%",
	"85%",
	"90%",
	"95%",
	"99%",
};
#endif//SPE_TESTING

/**
 * Option names (like it have to be written in settings-file).
 */
const char *SETTINGS_OPTION [] =
{
	"link count=",		//option 0
	"links=",			//option 1
	"agregation=",		//option 2
	"window size=",	//option 3
	"tolerance=",		//option 4
	"preprocessing",	//option 5
	"td match=",		//option 6
	"td selector=",	//option 7
};
/**
 * Agregation unit names.
 */
const char *AGREG_UNIT_NAME [] =
{
	"flows",
	"packets",
	"bytes",
	"ent_sip",
	"ent_dip",
	"ent_sport",
	"ent_dport",
	"unspecified-error",
};
/**
 * Agregation unit codes.
 */
enum agreg_unit_code {
   AU_FLOWS = 0,
   AU_PACKETS,
   AU_BYTES,
   AU_ESIP,
   AU_EDIP,
   AU_ESPORT,
   AU_EDPORT,
};
/**
 * True detection match versions.
 */
enum true_det_match_version {
   TDM_ANY = 0,
   TDM_EXACT,
};

typedef struct PCA_basic_settings {
   string path_to_settings;
   char *in_unirec_specifier;//used by detector only
   char *out_unirec_specifier;
	unsigned int link_count;
	vector <string> link_names;
	unsigned int agreg_unit_per_link;
	unsigned int agreg_unit_field;
	unsigned int *selected_agreg_units;
	unsigned int working_timebin_window_size;//used by detector only
	unsigned int data_matrix_width;//used by detector only

	unsigned int out_of_timebin_rcv_tolerance;//used by detector only
	unsigned int timeslot_increment;//used by detector only
	unsigned int preprocessing_flag;//used by detector only
	unsigned int true_detection_match;//used by detector only
	uint64_t true_detection_selector;//used by detector only
} pca_basic_settings_t;

#endif
// END OF PCA_basic.h
