

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <nemea-common.h>
#include <cuckoo_hash_v2.h>



#define HT_TABLE_SIZE 64000
#define HT_DATA_SIZE  128
#define HT_KEY_SIZE   2
#define SSH_PORT 22

#define FIN_FLAG 0x1
#define SYN_FLAG 0x2
#define PSH_FLAG 0x8
#define ACK_FLAG 0x10



#define SCAN_UNIQ_CON_THRESHOLD 5
#define SCAN_UNIQ_MEAN_PPF_THRESHOLD 2
#define SCAN_UNIQ_SYN_ONLY_RATIO_THRESHOLD 0.9f

#define BF_TOTAL_CON_THRESHOLD 30
#define BF_TOTAL_MEAN_PPF_THRESHOLD_MIN 7
#define BF_TOTAL_MEAN_PPF_THRESHOLD_MAX 25
#define BF_TOTAL_SYN_ONLY_RATIO_THRESHOLD 50
#define BF_TOTAL_WCON_RATIO_THRESHOLD 0.9f






static const char *RED_S  = "\033[0;31m";
static const char *RED_E  = "\033[0m";


typedef struct {
   ip_addr_t atk_ip;
   uint32_t uniq_con;
   uint32_t total_con;
   float uniq_ppf;
   float total_ppf;
   uint32_t vic_ip_count;
   uint32_t uniq_syn_only;
   uint32_t total_syn_only;
   uint32_t total_wcon;
   ip_addr_t *vic_ip_ar;
} ht_data_t;



