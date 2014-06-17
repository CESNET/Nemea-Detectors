

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






// SCAN
#define SCAN_UNIQ_CON_THRESHOLD 5
#define SCAN_UNIQ_MEAN_PPF_THRESHOLD 2
#define SCAN_UNIQ_SYN_ONLY_THRESHOLD 5
#define SCAN_UNIQ_SYN_ONLY_RATIO_THRESHOLD 0.9f // Not used
#define SCAN_UNIQ_ACK_ONLY_THRESHOLD 5

// BRUTEFORCE
#define BF_TOTAL_CON_THRESHOLD 15
#define BF_TOTAL_MEAN_PPF_THRESHOLD_MIN 9
#define BF_TOTAL_MEAN_PPF_THRESHOLD_MAX 30
#define BF_TOTAL_SYN_ONLY_RATIO_THRESHOLD 50
#define BF_TOTAL_CON_SAP_THRESHOLD 15
#define BF_TOTAL_CON_SAP_RATIO_THRESHOLD 0.9f // Not used


#define HT_TABLE_SIZE 64000
#define HT_DATA_SIZE  128
#define HT_KEY_SIZE   2
#define SSH_PORT 22
#define TCP 6

#define FIN_FLAG 0x1
#define SYN_FLAG 0x2
#define PSH_FLAG 0x8
#define ACK_FLAG 0x10



static const char *RED_S  = "\033[0;31m";
static const char *RED_E  = "\033[0m";



typedef struct {
   ip_addr_t vic_ip;
   float ppf;
   float mfd;
   uint32_t syn_only;   // SYN only flows
   uint32_t con_sap;    // SYN && ACK && PSH flows
   uint32_t con_total;  // Total flows
} vic_data_t;


typedef struct {
   ip_addr_t atk_ip;
   uint32_t uniq_con;
   uint32_t total_con;
   float uniq_ppf;
   float total_ppf;
   uint32_t vic_ip_count;
   uint32_t uniq_syn_only;
   uint32_t uniq_syn_ack_only;
   uint32_t total_con_sap;
   vic_data_t *vic_data;
} ht_data_t;


enum attack_types {
   AT_SCAN_UNK = 1,
   AT_SCAN_SYN = 2,
   AT_SCAN_CON = 4,
   AT_SCAN_INV = 8,
   AT_BRUTEFORCE_IP = 16,
   AT_BRUTEFORCE_ALL = 32
};
