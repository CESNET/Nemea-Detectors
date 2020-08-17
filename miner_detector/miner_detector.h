/**
 * \file miner_detector.h
 * \brief Nemea module for detecting bitcoin miners.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2016
 */


#include <stdint.h>
#include <unirec/unirec.h>

#ifndef _H_MINER_DETECTOR
#define _H_MINER_DETECTOR

#define PROTO_TCP 0x06

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04    
#define TCP_PSH 0x08
#define TCP_ACK 0x10    // 16


/**
 * Used to compute score for suspect.
 * ACK flows + ACKPUSH flows must be at least this % of total flows.
 */
#define SUSPECT_ACKPUSH_FLOW_RATIO 80

/**
 * Used to compute score for suspect.
 * Lower boundry of bytes per packets.
 */
#define SUSPECT_LOW_BPP_TRESHOLD 50

/**
 * Used to compute score for suspect.
 * Upper boundry of bytes per packets.
 */
#define SUSPECT_HIGH_BPP_THRESHOLD 130

/**
 * Used to compute score for suspect.
 * Lower boundry of packets per flow.
 * BEWARE: This is reversed interval so anything that is NOT in the interval counts.
 */
#define SUSPECT_REVERSE_LOW_PPF_TRESHOLD 10

/**
 * Used to compute score for suspect.
 * Upper boundry of packets per flow.
 * BEWARE: This is reversed interval so anything that is NOT in the interval counts.
 */
#define SUSPECT_REVERSE_HIGH_PPF_TRESHOLD 20

/**
 * Used to compute score for suspect.
 * Lower boundry of packets per minute.
 */
#define SUSPECT_LOW_PPM_TRESHOLD 8

/**
 * Used to compute score for suspect.
 * Upper boundry of packets per minute.
 */
#define SUSPECT_HIGH_PPM_TRESHOLD 30

/**
 * Used to compute score for suspect.
 * Percent of flows for which is source port number larger than destination port number.
 */
#define SUSPECT_REQ_FLOWS_TRESHOLD 0.9

/**
 * Used to compute score for suspect.
 * Minimum active timeout of the suspect.
 */
#define SUSPECT_MIN_ACTIVE_TIME 300

/*
 * Used to compute score for suspect.
 * Value to add to the score if a given condition is met.
 */
#define SUSPECT_SCORE_ACKPUSH_FLOW_RATIO 2
#define SUSPECT_SCORE_BPP 2
#define SUSPECT_SCORE_PPF 1
#define SUSPECT_SCORE_PPM 2
#define SUSPECT_SCORE_REQ_FLOWS 3
#define SUSPECT_SCORE_ACTIVE_TIME 3

/**
 * Used when not using active test.
 */
#define STRATUM_NOT_USED ((int) (0xdeadbeaf))

/**
 * Used to identify permanent records in blacklist/whitelist DB.
 */
#define BWL_PERMANENT_RECORD 0


/**
 * After what time whitelisted item will expire in seconds.
 */
#define WL_ITEM_EXPIRE_TIME (3600*24)

/**
 * After what time blacklisted item will expire in seconds.
 */
#define BL_ITEM_EXPIRE_TIME (3600*24)

/**
 * Duration to sleep after iteration in list expire thread.
 */
#define BWL_LIST_EXPIRE_SLEEP_DURATION 3600




/**
 * \brief Key structure to suspect database.
 */
typedef struct {
    ip_addr_t suspect_ip;
    ip_addr_t pool_ip;
    uint16_t port;
} suspect_item_key_t;


/**
 * \brief Structure containing information about suspect.
 */
typedef struct suspect_item {
    bool flagged;
    uint8_t pool_id;
    uint64_t ack_flows;
    uint64_t ackpush_flows;
    uint64_t syn_flows;
    uint64_t rst_flows;
    uint64_t fin_flows;
    uint64_t other_flows;
    uint64_t req_flows;
    uint64_t packets;
    uint64_t bytes;
    uint32_t first_seen;
    uint32_t last_seen;
    uint32_t last_exported;
} suspect_item_t;


/**
 * \brief Key to whitelist/blacklist table.
 */
typedef struct {
    ip_addr_t ip;
    uint16_t port;
} list_key_t;


/**
 * Structure containing information used for configurating.
 */
typedef struct __attribute__ ((__packed__)) {
    char blacklist_file[256];
    char whitelist_file[256];
    char store_blacklist_file[256];
    char store_whitelist_file[256];

    uint32_t conn_timeout;
    uint32_t read_timeout;    
    uint32_t timeout_active;
    uint32_t timeout_inactive;
    uint32_t check_period;
    char stratum_check[8];
    uint32_t score_treshold;

    uint32_t suspect_db_size;
    uint32_t suspect_db_stash_size;
    uint32_t blacklist_db_size;
    uint32_t blacklist_db_stash_size;
    uint32_t whitelist_db_size;
    uint32_t whitelist_db_stash_size;
} config_struct_t;



bool miner_detector_initialization(config_struct_t*);
void miner_detector_process_data(ur_template_t *, const void *);


#endif
