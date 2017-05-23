/**
 * \file utils.h
 * \brief Nemea module for detecting bitcoin miners.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2016
 */


#include <stdint.h>
#include <unirec/unirec.h>
#include "miner_detector.h"

#include <string>

#ifndef _H_MINER_UTILS
#define _H_MINER_UTILS


enum stratum_timeout_types {
    STRATUM_CONN_TIMEOUT,
    STRATUM_READ_TIMEOUT
};

enum stratum_check_ret_codes {
    ERR_SOCKET_CREATE,
    ERR_SOCKET_FGET,
    ERR_SOCKET_FSET,
    ERR_CONNECT,
    ERR_SELECT,
    ERR_CONNECT_TIMEOUT,
    ERR_WRITE,
    ERR_READ,
    ERR_READ_TIMEOUT,
    ERR_MEMORY,
    ERR_REGEX,
    DATA_OK,
    STRATUM_MATCH,
    STRATUM_NO_MATCH
};

enum miner_pool_ids {
    STRATUM_MPOOL_BITCOIN,
    STRATUM_MPOOL_MONERO,
    STRATUM_MPOOL_ETHEREUM,
    STRATUM_MPOOL_ZCASH
};

suspect_item_key_t create_suspect_key(ip_addr_t& suspect, ip_addr_t& pool, uint16_t port);
int stratum_check_server(char *ip, uint16_t port, uint8_t *pool_id);
void stratum_set_timeout(int type, int timeout);
const char *stratum_error_string(int err);
const char *stratum_mpool_string(uint8_t id);
#endif
