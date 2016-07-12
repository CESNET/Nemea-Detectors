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

#define STRATUM_RECV_TIMEOUT 5

suspect_item_key_t create_suspect_key(ip_addr_t& suspect, ip_addr_t& pool, uint16_t port);
bool check_for_stratum_protocol(std::string ip, uint16_t port);

#endif
