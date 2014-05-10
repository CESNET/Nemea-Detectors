/*!
 * \file parser_pcap_dns.h
 * \brief Parser for packets, it parses txt file from Tshark.
 * \author Zdenek Rosa <rosazden@fit.cvut.cz>
 * \date 2014
 */
/*
 * Copyright (C) 2014 CESNET
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
#ifndef _PARSER_PCAP_DNS_
#define _PARSER_PCAP_DNS_



#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "tunnel_detection_dns_structs.h"




/*!
 * \brief Read IPV4 from file
 * Function reads IPv4 from file, return it in number.
 * \param[in] file pointer to file.
 * \return IPv4 in 32b number
 */
uint32_t read_ip_address_v4(FILE * file);

/*!
 * \brief Read number from file
 * Function reads number from file, return it in number.
 * \param[in] file pointer to file.
 * \return int number
 */
int read_int(FILE * file);

/*!
 * \brief Read double from file
 * Function reads number from file, return it in number.
 * \param[in] file pointer to file.
 * \return double
 */
double read_double(FILE * file);

/*!
 * \brief Read string from file
 * Function reads string from file.
 * \param[in] file pointer to file.
 * \param[in] string pinter to memory were to save string.
 * \param[in] maxsize max length of string.
 * \return length of read string
 */
int read_string(FILE * file, char * string, int maxsize);

/*!
 * \brief Read IPV6 from file
 * Function reads IPv6 from file, save it like 2x64b number.
 * \param[in] file pointer to file.
 * \param[in] pointer to memory where to save IP. 
 */
void read_ip_address_v6(FILE * file, uint64_t * ip);

/*!
 * \brief Read rest of line
 * Function reads rest of line from file
 * \param[in] file pointer to file.
 */
void read_rest_of_line(FILE * file);

/*!
 * \brief Read packet from file
 * Function reads packet from file
 * \param[in] file pointer to file.
 * \param[in] create pointer to structure with results.
 * \return 0 on SUCCESS, -1 on end of the file
 */
int read_packet(FILE *file, packet_t * create);

/*!
 * \brief Init function of parser
 * Function inicialize parser (open file for reading)
 * \param[in] name name of file
 * \return pointer on file on SUCCESS, NULL on ERROR
 */
FILE * parser_initialize(char *name);

/*!
 * \brief Parser end
 * Function close file for reading packets
 * \param[in] file pointer to file.
 */
void parser_end(FILE *file);
;

 #endif /* _PARSER_PCAP_DNS_ */