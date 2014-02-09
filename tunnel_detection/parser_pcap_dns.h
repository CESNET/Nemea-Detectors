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


#define MAX_SIZE_OF_REQUEST_DOMAIN 255
/*!
 * \brief Structure containing packet DNS
 * Structure used to keep information about DNS packet.
 */
 typedef struct packet_t packet_t ;
 struct packet_t {
 	double time;
	uint32_t src_ip;
	uint32_t dst_ip;
	unsigned int size;
	char is_response;
	char  request_string[MAX_SIZE_OF_REQUEST_DOMAIN];
	int request_length;
} ;



uint32_t read_ip_address_v4(FILE * file);

int read_int(FILE * file);

double read_double(FILE * file);

int read_string(FILE * file, char * string );

uint64_t read_ip_address_v6(FILE * file);

void read_rest_of_line(FILE * file);

int read_packet(FILE *file, packet_t * create);

FILE * parser_inicialize(char *name);


void parser_end(FILE *file);
;

 #endif /* _PARSER_PCAP_DNS_ */