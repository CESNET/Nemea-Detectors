/*!
 * \file parser_pcap_dns.c
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
#include "parser_pcap_dns.h"

uint32_t read_ip_address_v4(FILE * file){
	int ip=0;
	char a[4];
	char sign;
	char num = 0;
	for (int i = 0; i < 4; i++){
		ip <<= 8;
		sign = fgetc(file);
		num=0;
		
		while(sign >= '0' && sign <= '9'){
			a[num++] = sign;
			sign = fgetc(file);	
		}
		a[num]=0;
		//printf("%s.",a);
		ip |= atoi(a);
	}
	ungetc(sign, file);	
	return ip;
}

int read_int(FILE * file){
	char number[11];
	unsigned char size=0;
	int sign;
	sign = fgetc(file);	
	while(sign >= '0' && sign <= '9'){
		number[size++]=sign;
		sign = fgetc(file);	
	}
	number[size]=0;
	ungetc(sign, file);	
	return atoi(number);	
}


double read_double(FILE * file){
	char number[20];
	unsigned char size=0;
	int sign;
	sign = fgetc(file);	
	while((sign >= '0' && sign <= '9') || sign == '.'){
		number[size++]=sign;
		sign = fgetc(file);	
	}
	number[size]=0;
	ungetc(sign, file);	
	return atof(number);	
}



int read_string(FILE * file, char * string, int maxsize){
	unsigned int size=0;
	int sign;
	sign = fgetc(file);	
	while(sign != ';' && sign != '\n' && sign != -1 && size < maxsize - 1){
		string[size++] = sign;
		sign = fgetc(file);	
	}
	string[size]=0;
	ungetc(sign, file);	
	return size;	
}

void read_ip_address_v6(FILE * file, uint64_t * ip){
	char sign;
	unsigned char size = 0;
	char str[40];
	sign = fgetc(file);
	if(sign != ';' && sign != ',' && sign != '\n' && sign != -1 ){
		ip_addr_t addr;
		while(sign != ';' && sign != ',' && sign != '\n' && sign != -1 && size < 39){
			str[size++] = sign;
			sign = fgetc(file);
		}
		str[size]=0;
		if(ip_from_str(str, &addr) == 1){
			memcpy(&ip[0], &addr, 16);
		}
		ungetc(sign, file);	
	}
}

void read_rest_of_line(FILE * file){
	int sign;
	int size;
	sign = fgetc(file);
	while(sign != '\n' && sign != -1){
		sign = fgetc(file);	
	}
}

void read_item(FILE * file){
	int sign;
	int size;
	sign = fgetc(file);
	while(sign != ';' && sign != '\n' && sign != -1){
		sign = fgetc(file);	
	}
}

int read_packet(FILE *file, packet_t * create){
	int sign;
	create->request_length=0;
	create->request_string[0] = 0;
	create->txt_response[0] = 0;
	create->cname_response[0] = 0;
	create->mx_response[0] = 0;
	create->ns_response[0] = 0;

	
	if(file==NULL)
		return -1;

	//test if it is not on the end of file
	sign = fgetc(file);
	if(sign==-1)
		return -1;
	ungetc(sign,file);

   //create = (packet_t *) calloc(sizeof(packet_t),1); 

	//read time
	/*char time[32];
	fgets ( time, sizeof(time), file );
	sign = fgetc(file);*/
	//ungetc(sign,file);
	create->time = read_double(file);
	sign = fgetc(file);


	//read ip address v4
	sign = fgetc(file);
	if(sign != ';'){
		ungetc(sign,file);
		
		create->src_ip_v4 = read_ip_address_v4(file);
		sign = fgetc(file);
		create->dst_ip_v4 = read_ip_address_v4(file);
		sign = fgetc(file);
		create->ip_version = IP_VERSION_4;
	}
	//read ip address v6
	sign = fgetc(file);
	if(sign != ';'){
		ungetc(sign,file);
		read_ip_address_v6(file, create->src_ip_v6);
		sign = fgetc(file);
		read_ip_address_v6(file, create->dst_ip_v6);
		sign = fgetc(file);
		create->ip_version = IP_VERSION_6;
	}

	//read type (response/request)
	sign = fgetc(file);
	if(sign != ';'){
		ungetc(sign,file);
		create->is_response = read_int(file);
		sign = fgetc(file);
	}

	//read size
	sign = fgetc(file);
	if(sign != ';'){
		ungetc(sign,file);
		create->size = read_int(file);
		sign = fgetc(file);
	}

	//read request string 
	sign = fgetc(file);
	if(sign != ';'){
		ungetc(sign,file);
		create->request_length = read_string(file, create->request_string, MAX_SIZE_OF_REQUEST_DOMAIN);
		sign = fgetc(file);
	}

if(create->is_response){
		//read response ip 
		sign = fgetc(file);
		/*while(sign != ';'){
			if(sign != ','){
				ungetc(sign,file);
			}
			read_ip_address_v4(file);
			sign = fgetc(file);
		}*/
		read_item(file);

		//read txt string 
		sign = fgetc(file);
		if(sign != ';'){
			ungetc(sign,file);
			read_string(file, create->txt_response, MAX_SIZE_OF_RESPONSE_STRING);
			sign = fgetc(file);
		}
		//printf("%s\n",create->txt_response );

		//read cname string 
		sign = fgetc(file);
		if(sign != ';'){
			ungetc(sign,file);
			read_string(file, create->cname_response, MAX_SIZE_OF_RESPONSE_STRING);
			sign = fgetc(file);
		}	
		//printf("%s\n",create->cname_response );


		//read mx string
		sign = fgetc(file);
		if(sign != ';'){
			ungetc(sign,file);
			read_string(file, create->mx_response, MAX_SIZE_OF_RESPONSE_STRING);
			sign = fgetc(file);
		}
		//printf("%s\n",create->mx_response );

		//read ns string
		sign = fgetc(file);
		if(sign != ';' && sign != '\n' && sign != -1){
			ungetc(sign,file);
			read_string(file, create->ns_response, MAX_SIZE_OF_RESPONSE_STRING);
			sign = fgetc(file);
		}
		//printf("%s\n",create->ns_response );
		
		read_rest_of_line(file);
	}
	else{
		//read rest of line
		read_rest_of_line(file);
	}
	return 0;
}

FILE * parser_inicialize(char *name){
   	FILE *file = fopen ( name, "r" );
   	return file;
}


void parser_end(FILE *file){
	fclose(file);
}
/*
int main(int argc, char **argv){
	static const char filename[] = "cap10.txt";
	packet_t * packet;
   	FILE *file = fopen ( filename, "r" );
   	if ( file != NULL )
   	{
   		packet = read_packet(file);
   	}
}
*/
