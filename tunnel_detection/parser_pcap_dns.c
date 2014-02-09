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



int read_string(FILE * file, char * string ){
	unsigned int size=0;
	int sign;
	sign = fgetc(file);	
	while(sign != ';' && sign != -1){
		string[size++] = sign;
		sign = fgetc(file);	
	}
	string[size]=0;
	ungetc(sign, file);	
	return size;	
}

uint64_t read_ip_address_v6(FILE * file){
	uint64_t ip=0;
	char sign;
	int size;
	sign = fgetc(file);

	while(sign != ';'){
		sign = fgetc(file);	
	}
	ungetc(sign, file);	
	return ip;
}

void read_rest_of_line(FILE * file){
	int sign;
	int size;
	sign = fgetc(file);
	while(sign != '\n' && sign != -1){
		sign = fgetc(file);	
	}
}

int read_packet(FILE *file, packet_t * create){
	int sign;


	
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
		create->src_ip = read_ip_address_v4(file);
		sign = fgetc(file);
		create->dst_ip = read_ip_address_v4(file);
		sign = fgetc(file);
	}
	//read ip address v6
	sign = fgetc(file);
	if(sign != ';'){
		ungetc(sign,file);
		read_ip_address_v6(file);
		sign = fgetc(file);
		read_ip_address_v6(file);
		sign = fgetc(file);
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
		//create->request_string = (char *) malloc(sizeof(char) * MAX_SIZE_OF_REQUEST_DOMAIN); 
		create->request_length = read_string(file, create->request_string);
		sign = fgetc(file);
	}
	

	//read rest of line
	read_rest_of_line(file);

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
