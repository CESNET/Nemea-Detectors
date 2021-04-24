/**
 * \file dga_detector.c
 * \brief DGA detector NEMEA module.
 * \author Jiri Setinsky <xsetin00@stud.fit.vutbr.cz>
 * \date 2020
 */
/*
 * Copyright (C) 2013,2014,2015,2016,2017,2018,2019 CESNET
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

//#define TESTING 1
#define DATASET "diff.csv"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <ctype.h>
#include <time.h>

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 DNS_RR_TTL,
   uint32 PACKETS,
	uint16 DNS_CNT_ANSWERS,
   uint16 DNS_CNT_AUTHS,
   uint16 DNS_CNT_QUESTIONS,
   uint16 DNS_FLAGS,
   uint16 DNS_ID,
   uint16 DNS_Q_CLASS,	
   uint16 DNS_Q_TYPE,	
   uint16 DNS_RR_CLASS,	
   uint16 DNS_RR_RLENGTH,	
   uint16 DNS_RR_TYPE,	
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,	
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TOS,
   uint8 TTL,
   string DNS_Q_NAME,
   string DNS_RR_NAME,
   bytes DNS_RR_RDATA,   
   uint32 BAR,
   string DNS_NAME

  
   
)
    
trap_module_info_t *module_info = NULL;


/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("DGA Detector", \
        "This module serves as detector of DGA domain names.", 1, 1)
  
/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) 
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


//--------------------------------HASH TABLE-------------------------------------------------------------

#define SIZE_NGRAM 1874958 
#define SIZE_DIC 528720
#define SIZE_SUFFIX 9077
#define SIZE_DGA 7522604

typedef struct my_string string_item;
struct my_string 
{
   char *data;   
   string_item *next;
};

string_item* ngram_table[SIZE_NGRAM]; 
string_item* dic_table[SIZE_DIC]; 
string_item* suffix_table[SIZE_SUFFIX];
string_item* dga_table[SIZE_DGA]; 

void table_init(string_item** hashArray,uint32_t SIZE);
unsigned long hash(char *str,uint32_t SIZE);
unsigned long hash(char *str,uint32_t SIZE);
struct my_string *search(char *key,string_item** hashArray, uint32_t SIZE);
void insert(char *data,string_item** hashArray, uint32_t SIZE);
void display(string_item** hashArray,uint32_t SIZE);
void clear_table(string_item** hashArray,uint32_t SIZE);

//-------------------------------END OF HASH TABLE-------------------------------------------------------

//-------------------------------FEATURES COMPUTATIONS---------------------------------------------------
/**
 * Function to predict DGA adress based on its features
 */
int predict(float features[]);

/**
 * Enumeration of features
 */
enum features{dictionary,alexa_ratio,alexa_ratio3,alexa_ratio4,alexa_ratio5,entrop,numeric,cons,length,valid_suffix, domain_level, www, dga_ratio,dga_ratio3,dga_ratio4,dga_ratio5,diff, metric_entrop, spec_char};

void isconsonant(int* counter,char *str);
char *lowercase(char *str);
int makehist(char *S,int *hist,int len);
void compute_ngrams(char *str, float features[], int n);
double entropy(int *hist,int histlen,int len);
float dict_match(char *domain,int n);
void print_csv(uint32_t flag,FILE* file,float alexa,float alexa3,float alexa4,float alexa5, float dic, float num, double entropy, float cons, int len, char* s, int suffix, int suffix_num, int www, float dga,float dga3,float dga4,float dga5, float diff, float metric_ent, float spec);
void compute_features(char* domain,float features[]);
void normalize(char* domain, float features[], int len);
void init_data();

//-------------------------------END OF FEATURES COMPUTATIONS--------------------------------------------


/**
 * Main function 
 */
int main(int argc, char **argv)
{
   int ret;
   signed char opt; 
   /* **** TRAP initialization **** */

   /*
    * Macro allocates and initializes module_info structure according to MODULE_BASIC_INFO and MODULE_PARAMS
    * definitions on the lines 71 and 84 of this file. It also creates a string with short_opt letters for getopt
    * function called "module_getopt_string" and long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   /*
    * Let TRAP library parse program arguments, extract its parameters and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);

   /*
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   /*
    * Parse program arguments defined by MODULE_PARAMS macro with getopt() function (getopt_long() if available)
    * This macro is defined in config.h file generated by configure script
    */
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) 
      {
         default:
            fprintf(stderr, "Invalid arguments.\n");
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
            TRAP_DEFAULT_FINALIZATION();
            return -1;
      }
   }

   #ifndef TESTING

      #define INDATA "BYTES,LINK_BIT_FIELD,TIME_FIRST,TIME_LAST,DNS_RR_TTL,PACKETS,DNS_CNT_ANSWERS,DNS_CNT_AUTHS,"\
                     "DNS_CNT_QUESTIONS,DNS_FLAGS,DNS_ID,DNS_Q_CLASS,DNS_Q_TYPE,DNS_RR_CLASS,DNS_RR_RLENGTH,DNS_RR_TYPE,DST_PORT,"\
                     "SRC_PORT,DIR_BIT_FIELD,PROTOCOL,TCP_FLAGS,TOS,TTL,DNS_Q_NAME,DNS_RR_NAME,DNS_RR_RDATA"//,SRC_IP,DST_IP"
      
      #define OUTDATA "DNS_Q_NAME,TIME_FIRST"

   #else

      #define INDATA "DNS_NAME,BAR"
      #define OUTDATA "DNS_NAME"
  
   #endif
   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0, INDATA, NULL); //BAR,DNS_NAME
   if (in_tmplt == NULL)
   {
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }
   
   ur_template_t *out_tmplt = ur_create_output_template(0, OUTDATA, NULL);
   if (out_tmplt == NULL)
   {
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      return -1;
   }

   // Allocate memory for output record
   void *out_rec = ur_create_record(out_tmplt, UR_MAX_SIZE);
   if (out_rec == NULL)
   {
      ur_free_template(in_tmplt);
      ur_free_template(out_tmplt);
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      return -1;
   }
   
  
   /* ***** DATA inicialization ****** */
   init_data();
   
   // for training purposes
   #ifdef TESTING
      // CSV output
      
      FILE *dataset=fopen(DATASET,"w");
      if (dataset == NULL)
      {
         printf("Cannot open file \n");
         fclose(dataset);
         exit(0);
      }
      
      fputs("domain,class,dictionary,alexa,alexa3,alexa4,alexa5,entropy,num,cons,len,suffix,suffix_num,www,dga,dga3,dga4,dga5,diff,metric_entropy,spec_char\n",dataset);
      // Variables for confussion matrix
      int fals=0;
      int celk=0;
      int truepos=0;
      int trueneg=0;
      int falseneg=0;
      float average_length=0;
      float average_entropy=0;
      float average_alexa=0;
      float average_dictionary=0;
      float average_cons=0;
      float average_nums=0;
      float average_dga=0;
      float variance_length=0;
      float variance_entropy=0;
      float variance_alexa=0;
      float variance_dictionary=0;
      float variance_cons=0;
      float variance_nums=0;
      float variance_dga=0;
     
   #endif

   /* **** Main processing loop **** */
   // Read data from input, process them and write to output
   while (!stop) 
   {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);

      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) 
      {
         if (in_rec_size <= 1) 
         {
            break; // End of data (used for testing purposes)
         } else 
         {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }
      
      // PROCESS THE DATA
      
      // for training purposes
      #ifdef TESTING
         celk++;
         int flag=ur_get(in_tmplt, in_rec, F_BAR);
         int size=ur_get_var_len(in_tmplt, in_rec, F_DNS_NAME);
         char *s=calloc(1,size+1);
         strncpy(s,ur_get_ptr(in_tmplt, in_rec, F_DNS_NAME),size);
      #else
         int size=ur_get_var_len(in_tmplt, in_rec, F_DNS_Q_NAME);
         char *s=calloc(1,size+1);
         strncpy(s,ur_get_ptr(in_tmplt, in_rec, F_DNS_Q_NAME),size);
         uint16_t dns_flags= ur_get(in_tmplt, in_rec, F_DNS_FLAGS);
         uint16_t nx_flag= dns_flags&15;
         uint16_t aa_flag= (dns_flags&1024)>>10;
         uint16_t qr_flag= (dns_flags&32768)>>15;
      #endif
      

      // classify only NX domains
      #ifndef TESTING
         if (nx_flag==3 && aa_flag == 1 && qr_flag==1)
         {  
      #endif
         float features[19]={0};
         
         int len=strlen(s);
         if(len!=0)
         {
            s=lowercase(s);

            // normalize and get feature vector
            normalize(s, features,len);

            // for training purposes
            #ifdef TESTING
               print_csv(flag,dataset,features[alexa_ratio],features[alexa_ratio3],features[alexa_ratio4],features[alexa_ratio5],features[dictionary],features[numeric],features[entrop],features[cons],features[length],s, features[valid_suffix], features[domain_level], features[www], features[dga_ratio], features[dga_ratio3],features[dga_ratio4],features[dga_ratio5], features[diff], features[metric_entrop], features[spec_char]);
            #endif

            int dga_pos=0;

            // classification of the domain
            dga_pos=predict(features);
            
            // for training purposes
            #ifdef TESTING
               if (dga_pos == 1 && flag == 1)   
                  truepos++;
               if (dga_pos == 0 && flag == 0)
                  trueneg++;
               if (dga_pos == 0 && flag == 1)  
                  falseneg++;
               if (dga_pos == 1 && flag == 0)  
                  fals++;
               average_entropy+=features[entrop];
               average_length+=features[length];
               average_alexa+=features[alexa_ratio];
               average_dictionary+=features[dictionary];
               average_cons+=features[cons];
               average_nums+=features[numeric];
               variance_entropy+=features[entrop]*features[entrop];
               variance_length+=features[length]*features[length];
               variance_alexa+=features[alexa_ratio]*features[alexa_ratio];
               variance_dictionary+=features[dictionary]*features[dictionary];
               variance_cons+=features[cons]*features[cons];
               variance_nums+=features[numeric]*features[numeric]; 
            #endif
            
               
            
            // DGA domain founded
            if (dga_pos==1)
            {
               
               // Fill output record
               #ifdef TESTING
                  // for training purposes
                  ur_set_string(out_tmplt, out_rec, F_DNS_NAME,s);
               #else
                  // domain
                  ur_set_string(out_tmplt, out_rec, F_DNS_Q_NAME,s);
                  
                  
                  //ur_set(out_tmplt, out_rec, F_TIME_LAST, ur_get(in_tmplt, in_rec, F_TIME_LAST));
               
                  //ur_set(out_tmplt, out_rec, F_SRC_IP,ur_get(in_tmplt, in_rec, F_SRC_IP));
                  //ur_set(out_tmplt, out_rec, F_DST_IP,ur_get(in_tmplt, in_rec, F_DST_IP));
                  // time captured
                  ur_set(out_tmplt, out_rec, F_TIME_FIRST,ur_get(in_tmplt, in_rec, F_TIME_FIRST));
               #endif
               // Send record to interface 0.
               // Block if ifc is not ready (unless a timeout is set using trap_ifcctl)
               ret = trap_send(0, out_rec, ur_rec_size(out_tmplt,out_rec));
                                  
            }
         }
         free(s); 
      // for training purposes
      #ifndef TESTING
         }
      #endif
      
      // Handle possible errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
      
   }
   
   // for training purposes
   #ifdef TESTING
      
      average_length/=celk;
      average_entropy/=celk;
      average_alexa/=celk;
      average_dictionary/=celk;
      average_cons/=celk;
      average_nums/=celk;
      variance_length/=celk;
      variance_entropy/=celk;
      variance_alexa/=celk;
      variance_dictionary/=celk;
      variance_cons/=celk;
      variance_nums/=celk;
      variance_dga/=celk;
      variance_length-=average_length*average_length;
      variance_entropy-=average_entropy*average_entropy;
      variance_alexa-=average_alexa*average_alexa;
      variance_dictionary-=average_dictionary*average_dictionary;
      variance_cons-=average_cons*average_cons;
      variance_nums-=average_nums*average_nums;
      double time_spent =0;// (double)(end - begin) / CLOCKS_PER_SEC;
      printf("{\"celk\":\"%d\",\
               \"true_pos\":\"%d\",\
               \"false_pos\":\"%d\",\
               \"false_neg\":\"%d\",\
               \"true_neg\":\"%d\",\
               \"length\":\"%f\",\
               \"entropy\":\"%f\",\
               \"alexa\":\"%f\",\
               \"dictionary\":\"%f\",\
               \"nums\":\"%f\",\
               \"cons\":\"%f\",\
               \"var_length\":\"%f\",\
               \"var_entropy\":\"%f\",\
               \"var_alexa\":\"%f\",\
               \"var_dictionary\":\"%f\",\
               \"var_cons\":\"%f\",\
               \"var_nums\":\"%f\",\
               \"time\":\"%f\",\
               \"acc\":\"%f\"}\n",celk,truepos,fals,falseneg,trueneg,average_length,average_entropy, average_alexa, average_dictionary, average_nums, average_cons,variance_length,variance_entropy,variance_alexa,variance_dictionary,variance_cons,variance_nums,time_spent,((trueneg+truepos)/(float)celk)*100);
      // close train dataset
      fclose(dataset);
   #endif
   
   /* **** Cleanup **** */
      
   // clear hash tables
   clear_table(ngram_table,SIZE_NGRAM);
   clear_table(dic_table,SIZE_DIC);
   clear_table(suffix_table,SIZE_SUFFIX);
   clear_table(dga_table,SIZE_DGA);
   // Do all necessary cleanup in libtrap before exiting
   TRAP_DEFAULT_FINALIZATION();
   // Release allocated memory for module_info structure
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Free unirec templates and output record
   ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_finalize();   
   
   return 0;
}

//--------------------------------------------FUNCTIONS DEFINITIONS------------------------------------------------------------

//---------------------------------------------------HASH FUNCTIONS------------------------------------------------------------
/**
 * Function to init hash table to NULL
 */
void table_init(string_item** hashArray,uint32_t SIZE)
{
   for (size_t i = 0; i < SIZE; i++)
   {
      hashArray[i]=NULL;   
   }
   
}

/**
 * Function to compute hash of the string
 */
unsigned long hash(char *str,uint32_t SIZE)
{
   unsigned long hash = 5381;
   int c;

   while ((c = *str++))
      hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

   return hash%SIZE;
}

/**
 * Function to search a string in the hash table
 */
struct my_string *search(char *key,string_item** hashArray, uint32_t SIZE) 
{
   //get the hash 
   unsigned long hashIndex = hash(key,SIZE);  
	
   //move in array until an empty 
   string_item *tmp=hashArray[hashIndex];
   while(tmp != NULL) {
	
      if(!strcmp(tmp->data,key))
      {
         return tmp; 
      }
         
			
      //go to next cell
      tmp=tmp->next;
		
   }        
	
   return NULL;        
}

/**
 * Function to insert a string to hash table
 */
void insert(char *data,string_item** hashArray, uint32_t SIZE) 
{

   string_item *item = search(data,hashArray,SIZE);
  
   if(item==NULL)
   {
     
      //get the hash 
      unsigned long hashIndex = hash(data,SIZE);
      item=(string_item*) calloc(sizeof(struct my_string),1);
      item->data=(char*)calloc(strlen(data)+1,1);

      if(item && item->data)
      {
         item->next = hashArray[hashIndex];
         strcpy(item->data,data);  
         hashArray[hashIndex]=item;          
      }
       
   }
}

/**
 * Function to display a content of the hash table
 */
void display(string_item** hashArray,uint32_t SIZE) 
{
   
   for (size_t i = 0; i < SIZE; i++)
   {
      string_item* tmp=hashArray[i];
      printf("%ld-------------",i);
      while(tmp!=NULL)
      {
         printf("%s------------",tmp->data);
         tmp=tmp->next;
      }
      printf("------------\n");
   }
   
	printf("-----------end---------\n");
}

/**
 * Function to free the hash table
 */
void clear_table(string_item** hashArray,uint32_t SIZE)
{
    for (int i = 0; i < SIZE; i++)
    {
        string_item *tmp = hashArray[i];
        string_item *prev_item = NULL;

        while (tmp != NULL)
        {
            prev_item = tmp;
            tmp = tmp->next;
            free(prev_item->data);
            free(prev_item);
        }

        hashArray[i] = NULL;
    }
}
//---------------------------------------------------END OF HASH------------------------------------------------------------

//-------------------------------------------------FEATURES COMPUTATIONS----------------------------------------------------

/**
 * Function to find type of characters (consonant, digit, nonalfanumeric)
 */
void isconsonant(int* counter,char *str)
{
   for(int i = 0; str[i]; i++)
   {
      if (!isdigit(str[i]))
      {    
         if(str[i]!='a' && str[i]!='e' && str[i]!='i' && str[i]!='o' && str[i]!='u')
         {
            if(str[i] >= 97 && str[i] <= 122 )
               counter[0]++;
            else
               counter[2]++;
         }
      }else
      {
         counter[1]++;
      }
      
   }
   return;
}

/**
 * Function to convert a string to lowercase
 */
char *lowercase(char *str)
{
    for(int i = 0; str[i]; i++)
    {
      str[i] = tolower(str[i]);
    }
    return str;
}    

/**
 * Function to compute frequency of characters
 */
int makehist(char *S,int *hist,int len)
{
	int wherechar[256];
	int i,histlen;
	histlen=0;
	for(i=0;i<256;i++)wherechar[i]=-1;
	for(i=0;i<len;i++){
		if(wherechar[(int)S[i]]==-1)
      {
			wherechar[(int)S[i]]=histlen;
			histlen++;
		}
		hist[wherechar[(int)S[i]]]++;
	}
	return histlen;
}

/**
 * Function to compute an amount of valid and DGA n-grams
 */
void compute_ngrams(char *str, float features[], int n)
{
   char *ngram;
   int sum=0;
   int valid_cnt=0;
   int dga_cnt=0;
   ngram=calloc(n+1,sizeof(char));
   if((int)features[length]<n)
   {
      free(ngram);
      return;
   }
      
   int p=0;
   // get n-grams
   for(int i=0;i<(int)features[length];i++)
   {
      if (((int)features[length]-i) == (n-1))
      {
         break;
      }
      for(int k=i;k<(i+n);k++)
      {
         ngram[p]=str[k];
         p++;
      }
      ngram[p]='\0';
      sum++;
      // search in hash tables
      if(search(ngram,ngram_table,SIZE_NGRAM)!=NULL)
         valid_cnt++;
      if(search(ngram,dga_table,SIZE_DGA)!=NULL)
         dga_cnt++;
      p=0;
   }
   // n-gram length
   if (n == 3)
   {
      features[alexa_ratio3]=(float)valid_cnt/sum;
      features[dga_ratio3]=(float)dga_cnt/sum;
   }
   else if (n == 4)
   {
      features[alexa_ratio4]=(float)valid_cnt/sum;
      features[dga_ratio4]=(float)dga_cnt/sum;
   }
   else if (n == 5)
   {
      features[alexa_ratio5]=(float)valid_cnt/sum;
      features[dga_ratio5]=(float)dga_cnt/sum;
   }
   free(ngram);
}

/**
 * Function to compute an entropy of the string
 */
double entropy(int *hist,int histlen,int len)
{
	int i;
	double H;
	H=0;
	for(i=0;i<histlen;i++)
   {
		H-=(double)hist[i]/len*log((double)hist[i]/len)/log(2);
	}
	return H;
}

/**
 * Function to find english words in the string
 */
float dict_match(char *domain,int n)
{
   float cnt=0;
   //printf("%s ---- %d\n",domain,n);
      
   int start=0;

   int found=0;
   char sub[n];
   
   for (int end=n-1; end>=(start+3); end--)
   {  
      
      memset(sub,0,n);
      memcpy(sub,&domain[start],end-start);
      int sub_len=strlen(sub);
      //printf("%s\n",sub);
      if(search(sub,dic_table,SIZE_DIC)!=NULL)
      {
         
        
         //printf("----------found %s \n",sub);
         start+=sub_len;
         cnt+=sub_len;
         end=n+1;
         found=1;
         //printf("end----%d  start-------%d\n",end,start);
         
         
      }

      
      if(sub_len==3 && found == 0)
      {

         start++;
         end=n+1;
      }
      found=0;
      
        
   }

   return cnt/n;
   
}

/**
 * Function to print the feature vector to the file
 */
void print_csv(uint32_t flag,FILE* file,float alexa,float alexa3,float alexa4,float alexa5, float dic, float num, double entropy, float cons, int len, char* s, int suffix, int suffix_num, int www, float dga,float dga3,float dga4,float dga5, float diff, float metric_ent, float spec)
{
   
   if(flag==1)
   {                                                     
      fprintf(file,"%s,dga,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f\n",s,dic,alexa,alexa3,alexa4,alexa5,entropy,num,cons,len, suffix, suffix_num, www, dga,dga3,dga4,dga5, diff, metric_ent, spec);
   }else
   {
      fprintf(file,"%s,legit,%f,%f,%f,%f,%f,%f,%f,%f,%d,%d,%d,%d,%f,%f,%f,%f,%f,%f,%f\n",s,dic,alexa,alexa3,alexa4,alexa5,entropy,num,cons,len, suffix, suffix_num, www, dga,dga3,dga4,dga5, diff, metric_ent, spec);
   }
   
   
   return;
}

/**
 * Function to compute individual features of the domain name
 */
void compute_features(char* domain,float features[])
{
      int *hist,histlen; 
      features[length]=strlen(domain);  
      
      //printf("extrahování validních subdomén: %s\n", domain);
      hist=(int*)calloc(features[length],sizeof(int));
      histlen=makehist(domain,hist,features[length]);
      features[entrop]=entropy(hist,histlen,features[length]);
      features[metric_entrop]=features[entrop]/features[length];
      //printf("%lf\n",H);
      free(hist);

      int c[3]={0,0,0};
      isconsonant(c,domain);
      features[cons]=((float)c[0])/features[length];
      features[numeric]=((float)c[1])/features[length];
      features[spec_char]=((float)c[2])/features[length];
         
      features[dictionary]=dict_match(domain,features[length]);
      
      compute_ngrams(domain,features,3);
     
      compute_ngrams(domain,features,4);
    
      compute_ngrams(domain,features,5);

      
      if(features[length] >= 5)
      { 
         features[alexa_ratio]=(features[alexa_ratio3]+features[alexa_ratio4]+features[alexa_ratio5])/3;
         features[dga_ratio]=(features[dga_ratio3]+features[dga_ratio4]+features[dga_ratio5])/3;
         features[diff]=features[dga_ratio]-features[alexa_ratio]+1;

      }else
      {
         //printf("juhu %s\n", domain);
         features[alexa_ratio]=0;
         features[dga_ratio]=0;
         features[diff]=0;
      }    
      
}

/**
 * Function to normalize a domain name (removes dots and TLD)
 */
void normalize(char* domain, float features[], int len)
{
   int domain_cnt=0;
   int suffix=0;
   int has_www=0;
   char copy[len+1];
   strcpy(copy,domain);
   char* token=strtok(copy,".");
   //printf("%s\n",token);
   char *final=(char*)calloc(len+10,1);
   //char *first=(char*)calloc(strlen(token)+1,1);
   //strcpy(first,token);
   //char start_by_www=0;
   //char first_suffix=1;
   //char **subdomains=calloc(sizeof(char*),15);
   
   char *backup=calloc(len+1,1);
 
   
   while (token!=NULL)
   {
      //subdomains[domain_cnt]=(char*)calloc(strlen(token)+1,1);
      //strcpy(subdomains[domain_cnt],token);
      /*
      int len=strlen(token);
      
      if(len >= 4 && token[0]=='x' && token[1] == 'n' && token[2] == '-' && token[3] == '-')
         xn=true;
      
      if (len >= 2 && token[0] == 'c' && token[1] == 'z')     
         cz=true;
      */
        
      if(!strcmp(token,"www"))
      {
         has_www=1;
      }
      
      domain_cnt++;
      
      if(search(token,suffix_table,SIZE_SUFFIX))
      {
            suffix++;       
      }
      
      //backup=realloc(backup,strlen(token)+1);
      //memset(backup,0,(int)features[length]+1);
      strcpy(backup,token);
      token=strtok(NULL,"."); 
      if(token!=NULL)
         strcat(final,backup);
     
   }
   
   if (strlen(final)==0)
      strcpy(final,backup);
   
   compute_features(final,features);
   
   //printf("%s\n", final);
   //subdomains=realloc(subdomains,domain_cnt*sizeof(char*));
   
   /*
   for(int i=0;i<domain_cnt;i++)
   {
      //printf("%s\n",subdomains[i]);
      free(subdomains[i]);
   }
   free(subdomains);
   */
   free(backup);
   free(final);
   domain_cnt--;
   features[valid_suffix]=suffix;
   features[www]=has_www;
   features[domain_level]=domain_cnt;

}

/**
 * Function to init external data from files to hash tables
 */
void init_data()
{
   char word[50];
   char* item;
      
   int dir_len=strlen(VAR);
   char *path=calloc(dir_len+25,sizeof(char));
   
   strcpy(path,VAR);
   strcpy(path+dir_len, "data/alexa.txt\0");

   // valid ngrams
   FILE* alexa=fopen(path,"r");
   if (alexa == NULL){
        printf("Cannot open file \n");
        fclose(alexa);
        exit(1);
   }
   
   table_init(ngram_table,SIZE_NGRAM);
 
   while(fgets(word,50,alexa))
   {
      
      item=strtok(word,"\n"); 
      insert(item,ngram_table,SIZE_NGRAM);
            
   }
   
   strcpy(path+dir_len, "data/words_alpha.txt\0");
   
   // english dictionary
   FILE *dic;
   dic=fopen(path,"r");
  
   
   if (dic == NULL)
   {
        printf("Cannot open file \n");
        fclose(dic);
        exit(1);
   }
   
   table_init(dic_table,SIZE_DIC);

   while(fgets(word,50,dic))
   {
      
      item=strtok(word,"\n");
      insert(item,dic_table,SIZE_DIC);
   
   }

   strcpy(path+dir_len, "data/suffix.txt\0");
   
   // public suffix
   FILE *suffix;
   suffix=fopen(path,"r");
  
   
   if (suffix == NULL)
   {
        printf("Cannot open file \n");
        fclose(suffix);
        exit(1);
   }
   
   table_init(suffix_table,SIZE_SUFFIX);

   while(fgets(word,50,suffix))
   {
      
      item=strtok(word,"\n");
      insert(item,suffix_table,SIZE_SUFFIX);
   
   }
   
   strcpy(path+dir_len, "data/dga_nodict.txt\0");
   
   // DGA ngrams
   FILE *dga;
   dga=fopen(path,"r");
  
   
   if (dga == NULL){
        printf("Cannot open file \n");
        fclose(dga);
        exit(1);
   }
   
   table_init(dga_table,SIZE_DGA);

   while(fgets(word,50,dga))
   {
      
      item=strtok(word,"\n");
      insert(item,dga_table,SIZE_DGA);
   
   }

   // close input files
   fclose(alexa);
   fclose(dic);
   fclose(dga);
   fclose(suffix);
   free(path);
   
}
//-------------------------------------------------END OF FEATURES COMPUTATIONS--------------------------------------------------