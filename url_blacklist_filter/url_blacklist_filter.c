/**
 * \file url_blacklist_filter.c
 * \brief Module checking if URL from UniRec is on blacklist.
 * \author Michaela Novotna <xnovot2i@stud.fit.vutbr.cz>
 * \date 2023
 */
/*
 * Copyright (C) 2013,2014,2015,2016 CESNET
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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include "fields.h"

#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>  

#define MAX_STR_LEN 2048

char **malicious_urls;
char *malicious_urls_file = NULL;
int blacklist_size = 0;

/**
 * Definition of fields used in unirec templates (for both input and output interfaces)
 */
UR_FIELDS (
   ipaddr SRC_IP,
   ipaddr DST_IP,
   time TIME_FIRST,
   time TIME_LAST,
   uint64 BYTES,
   uint64 BYTES_REV, 
   uint32 PACKETS,
   uint32 PACKETS_REV,
   string HTTP_REQUEST_HOST,
   string HTTP_REQUEST_URL,
   uint32 HTTP_RESPONSE_STATUS_CODE,
)

trap_module_info_t *module_info = NULL;


/**
 * Definition of basic module information - module name, module description, number of input and output interfaces
 */
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("URL blacklist filter", \
        "This module receives flow records in UniRec and checks if HTTP URL is on blacklist. If found, the flow record it forwarded to output. The blacklist is loaded from a text file passed as parameter. The file should contain one URL per line.", 1, 1)
  //BASIC(char *, char *, int, int)


/**
 * Definition of module parameters - every parameter has short_opt, long_opt, description,
 * flag whether an argument is required or it is optional and argument type which is NULL
 * in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16, uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
  PARAM('f', "file", "File with the list of malicious URLs", required_argument, "string") \
  PARAM('p', "print", "Print checked URLs and results to stdout", no_argument, "none") \
  PARAM('r', "pid", "Path to file for saving pid of process", required_argument, "string") 
//PARAM(char, char *, char *, no_argument  or  required_argument, char *)
/**
 * To define positional parameter ("param" instead of "-m param" or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 */


static int stop = 0;
static int verbose_print = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)


void free_url_array(char **malicious_urls){
   // free memory allocated for the list of malicious URLs
   for (int i = 0; i < blacklist_size; i++) {
      if (malicious_urls[i] != NULL) {
         free(malicious_urls[i]);
      }
   }
   if (malicious_urls != NULL) {
      free(malicious_urls);
   }
}


char** load_malicious_urls(char **malicious_urls, char *file_name){
   if (verbose_print) {
      printf("Loading malicious URL from %s\n", file_name);
   }
   FILE *fp = fopen(file_name, "r");
   if (fp == NULL) {
      fprintf(stderr, "Error: File with malicious URLs could not be opened.\n");
      return NULL;
   }
   //load lines
   char line[200];
   int j = 0;
   malicious_urls = malloc(sizeof(char*));
   if (malicious_urls == NULL) {
      fprintf(stderr, "Error: Memory allocation problem (malicious URLs).\n");
      return NULL;
   }
   size_t len = 0;
   while (fgets(line, 200, fp) != NULL) {;
      // remove newline character
      line[strcspn(line, "\n")] = 0;
      // add line to array
      len = sizeof(char*) * (j+1);
      malicious_urls = realloc(malicious_urls, len);
      if (malicious_urls == NULL) {
         fprintf(stderr, "Error: Memory allocation problem (malicious URLs).\n");
         return NULL;
      }
      malicious_urls[j] = malloc(strlen(line) + 1);
      strcpy(malicious_urls[j], line);
      j++;
   }
   blacklist_size = j;
   fclose(fp);
   if (verbose_print) {
      printf("Loaded %d malicious URLs\n", j);
   }
   return malicious_urls;
}

void clean_pid_file(char *pid_file){
   // remove PID file
   if (pid_file != NULL) {
      remove(pid_file);
   }
}


bool ends_with_substring(char *str, char *substr){
   // check if str ends with substr
   size_t str_len = strlen(str);
   size_t substr_len = strlen(substr);
   if (str_len < substr_len) {
      return false;
   }
   int i = strncmp(str + str_len - substr_len, substr, substr_len);
   if (i == 0) {
      return true;
   } else {
      return false;
   }
}


bool is_malicious(char *url, char **malicious_urls){
   // check if url is malicious
   char *found;
   for (int i = 0; i < blacklist_size; i++) {
      if (ends_with_substring(malicious_urls[i], url)) {
         return true;
      }
   }
   return false;
}


void reload_blacklist(int signalNum) {
  if (signalNum == SIGUSR1) {
    // get current time and print info message
    time_t rawtime;
    struct tm *timeinfo;
    char buffer[100];
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, sizeof(buffer), "Caught SIGUSR1 signal - reloading blacklist (at %Y-%m-%d %H:%M:%S).", timeinfo);
    puts(buffer);
    // reload blacklist
    malicious_urls = load_malicious_urls(malicious_urls, malicious_urls_file);
  }
}


int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   char *pid_file = NULL;

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
      switch (opt) {
      case 'f':
         malicious_urls_file = optarg;
         break;
      case 'p':
         verbose_print = 1; // print URLs and other verbose information
         break;
      case 'r':
         pid_file = optarg;
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return -1;
      }
   }

   if (malicious_urls_file == NULL) {
      fprintf(stderr, "Error: Malicious URLs file not specified.\n");
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   // register signal handler
   signal(SIGUSR1, reload_blacklist);

   // save PID to file
   if (pid_file != NULL) {
      FILE *pid_f = fopen(pid_file, "w");
      if (pid_f == NULL) {
         fprintf(stderr, "Error: PID file could not be created.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return -1;
      }
      fprintf(pid_f, "%d", getpid());
      fclose(pid_f);
   }

   // load list of malicious URLs
   malicious_urls = load_malicious_urls(malicious_urls, malicious_urls_file);
   if (malicious_urls == NULL) {
      fprintf(stderr, "Error: Malicious URLs could not be loaded.\n");
      clean_pid_file(pid_file);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0, "HTTP_REQUEST_HOST, HTTP_REQUEST_URL", NULL);
   trap_set_required_fmt(0, TRAP_FMT_UNIREC, NULL);
   if (in_tmplt == NULL){
      fprintf(stderr, "Error: Input template could not be created.\n");
      clean_pid_file(pid_file);
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      TRAP_DEFAULT_FINALIZATION();
      return -1;
   }

   /* **** Main processing loop **** */
   if (verbose_print) {
      printf("Processing input data ...\n");
   }
   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;

      // Receive data from input interface 0.
      // Block if data are not available immediately (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      if (ret == TRAP_E_FORMAT_CHANGED) {
         // Get the data format of senders output interface (the data format of the output interface it is connected to)
         const char *spec = NULL;
         uint8_t data_fmt = TRAP_FMT_UNKNOWN;
         if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
            fprintf(stderr, "Data format was not loaded.");
            break;
         }
         // Set the same data format to the output interface
         trap_set_data_fmt(0, TRAP_FMT_UNIREC, spec);
      }

      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }

      // PROCESS THE DATA

      // Check if there is both HOST and PATH (URL) fields (needed to get full URL)
      uint16_t host_len = ur_get_var_len(in_tmplt, in_rec, F_HTTP_REQUEST_HOST);
      uint16_t path_len = ur_get_var_len(in_tmplt, in_rec, F_HTTP_REQUEST_URL);
      if (host_len == 0 || path_len == 0) {
         continue;
      }

      // Concatenate HOST and PATH to get full URL
      char full_url[host_len + path_len + 1];
      char *host = ur_get_ptr(in_tmplt, in_rec, F_HTTP_REQUEST_HOST);
      char *path = ur_get_ptr(in_tmplt, in_rec, F_HTTP_REQUEST_URL);
      strncpy(full_url, host, host_len);
      strncpy(full_url + host_len, path, path_len);
      full_url[path_len + host_len] = '\0';

      // Check if URL is in the list of malicious URLs, if not continue
      if (!is_malicious(full_url, malicious_urls)) {
         if (verbose_print) {
            printf("URL \"%s\" -> CLEAN\n", full_url);
         }
         continue;
      }

      if (verbose_print) {
         printf("URL \"%s\" -> MALICIOUS\n", full_url);
      }

      // URL is malicious - re-send record to output interface.
      ret = trap_send(0, in_rec, ur_rec_size(in_tmplt, in_rec));

      // Handle possible errors
      TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);

      
   }


   /* **** Cleanup **** */
   if (verbose_print) {
      printf("End");
   }

   clean_pid_file(pid_file);

   // Free allocated memory for malicious URLs
   free_url_array(malicious_urls);

   // Do all necessary cleanup in libtrap before exiting
   TRAP_DEFAULT_FINALIZATION();

   // Release allocated memory for module_info structure
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   // Free unirec templates and output record
   ur_free_template(in_tmplt);
   ur_finalize();

   return 0;
}

