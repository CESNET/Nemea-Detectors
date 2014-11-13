/**
 * \file output.c
 * \brief VoIP fraud detection module - output
 * \author Lukas Truxa <truxaluk@fit.cvut.cz>
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

#include "output.h"


// Return actual date and time in system default format

char * get_actual_time_string()
{
   time_t actual_time;

   // get actual local time
   time(&actual_time);

   return time_t_to_str(actual_time);
}

// Convert time_to to char array (string) in system default format

char * time_t_to_str(time_t time)
{
   static char time_str[20];
   struct tm *local_time;

   local_time = localtime(&time);

   // convert local_time to string in defined format
   if (strftime(time_str, 20, FORMAT_DATETIME, local_time) == 0) {
      // set empty string in case of error strftime
      time_str[0] = '\0';
   }

   return time_str;
}

// Convert signed integer to char array (string)

char * int_to_str(int integer)
{
   static char string [LENGTH_BUFFER_INTTOSTR];
   sprintf(string, "%d", integer);
   return string;
}

// Convert unsigned integer to char array (string)

char * uint_to_str(unsigned int integer)
{
   static char string [LENGTH_BUFFER_INTTOSTR];
   sprintf(string, "%u", integer);
   return string;
}

// Print error information on error output

void print_error(int error_number, char * error_description)
{
   fprintf(stderr, LOG_ERROR_PREFIX);
   fprintf(stderr, "%i:%s", error_number, error_description);
   fprintf(stderr, "\n");
}

// Write input strings to log file (variadic funtion)

void write_to_log(char * str, ...)
{

   // check if log_file is set (configuration of module)
   if (modul_configuration.log_file != NULL) {

      va_list parameters;
      char * parameter;

      static FILE * io_log_file;

      // open log file (append, text mode)
      io_log_file = fopen(modul_configuration.log_file, "at");
      if (io_log_file == NULL) {
         fprintf(stderr, "Error open log file: %s!\n", modul_configuration.log_file);
         return;
      }

      // set first parameter
      parameter = str;

      // initialization of parameters list
      va_start(parameters, str);

      // write parameters to log file
      while (parameter != NULL) {
         fprintf(io_log_file, "%s", parameter);
         parameter = va_arg(parameters, char*);
      }

      // close log file
      fclose(io_log_file);

      // end using variable parameters list
      va_end(parameters);
   }
}

// Write input strings to standard output (variadic function)

void write_std(char * str, ...)
{
   va_list parameters;
   char * parameter;

   // set first parameter
   parameter = str;

   // initialization of parametres list
   va_start(parameters, str);

   // write parameters to standard output
   while (parameter != NULL) {
      printf("%s", parameter);
      parameter = va_arg(parameters, char*);
   }

   // end using variable parameters list
   va_end(parameters);
}
