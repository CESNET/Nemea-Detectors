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

ur_time_t current_time;
// Return actual date and time in system default format

char *get_actual_time_string()
{
   return time_t_to_str(current_time);
}

// Convert time_to to char array (string) in system default format

char *time_t_to_str(ur_time_t t)
{
   static char time_str[FORMAT_DATETIME_LENGTH];
   const time_t time = t;
   struct tm tmp_tm;

   // convert local_time to string in defined format
   if (strftime(time_str, FORMAT_DATETIME_LENGTH, FORMAT_DATETIME, gmtime_r(&time, &tmp_tm)) == 0) {
      // set empty string in case of error strftime
      time_str[0] = '\0';
   }

   return time_str;
}

/** \brief Macro to generating function for converting to char array (string). */
#define GENERATE_FUNCTION_CONVERT_TO_STR(NAME_FUNCTION, VARIABLE_TYPE, FORMAT) char * NAME_FUNCTION(VARIABLE_TYPE input) \
{ \
   static char NAME_FUNCTION_string [LENGTH_BUFFER_INTTOSTR]; \
   sprintf(NAME_FUNCTION_string, FORMAT, input); \
   return NAME_FUNCTION_string; \
}

// Convert signed integer to char array (string)
GENERATE_FUNCTION_CONVERT_TO_STR(int_to_str, int, "%d")

// Convert unsigned integer to char array (string)
GENERATE_FUNCTION_CONVERT_TO_STR(uint_to_str, unsigned int, "%u")

// Convert unsigned short integer to char array (string)
GENERATE_FUNCTION_CONVERT_TO_STR(ushortint_to_str, unsigned short int, "%hu")


// Write input strings to defined stream output (variadic function)

void write_to_stream(FILE * stream, char * str, ...)
{
   va_list parameters;
   char * parameter;

   // set first parameter
   parameter = str;

   // initialization of parameters list
   va_start(parameters, str);

   // write parameters to standard output
   while (parameter != NULL) {
      fprintf(stream, "%s", parameter);
      parameter = va_arg(parameters, char*);
   }

   // end using variable parameters list
   va_end(parameters);
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
