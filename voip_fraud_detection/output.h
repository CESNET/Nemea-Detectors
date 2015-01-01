/**
 * \file output.h
 * \brief VoIP fraud detection module - output - header file
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


#ifndef VOIP_FRAUD_DETECTION_OUTPUT_H
#define VOIP_FRAUD_DETECTION_OUTPUT_H

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdarg.h>
#include "configuration.h"
#include "data_structure.h"


/** \brief Prefix string of error message. */
#define ERROR_MESSAGE_PREFIX "ERR_voip_fraud_detection:"

/** \brief Length of buffer in convert_to_str() function (int_to_str(), uint_to_str(), ...). */
#define LENGTH_BUFFER_INTTOSTR 10

/** \brief Function macro for printing to standard output with actual datetime.
 * Unlimited input parameters are printed to standard output with actual datetime at the beginning of text.
 */
#define PRINT_OUT(...) write_to_stream(stdout, get_actual_time_string(), ";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard error output with actual datetime.
 * Unlimited input parameters are printed to standard error output with actual datetime at the beginning of text.
 */
#define PRINT_ERR(...) write_to_stream(stderr, ERROR_MESSAGE_PREFIX, get_actual_time_string(), ";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to log file with actual datetime.
 * Unlimited input parameters are printed to log files with actual datetime at the beginning of text.
 */
#define PRINT_LOG(...) write_to_log(get_actual_time_string(), ";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard output and log file at the same time with actual datetime.
 * Unlimited input parameters are printed to standard output and log file at the same time with actual
 * datetime at the beginning of text.
 */
#define PRINT_OUT_LOG(...) write_to_stream(stdout, get_actual_time_string(), ";", __VA_ARGS__, NULL);\
write_to_log(get_actual_time_string(),";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard error output and log file at the same time with actual datetime.
 * Unlimited input parameters are printed to standard error output and log file at the same time with actual
 * datetime at the beginning of text.
 */
#define PRINT_ERR_LOG(...) write_to_stream(stderr, ERROR_MESSAGE_PREFIX, get_actual_time_string(), ";", __VA_ARGS__, NULL);\
write_to_log(ERROR_MESSAGE_PREFIX, get_actual_time_string(),";", __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard output.
 * Unlimited input parameters are printed to standard output.
 */
#define PRINT_OUT_NOTDATETIME(...) write_to_stream(stdout, __VA_ARGS__, NULL)

/** \brief Function macro for printing to standard output and log file at the same time.
 * Unlimited input parameters are printed to standard output and log file at the same time.
 */
#define PRINT_OUT_LOG_NOTDATETIME(...) write_to_stream(stdout, __VA_ARGS__, NULL);\
write_to_log(__VA_ARGS__, NULL)

/** \brief Function macro for printing to standard error output and log file at the same time.
 * Unlimited input parameters are printed to standard error output and log file at the same time.
 */
#define PRINT_ERR_LOG_NOTDATETIME(...) write_to_stream(stderr, ERROR_MESSAGE_PREFIX, __VA_ARGS__, NULL);\
write_to_log(ERROR_MESSAGE_PREFIX, __VA_ARGS__, NULL)


/** \brief Return actual date and time in system default format.
 * \return String with actual date and time.
 */
char * get_actual_time_string();

/** \brief Convert time_to to char array (string) in system default format.
 */
char * time_t_to_str(time_t time);

/** \brief Convert signed integer to char array (string).
 */
char * int_to_str(int integer);

/** \brief Convert unsigned integer to char array (string).
 */
char * uint_to_str(unsigned int integer);

/** \brief Convert unsigned short integer to char array (string).
 */
char * ushortint_to_str(unsigned short int integer);

/** \brief Write input strings to defined stream output (variadic function).
 */
void write_to_stream(FILE * stream, char * str, ...);

/** \brief Write input strings to log file (variadic funtion).
 */
void write_to_log(char * str, ...);

#endif	/* VOIP_FRAUD_DETECTION_OUTPUT_H */
