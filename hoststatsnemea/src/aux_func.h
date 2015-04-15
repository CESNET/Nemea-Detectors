/*
 * Copyright (C) 2013-2015 CESNET
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

#ifndef _AUX_FUNC_H_
#define _AUX_FUNC_H_

// Auxiliary functions for various conversions

#include <string>
#include <sstream>
#include <vector>
#include <limits>
#include <cstdarg>
#include <cstdio>
#include <syslog.h>
#include <stdint.h>

using namespace std;

extern int log_upto;

/** \brief Print given message to syslog and also to stdout
 * \param[in] level Type of a syslog priority
 * \param[in] msg The message
 */
inline void log(int level, const char *msg, ...)
{
   va_list args;
   if (level <= log_upto) {
      va_start(args, msg);
      vprintf(msg, args);
      va_end(args);
      printf("\n");
   }

   // Write to Syslog
   va_start(args, msg);
   vsyslog(level, msg, args);
   va_end(args);
}

/** \brief Parse and set new mask for syslog
 * \param[in] mask Mask name
 */
inline void parse_logmask(string &mask)
{
   if (mask.compare("LOG_EMERG") == 0) {
      log_upto = LOG_EMERG;
   } else if (mask.compare("LOG_ALERT") == 0) {
      log_upto = LOG_ALERT;
   } else if (mask.compare("LOG_CRIT") == 0) {
      log_upto = LOG_CRIT;
   } else if (mask.compare("LOG_ERR") == 0) {
      log_upto = LOG_ERR;
   } else if (mask.compare("LOG_WARNING") ==0) {
      log_upto = LOG_WARNING;
   } else if (mask.compare("LOG_NOTICE") == 0) {
      log_upto = LOG_NOTICE;
   } else if (mask.compare("LOG_INFO") == 0) {
      log_upto = LOG_INFO;
   } else if (mask.compare("LOG_DEBUG") == 0) {
      log_upto = LOG_DEBUG;
   }
   setlogmask(LOG_UPTO(log_upto));
}

/** \brief Convert int ot string
 * \param[in] x Number
 * \return String
 */
inline string int2str(int x)
{
   stringstream ss;
   ss << x;
   return ss.str();
}

/** \brief Convert string to int
 * \param[in] x String
 * \return Int
 */
inline int str2int(const string &x)
{
   stringstream ss(x);
   int i = 0;
   ss >> i;
   return i;
}

/** \brief Split string using any character from "delim" as a delimiter
 * \param[in] str String
 * \param[in] delim Delimiter
 * \param[in] escape If escape is set to true, "delim" can be escaped by backslash
 * \return A vector of strings
 */
inline vector<string> split(string str, char delim, bool escape = false)
{
   vector<string> vec;
   size_t i;
   while ((i = str.find(delim)) != string::npos) {
      if (escape && i > 0 && str[i-1] == '\\')
         continue;
      vec.push_back(str.substr(0,i));
      str = str.substr(i+1);
   }
   vec.push_back(str);
   return vec;
}

/** \brief Split string using any character from "delim" as a delimiter
 * \param[in] str String
 * \param[in] delim Delimiter
 * \param[in] escape If escape is set to true, "delim" can be escaped by backslash
 * \return A vector of strings
 */
inline vector<string> split(string str, const char *delim, bool escape = false)
{
   vector<string> vec;
   size_t i;
   while ((i = str.find_first_of(delim)) != string::npos) {
      if (escape && i > 0 && str[i-1] == '\\')
         continue;
      vec.push_back(str.substr(0,i));
      str = str.substr(i+1);
   }
   vec.push_back(str);
   return vec;
}

/** \brief Replace all occurences of "from" with "to" in string "str"
 * \param[in,out] str String
 * \param[in] from Find what
 * \param[in] to Replace with
 */
inline void replace(std::string& str, const std::string& from, const std::string& to) {
   if(from.empty())
      return;
   size_t start_pos = 0;
   while((start_pos = str.find(from, start_pos)) != std::string::npos) {
      str.replace(start_pos, from.length(), to);
      start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
   }
}

/** \brief Trim string
 * Removes whitespaces (spaces, tabs, etc.) from front and back of a string.
 * If all characters are whitespaces, empty string is returned.
 * \param[in] str Input string
 * \return Trimmed string
 */
inline string trim(const string &str)
{
   const char* WHITESPACE = " \t\n\v\f\r";
   size_t first = str.find_first_not_of(WHITESPACE);
   size_t last = str.find_last_not_of(WHITESPACE);
   if (first == string::npos) {
      return "";
   }
   return str.substr(first, last - first + 1);
}

/** \brief Safe increment of unsigned integer
 * Safely increase the value by one. In case of overflow, value is set to
 * the maximum possible value.
 * \warning Use this template only for uint8_t, uint16_t, uint32_t, uint64_t
 * \param[in] value Value to increase
 */
template <typename T>
inline void safe_inc (T &value)
{
   if (value < std::numeric_limits<T>::max()) {
      ++value;
   }
}

/** \brief Safely adds two unsigned integers of different types
 * In case of overflow, a destination value is set to the maximum possible value
 * of a destination type.
 * \warning Use this template only for uint8_t, uint16_t, uint32_t, uint64_t
 * \param[in] dst Destination variable
 * \param[in] src Source variable
 */
template <typename T1, typename T2>
inline void safe_add (T1 &dst, const T2 &src)
{
   if ((src > std::numeric_limits<T1>::max()) ||
      (dst > std::numeric_limits<T1>::max() - src)) {
      dst = std::numeric_limits<T1>::max();
   } else {
      dst += src;
   }
}

/** \brief Safely adds two unsigned integers of same type
 * In case of overflow, a destination value is set to the maximum possible value
 * of the type of parameters.
 * \warning Use this template only for uint8_t, uint16_t, uint32_t, uint64_t
 * \param[in] dst Destination variable
 * \param[in] src Source variable
 */
template <typename T>
inline void safe_add (T &dst, const T &src)
{
   if (dst > std::numeric_limits<T>::max() - src) {
      dst = std::numeric_limits<T>::max();
   } else {
      dst += src;
   }
}

#endif
