/*
 * Copyright (C) 2013 CESNET
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

#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <string>
#include <sstream>
#include <vector>
#include <limits>

using namespace std;

extern bool background;
extern int log_syslog;
extern int log_upto;

// static const char *level_str[] = {"EMERGENCY: ", "ALERT: ", "CRITICAL: ", "ERROR: ",
//                                   "WARNING: ", "NOTICE: ", "INFO: ", "DEBUG: "};

// Print given message to syslog and if running in foreground also to stdout
inline void log(int level, const char *msg, ...)
{
   va_list args;
   if (!background && level <= log_upto) {
      va_start(args, msg);
//       if (level >= 0 && level < sizeof(level_str))
//          printf(level_str[level]);
      vprintf(msg, args);
      va_end(args);
      printf("\n");
   }
   if (log_syslog) {
      va_start(args, msg);
      vsyslog(level, msg, args);
      va_end(args);
   }
}



inline string int2str(int x)
{
   stringstream ss;
   ss << x;
   return ss.str();
}

inline int str2int(const string &x)
{
   stringstream ss(x);
   int i = 0;
   ss >> i;
   return i;
}


// Split string using "delim" as a delimiter
// If escape is set to true, "delim" can be escaped by backslash
inline vector<string> split(string str, char delim, bool escape = false)
{
   vector<string> vec;
   int i;
   while ((i = str.find(delim)) != string::npos) {
      if (escape && i > 0 && str[i-1] == '\\')
         continue;
      vec.push_back(str.substr(0,i));
      str = str.substr(i+1);
   }
   vec.push_back(str);
   return vec;
}

// Split string using any character from "delim" as a delimiter
// If escape is set to true, "delim" can be escaped by backslash
inline vector<string> split(string str, const char *delim, bool escape = false)
{
   vector<string> vec;
   int i;
   while ((i = str.find_first_of(delim)) != string::npos) {
      if (escape && i > 0 && str[i-1] == '\\')
         continue;
      vec.push_back(str.substr(0,i));
      str = str.substr(i+1);
   }
   vec.push_back(str);
   return vec;
}


// Replace all occurences of "from" with "to" in string "str"
inline void replace(std::string& str, const std::string& from, const std::string& to) {
    if(from.empty())
        return;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

///////////////////////////////////////////////////////////////////////////////
// Templates definition
// WARNING: use these function only for uint8_t, uint16_t, uint32_t, uint64_t
// types

/**
 * safe_inc()
 *
 * Safely increase the value by one. In case of overflow, return value is set to
 * the maximum possible value.
 *
 * @param value Value to increase
 * @return Increased value
 */
template <typename T>
inline T safe_inc (const T &value) 
{
   if (value < std::numeric_limits<T>::max()) {
      return value + 1;
   } else {
      return value;
   }
}

/**
 * safe_add()
 *
 * Safely add two unsigned values of different types. In case of overflow, 
 * return value is set to the maximum possible value of destination variable.
 *
 * @param dst Destination variable
 * @param src Source variable
 * @return Sum of values or max value of destination type
 */
template <typename T1, typename T2>
inline T1 safe_add (const T1 &dst, const T2 &src) 
{
   if ((src > std::numeric_limits<T1>::max()) || 
      (dst > std::numeric_limits<T1>::max() - src)) {
      return std::numeric_limits<T1>::max();
   }
   else {
      return dst + src;
   }
}

/**
 * safe_add()
 *
 * Safely add two unsigned values of the same type. In case of overflow, 
 * return value is set to the maximum possible value of the type of parameters.
 *
 * @param dst Destination variable
 * @param src Source variable
 * @return Sum of values or max value of the type of parameters
 */
template <typename T>
inline T safe_add (const T &dst, const T &src)
{
   if (dst > std::numeric_limits<T>::max() - src) {
      return std::numeric_limits<T>::max();
   }
   else {
      return dst + src;
   }
}


#endif