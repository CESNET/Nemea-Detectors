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

#endif
