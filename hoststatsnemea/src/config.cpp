/*!
 * \file config.cpp
 * \brief The Configuration singleton - used for centralized access to configuration
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2013
 * \date 2012
 */
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
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <syslog.h>
#include <pthread.h>
#include "aux_func.h"
#include "config.h"

using namespace std;


bool copy_file(const char* from, const char* to)
{
   ifstream src(from);
   if (!src.good()) {
      src.close();
      return false;
   }
   ofstream dst(to);
   if (!dst.good()) {
      src.close();
      dst.close();
      return false;
   }
   dst << src.rdbuf();
   if (!dst.good()) {
      src.close();
      dst.close();
      return false;
   }
   src.close();
   dst.close();
   return true;
}


void Configuration::trimString(string &text)
{
   /* erase end of string */
   text.erase(text.find_last_not_of(INI_WHITESPACE)+1);

   /* erase begin of string */
   size_t pos;
   if ((pos = text.find_first_not_of(INI_WHITESPACE)) != 0) {
      text.erase(0, pos);
   }
}

void Configuration::parseLine(string line)
{
   string paramName, value;

   if (line.length() == 0 || line[0] == '#') {
      /* skip comment */
      return;
   }

   size_t pos = line.find_first_of(INI_DELIM);
   if (pos == string::npos) {
      /* not found - skip? */
      return;
   }
   paramName = line.substr(0, pos);
   trimString(paramName);
   value = line.substr(pos+1);
   trimString(value);
   values[paramName] = value;
}

void Configuration::load()
{
   fstream file;
   string line;
   file.open(INI_FILENAME, ios_base::in);
   if (file.good()) {
      while (file.good()) {
         getline(file, line);
         parseLine(line);
      }
      file.close();
      return;
   }
   file.open("/etc/" INI_FILENAME, ios_base::in);
   if (file.good()) {
      while (file.good()) {
         getline(file, line);
         parseLine(line);
      }
      file.close();
      return;
   }
   
   // Config file is not in current directory nor in /etc/, copy default config.
   log(LOG_NOTICE, INI_FILENAME " file not found, trying to load " INI_DEFAULT_FILENAME);
   
   // copy INI_DEFAULT_FILENAME to INI_FILENAME
   if (copy_file(INI_DEFAULT_FILENAME, INI_FILENAME)) {
      log(LOG_NOTICE, INI_DEFAULT_FILENAME " copied to " INI_FILENAME);
      file.open(INI_FILENAME, ios_base::in);
   } else {
      syslog(LOG_NOTICE, "Can't copy " INI_DEFAULT_FILENAME " to " INI_FILENAME, ", using default file directly.");
      file.open(INI_DEFAULT_FILENAME, ios_base::in);
   }
   if (file.good()) {
      while (file.good()) {
         getline(file, line);
         parseLine(line);
      }
      file.close();
      return;
   }
   
   cerr << "Could not load configuration" << endl;
   log(LOG_CRIT, "Could not load configuration");
}

Configuration::Configuration()
{
   pthread_mutex_init(&config_mutex, NULL);
   load();
}

int Configuration::lock()
{
   return pthread_mutex_lock(&config_mutex);
}

int Configuration::unlock()
{
   return pthread_mutex_unlock(&config_mutex);
}

void Configuration::reload()
{
   lock();
   clean();
   load();
   unlock();
}

string Configuration::getValue(string paramName)
{
   return values[paramName];
}

Configuration *Configuration::getInstance()
{
   // Only allow one instance of class to be generated.
   if (!Configuration::instance) {
      instance = new Configuration();
   }

   return instance;
}

void Configuration::clean()
{
   /* should be already locked, do not try to lock again */
   values.clear();
}

void Configuration::freeConfiguration()
{
   pthread_mutex_destroy(&config_mutex);
   /* This class is useless from this time! */
}

Configuration *Configuration::instance = NULL;
pthread_mutex_t Configuration::config_mutex;

#ifdef DEBUG_HS_CONFIG
int main(int argc, char **argv)
{
   cout << (*Configuration::getInstance());

   cout << "Found value: " << Configuration::getInstance()->getValue("rules") << endl;
   cout << "Found value: " << Configuration::getInstance()->getValue("rles") << endl;

   return 0;
}
#endif
