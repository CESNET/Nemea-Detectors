/*!
 * \file config.cpp
 * \brief The Configuration singleton - used for centralized access to configuration
 * \author Tomas Cejka <cejkat@cesnet.cz>
 * \date 2015
 * \date 2014
 * \date 2013
 * \date 2012
 */
/*
 * Copyright (C) 2012-2015 CESNET
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
#include <config.h>
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <cstdlib>
#include <pthread.h>
#include "aux_func.h"
#include "hs_config.h"

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

ConfigurationStatus Configuration::load()
{
   fstream file;
   string line;

   // Load configuration from a path defined by the user (only if the path is
   // defined)
   if (configFilePath.size()) {
      file.open(configFilePath.c_str(), ios_base::in);
      if (file.good()) {
         while (file.good()) {
            getline(file, line);
            parseLine(line);
         }
         file.close();
         return INIT_OK;
      } else {
         log(LOG_ERR, "Failed to open configuration file \"%s\"",
            configFilePath.c_str());
         return INIT_FAILED;
      }
   }

   // Load configuration from a path defined by Nemea directory
   file.open(SYSCONFDIR "/" INI_FILENAME, ios_base::in);
   if (file.good()) {
      while (file.good()) {
         getline(file, line);
         parseLine(line);
      }
      file.close();
      return INIT_OK;
   }

   // Load configuration from a file in the same directory as the binary file
   file.open(INI_FILENAME, ios_base::in);
   if (file.good()) {
      while (file.good()) {
         getline(file, line);
         parseLine(line);
      }
      file.close();
      return INIT_OK;
   }

   // Config file is not in current directory nor in Nemea directory, copy default config.
   log(LOG_NOTICE, INI_FILENAME " file not found, trying to load " INI_DEFAULT_FILENAME);

   // copy INI_DEFAULT_FILENAME to INI_FILENAME
   if (copy_file(SYSCONFDIR "/" INI_DEFAULT_FILENAME, SYSCONFDIR "/" INI_FILENAME)) {
      log(LOG_NOTICE, INI_DEFAULT_FILENAME " copied to " INI_FILENAME);
      file.open(SYSCONFDIR "/" INI_FILENAME, ios_base::in);
   } else if (copy_file(INI_DEFAULT_FILENAME, INI_FILENAME)){
      log(LOG_NOTICE, INI_DEFAULT_FILENAME " copied to " INI_FILENAME);
      file.open(INI_FILENAME, ios_base::in);
   } else {
      log(LOG_NOTICE, "Can't copy " INI_DEFAULT_FILENAME " to " INI_FILENAME
         ", using default file directly.");
      file.open(SYSCONFDIR "/" INI_DEFAULT_FILENAME, ios_base::in);
   }
   if (file.good()) {
      while (file.good()) {
         getline(file, line);
         parseLine(line);
      }
      file.close();
      return INIT_OK;
   }

   cerr << "Could not load configuration" << endl;
   log(LOG_ERR, "Could not load configuration");
   return INIT_FAILED;
}

Configuration::Configuration()
{
   pthread_mutex_init(&config_mutex, NULL);
   initStatus = load();
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
   initStatus = load();
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
   delete instance;
   pthread_mutex_destroy(&config_mutex);
   /* This class is useless from this time! */
}

void Configuration::setConfigPath(const string &file)
{
   configFilePath = file;
}

ConfigurationStatus Configuration::getInitStatus()
{
   return initStatus;
}

/** \brief Get integer configuration value
 * Get the value from the configuration file. If the value is not specified or
 * is less than a minimal value, returns default value.
 * \param[in] name Meaning of the value for error messages
 * \param[in] param Name of the value in the configuration file
 * \param[in] def_value Default value
 * \param[in] min_value Minimal value
 * \return Variable from configuration file or default value.
 */
int Configuration::get_cfg_val(string name, string param, int def_value,
   int min_value)
{
   int value;
   string value_str = trim(getValue(param));

   if (value_str.empty()) {
      log(LOG_WARNING, "Warning: %s '%s' is not specified in the configuration "
         "file. Using %d as default.", name.c_str(), param.c_str(), def_value);
      value = def_value;
   } else {
      value = atoi(value_str.c_str());
   }

   if (value < min_value) {
      log(LOG_WARNING, "Warning: %s value '%s' is less than the minimum "
         "value (%d). Using %d as default.", name.c_str(), param.c_str(),
         min_value, def_value);
      value = def_value;
   }

   return value;
}

/** \brief Get status configuration value
 * Get the value from the configuration file. If value is "1", "true" or
 * "enabled", returns true. Otherwise returns false.
 * If the value is not specified, returns false.
 * \param[in] name Meaning of the value for error messages
 * \param[in] param Name of the value in the configuration file
 * \return True or false
 */
bool Configuration::get_cfg_val(std::string name, std::string param)
{
   bool value;
   string value_str = trim(getValue(param));

   if (value_str.empty()) {
      log(LOG_WARNING, "Warning: Status of %s '%s' is not specified in the "
         "configuration file. Disabled by default.", name.c_str(),
         param.c_str());
      value = false;
   } else {
      if (value_str == "1" || value_str == "true" || value_str == "enabled") {
         value = true;
      } else {
         value = false;
      }
   }

   return value;
}

// Static variables Initialization
string Configuration::configFilePath = "";
ConfigurationStatus Configuration::initStatus = NOT_INIT;
Configuration *Configuration::instance = NULL;
pthread_mutex_t Configuration::config_mutex;
