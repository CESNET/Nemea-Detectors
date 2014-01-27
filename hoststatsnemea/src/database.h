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

#ifndef _HS_DATABASE_H
#define _HS_DATABASE_H

#include <string>
#include <vector>
#include "hoststats.h" // stat_map_t, host_key_t, host_rec_t

class Database {
   std::string profile_name;
   std::string path;
   std::string db_cleaner;
   std::string max_db_size;
   bool read_only;
public:
   Database(const std::string& profile_name);
   int connect();
   int disconnect();
   int reloadConfig();
   int store(const std::string &timeslot, const stat_map_t &stat_map) const;
   int load(const std::string &timeslot, stat_map_t &stat_map) const;
   int cleanup() const;
   int getRecord(const std::string& timeslot, const hosts_key_t &key, hosts_record_t &rec) const;
   std::vector<std::string> getTimeslots(const std::string &start = "", const std::string &end = "") const;
   int getNumOfRecords(const std::string &timeslot) const;
   
   static int storeToFile(const std::string &filename, const stat_map_t &stat_map);
};


#endif
