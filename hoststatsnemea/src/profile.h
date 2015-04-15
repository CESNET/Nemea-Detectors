/**
 * \file profile.h
 * \brief Main processing of flow data (header file)
 * \author Lukas Hutak <xhutak01@stud.fit.vutbr.cz>
 * \date 2014
 * \date 2015
 */
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

#ifndef _PROFILE_H_
#define _PROFILE_H_

#include <vector>
#include <BloomFilter.hpp>
#include "hoststats.h"
#include "subprofiles.h"

extern "C" {
   #include <unirec/unirec.h>
}

/* -------------------- MAIN PROFILE -------------------- */

class HostProfile {
private:
   stat_table_t *stat_table;   // Statistics table

   // Pointers to common active/learning BloomFilter
   bloom_filter *bf_com_active, *bf_com_learn;
   // Pointer to active/learning BloomFilter for flow direction (req/rsp)
   bloom_filter *bf_dir_active, *bf_dir_learn;

   int table_size;            // Size of table
   bool detector_status;      // Main profile detector active/inactive
   bool port_flowdir;         // Flow direction based on port value (0[off]/1[on])
   sp_list_ptr_v sp_list;     // List of enabled subprofiles

   // Get the reference of record from the table
   hosts_record_t& get_record(const hosts_key_t& key, int8_t **lock);

public:
   int active_timeout;
   int inactive_timeout;
   int det_start_time;

   // Constructor
   HostProfile();

   // Destructor
   ~HostProfile();

   // Update the main profile and subprofiles
   void update(const void *record, const ur_template_t *tmplt,
      bool subprofiles = true);

   // Remove record from the main profile and subprofiles
   void remove_by_key(const hosts_key_t &key);

   // Release all stats loaded in memory
   void release();

   // Clear active BloomFilter and swap pointers
   void swap_bf();

   // Run detectors on the record
   void check_record(const hosts_key_t &key, const hosts_record_t &record,
      bool subprofiles = true);

   // Run detectors on each record in table
   void check_table(bool check_all);
};

#endif
