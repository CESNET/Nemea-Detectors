/**
 * \file ipblacklistfilter.cpp
 * \brief Module for detecting blacklisted IP addresses.
 * \author Erik Sabik, xsabik02@stud.fit.vutbr.cz
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \author Filip Suster, sustefil@fit.cvut.cz
 * \date 2013-2018
 */

/*
 * Copyright (C) 2013, 2014, 2015, 2018 CESNET
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

#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <cerrno>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <unistd.h>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include <ipdetect/patternstrings.h>

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif

/* include from nemea-common */
#include <nemea-common.h>
#include "ipblacklistfilter.h"
#include "fields.h"
#include "blacklist_watcher.h"

UR_FIELDS(
//BASIC_FLOW
      ipaddr SRC_IP,      //Source address of a flow
      ipaddr DST_IP,      //Destination address of a flow
      uint16 SRC_PORT,    //Source transport-layer port
      uint16 DST_PORT,    //Destination transport-layer port
      uint8 PROTOCOL,     //L4 protocol (TCP, UDP, ICMP, etc.)
      uint32 PACKETS,     //Number of packets in a flow or in an interval
      uint64 BYTES,       //Number of bytes in a flow or in an interval
      time TIME_FIRST,    //Timestamp of the first packet of a flow
      time TIME_LAST,     //Timestamp of the last packet of a flow
      uint8 TCP_FLAGS,    //TCP flags of a flow (logical OR over TCP flags field of all packets)
//COLLECTOR_FLOW
      uint64 LINK_BIT_FIELD,  //Bit field where each bit marks whether a flow was captured on corresponding link
      uint8 DIR_BIT_FIELD,    //Bit field used for determining incoming/outgoing flow
      uint8 TOS,              //IP type of service
      uint8 TTL,              //IP time to live
//Blacklist items
      uint64 SRC_BLACKLIST,   //Bit field of blacklists IDs which contains the source address of the flow
      uint64 DST_BLACKLIST,   //Bit field of blacklists IDs which contains the destination address of the flow
      string ADAPTIVE_IDS      // UUID4 of the scenario events, separated by comma, used when working with adaptive blacklist
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("ipblacklistfilter", "Module receives the UniRec record and checks if the source address " \
    "or destination address is present in any blacklist that are available. " \
    "If any of the addresses is blacklisted the record is changed by adding " \
    "an index of the blacklist(s) which blacklisted the address. " \
    "This module uses configurator tool. To specify files with blacklists (prepared by blacklist downloader) " \
    "use XML configuration file for IPBlacklistFilter (ipdetect_config.xml). " \
    "To show, edit, add or remove public blacklist information, use XML configuration file for " \
    "blacklist downloader (bl_downloader_config.xml).", 1, 1)

#define MODULE_PARAMS(PARAM) \
  PARAM('c', "", "Specify user configuration file for IPBlacklistFilter. [Default: " SYSCONFDIR "/blacklistfilter/ipdetect_config.xml]", required_argument, "string") \
  PARAM('4', "", "Specify IPv4 blacklist file (overrides config file). [Default: /tmp/blacklistfilter/ip4.blist]", required_argument, "string") \
  PARAM('6', "", "Specify IPv6 blacklist file (overrides config file). [Default: /tmp/blacklistfilter/ip6.blist]", required_argument, "string") \
  PARAM('n', "", "Do not send terminating Unirec when exiting program.", no_argument, "none")

using namespace std;

// Global variable for signaling the program to stop execution
int stop = 0;

// Global variable for signaling the program to update blacklists
int BL_RELOAD_FLAG = 0;

// Blacklist watcher flag. If set, the inotify based thread for watching blacklists is created
static bool WATCH_BLACKLISTS_FLAG;

/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1
)

/**
 * Function for swapping bits in byte.
 * \param in Input byte.
 * \return Byte with reversed bits.
 */
inline uint8_t bit_endian_swap(uint8_t in)
{
   in = (in & 0xF0) >> 4 | (in & 0x0F) << 4;
   in = (in & 0xCC) >> 2 | (in & 0x33) << 2;
   in = (in & 0xAA) >> 1 | (in & 0x55) << 1;
   return in;
}


/**
 * \brief Function for creating masks for IPv4 addresses. It fills the given
 * array with every possible netmask for IPv4 address.
 * \param m Array to be filled.
 */
void create_v4_mask_map(ipv4_mask_map_t &m)
{
   // Explicitly inserted or else it will be 0xFFFFFFFF
   m[0] = 0x00000000;

   for (int i = 1; i <= 32; i++) {
      m[i] = (0xFFFFFFFF >> (32 - i));

      // Swap bits in each byte for compatibility with ip_addr_t structure
      m[i] = (bit_endian_swap((m[i] & 0x000000FF) >> 0) << 0) |
             (bit_endian_swap((m[i] & 0x0000FF00) >> 8) << 8) |
             (bit_endian_swap((m[i] & 0x00FF0000) >> 16) << 16) |
             (bit_endian_swap((m[i] & 0xFF000000) >> 24) << 24);
   }
}

/**
 * \brief Function for creating masks for IPv6 addresses. It fills the given
 * array with every possible netmask for IPv6 address.
 * \param m Array to be filled.
 */
void create_v6_mask_map(ipv6_mask_map_t &m)
{
   // Explicitly inserted or else it will be 0xFF in every byte
   m[0][0] = m[0][1] = 0;

   for (int i = 1; i <= 128; i++) {
      if (i < 64) {
         m[i][0] = 0xFFFFFFFFFFFFFFFF >> (64 - i);
         m[i][1] = 0x0;
      } else {
         m[i][0] = 0xFFFFFFFFFFFFFFFF;
         m[i][1] = 0xFFFFFFFFFFFFFFFF >> (64 - i);
      }
   }
}

/**
 * \brief Function for loading blacklists. It parses files with blacklisted IP
 * addresses (IPv6 blacklist file is optional.). The file shall be preprocessed by blacklist downloader
 * (no redundant whitespaces, forcing lowercase etc.)
 * Function also checks validity of line on which the IP address was found. Invalid of bad formatted lines
 * are ignored.
 * \param v4_list IPv4 vector to be filled
 * \param v6_list IPv6 vector to be filled
 * \param config Configuration with blacklist files.
 * \return ALL_OK if everything goes well, BLIST_FILE_ERROR if file cannot be accessed.
 */
int reload_blacklists(black_list_t &v4_list, black_list_t &v6_list, const ip_config_t *config)
{
   ifstream input;
   string line, ip, bl_index_str;
   uint64_t bl_index;      // blacklist ID is a 64bit map
   int line_num = 0;
   ip_bl_entry_t bl_entry; // black list entry associated with ip address

   black_list_t v4_list_new;
   black_list_t v6_list_new;

   std::vector<char *> blacklist_files;
   blacklist_files.push_back(((ip_config_t *) config)->ipv4_blacklist_file);
   blacklist_files.push_back(((ip_config_t *) config)->ipv6_blacklist_file);

   // Read the blacklist files
   for (auto &file: blacklist_files) {
      line_num = 0;
      input.open(file, ifstream::in);

      if (!input.is_open()) {
         if (file == ((ip_config_t *) config)->ipv6_blacklist_file) {
            // Do not terminate the program when IPv6 blacklist not present
            cerr << "Warning: Could not read IPv6 blacklist, not detecting IPv6" << endl;
            continue;
         }
         cerr << "ERROR: Cannot open blacklist file: " << config->ipv4_blacklist_file << ". Is the downloader running?"
              << endl;
         return BLIST_FILE_ERROR;
      }

      while (!input.eof()) {
         getline(input, line);
         line_num++;

         if (input.bad()) {
            cerr << "ERROR: Failed reading blacklist file (getline badbit)" << endl;
            input.close();
            return BLIST_FILE_ERROR;
         }

         // Find IP-blacklist index separator
         size_t comma_sep = line.find_first_of(',');

         if (comma_sep == string::npos) {
            if (line.empty()) {
               // probably just newline at the end of file
               continue;
            }
            // Blacklist index delimeter not found (bad format?), skip it
            cerr << "WARNING: File '" << file << "' has bad formatted line number '" << line_num << "'" << endl;
            continue;
         }

         // Parse IP
         ip = line.substr(0, comma_sep);

         // Are we loading prefix?
         size_t slash_sep = ip.find_first_of('/');

         if (slash_sep == string::npos) {
            // IP only
            if (!ip_from_str(ip.c_str(), &bl_entry.ip)) {
               cerr << "WARNING: Invalid IP address in file '" << file << "' on line '" << line_num << "'" << endl;
               continue;
            }
            if (ip_is4(&bl_entry.ip)) {
               bl_entry.prefix_len = PREFIX_V4_DEFAULT;
            } else {
               bl_entry.prefix_len = PREFIX_V6_DEFAULT;
            }

         } else {
            // IP prefix
            if (!ip_from_str((ip.substr(0, slash_sep)).c_str(), &bl_entry.ip)) {
               cerr << "WARNING: Invalid IP address in file '" << file << "' on line '" << line_num << "'" << endl;
               continue;
            }

            ip.erase(0, slash_sep + 1);
            bl_entry.prefix_len = (uint8_t) strtol(ip.c_str(), nullptr, 0);
         }

         // Parse blacklist ID
         bl_index = strtoull((line.substr(comma_sep + 1, string::npos)).c_str(), NULL, 10);

         // Determine blacklist
         bl_entry.in_blacklist = bl_index;

         // If handling adaptive blacklist, load adaptive IDs in the entity
         if (bl_index == ADAPTIVE_BLACKLIST_INDEX) {
            string id_part = line.substr(comma_sep + 1, string::npos);
            size_t comma_sep2 = id_part.find_first_of(',');
            id_part = id_part.substr(comma_sep2 + 1, string::npos);
            bl_entry.adaptive_ids = id_part;
         }

         // blacklist:[ports] parsing
         uint16_t bl_num;
         uint16_t port;

         size_t bl_semicolon_sep = line.find_first_of(';');

         if (bl_semicolon_sep == string::npos) {
            // no ports present
            continue;
         }

         string str = line.substr(bl_semicolon_sep, string::npos);
         char *index = const_cast<char *>(str.c_str());
         char* end_ptr = nullptr;

         bl_entry.bl_ports = {};

#define state_start 0
#define state_blacklist_num 1
#define state_ports 2
#define state_invalid 3
#define state_end 4

         int state = state_start;
         while (state != state_end) {
            switch (state) {
            case state_start:
               if (*index == ';') {
                  index++;
                  state = state_blacklist_num;
               } else if (*index == '\0') {
                  state = state_end;
               } else {
                  state = state_invalid;
               }
               break;

            case state_blacklist_num:
               bl_num = strtoul(index, &end_ptr, 10);
               if (end_ptr == index || errno != 0) {
                  cerr << "Parsing blacklist number failed, errno:" << errno << endl;
                  state = state_invalid;
                  break;
               }

               index = end_ptr;
               bl_entry.bl_ports[bl_num] = {};

               if (*index == ':') {
                  index++;
                  state = state_ports;
               } else {
                  state = state_invalid;
               }
               break;

            case state_ports:
               port = strtoul(index, &end_ptr, 10);
               if (end_ptr == index || errno != 0) {
                  cerr << "Parsing port number failed, errno:" << errno << endl;
                  state = state_invalid;
                  break;
               }
               index = end_ptr;
               bl_entry.bl_ports.at(bl_num).insert(port);

               if (*index == ',') {
                  index++;
                  state = state_ports;
               } else if (*index == ';') {
                  index++;
                  state = state_start;
               } else {
                  state = state_end;
               }
               break;
            }

            if (state == state_invalid) {
               cerr << "Invalid blacklist:[ports] on line:" << str << endl;
               break;
            }
         }

         // Add entry to vector
         if (ip_is4(&bl_entry.ip)) {
            v4_list_new.push_back(bl_entry);
         } else {
            v6_list_new.push_back(bl_entry);
         }
      }

      input.close();
   }

   v4_list = move(v4_list_new);
   v6_list = move(v6_list_new);

   DBG((stderr, "Blacklists reloaded. Entries: IP4: %lu, IP6: %lu\n", v4_list.size(), v6_list.size()));

   return ALL_OK;
}

/**
 * \brief Function for searching in blacklists. It uses binary search
 * algorithm to determine whether the given ip address fits any of the prefix/IP in the list.
 * \param searched IP address that we are checking.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param black_list List of prefixes to be compared with. Either IPv4 or IPv6
 * \return IP_NOT_FOUND if the ip address doesn't fit any prefix. Index of the prefix otherwise.
 */
int ip_binary_search(const ip_addr_t *searched,
                     const ipv4_mask_map_t &v4mm,
                     const ipv6_mask_map_t &v6mm,
                     const black_list_t &black_list)
{
   int end, begin, mid;
   int mask_result = 1;
   ip_addr_t masked;

   begin = 0;
   end = black_list.size() - 1;

   // Binary search
   if (ip_is4(searched)) {
      // Searching in IPv4 blacklist
      // Mask the searched IP with the mask of the mid IP, if it matches the network IP -> found
      while (begin <= end) {
         mid = (begin + end) >> 1;
         masked.ui32[2] = searched->ui32[2] & v4mm[black_list[mid].prefix_len];
         mask_result = memcmp(&(black_list[mid].ip.ui32[2]), &(masked.ui32[2]), 4);

         if (mask_result < 0) {
            begin = mid + 1;
         } else if (mask_result > 0) {
            end = mid - 1;
         } else {
            break;
         }
      }
   } else {
      // Searching in IPv6 blacklist
      while (begin <= end) {
         mid = (begin + end) >> 1;
         if (black_list[mid].prefix_len <= 64) {
            // If the prefix is <= 64, compare only the first 8 bytes, since the other 8 bytes of the network are zeroes
            masked.ui64[0] = searched->ui64[0] & v6mm[black_list[mid].prefix_len][0];
            mask_result = memcmp(&(black_list[mid].ip.ui64[0]), &(masked.ui64[0]), 8);
         } else {
            masked.ui64[0] = searched->ui64[0];
            masked.ui64[1] = searched->ui64[1] & v6mm[black_list[mid].prefix_len][1];
            mask_result = memcmp(&(black_list[mid].ip.ui8), &(masked.ui8), 16);
         }

         if (mask_result < 0) {
            begin = mid + 1;
         } else if (mask_result > 0) {
            end = mid - 1;
         } else {
            break;
         }
      }
   }

   if (mask_result == 0) {
      // Address found, return blacklist index
      return mid;
   }

   return IP_NOT_FOUND;
}

/**
 * @brief fill bitfield with flags of ports where the port matching succeeded or where no port information are available
 * 		  gets called for records that have been already matched based on SRC_IP/DST_IP
 *
 * @param bl_entry blacklist entry
 * @param port src/dst port of the matched record
 *
 * @return bitfield with only those flags filled where ports were matched or not available
 */
uint64_t check_ports_get_bitfield(const ip_bl_entry_t &bl_entry, uint16_t port)
{
   uint64_t inverse_matched_bitfield = 0;

   if (bl_entry.bl_ports.empty()) {
      // no port information => match everything
      return bl_entry.in_blacklist;
   }

   for (const auto &blacklist: bl_entry.bl_ports) {
      if (blacklist.second.find(port) == blacklist.second.end()) {
         inverse_matched_bitfield |= (uint64_t)(1u << (uint32_t)(blacklist.first - 1));
      }
   }

   return inverse_matched_bitfield xor bl_entry.in_blacklist;
}

/**
 * \brief Function for checking blacklisted IPv4/IPv6 addresses.
 *
 * It extracts both source and
 * destination addresses from the UniRec record and tries to match them to either
 * address or prefix. If the match is positive the field in the detection record is filled
 * with the respective blacklist(s) number.
 * \param ur_in  Template of input UniRec record.
 * \param ur_out Template of detection UniRec record.
 * \param record Record being analyzed.
 * \param detected Detection record used if any address matches the blacklist.
 * \param v4mm Map of IPv4 masks.
 * \param v6mm Map of IPv6 masks.
 * \param v4blacklist List of IPv4 prefixes to be compared with.
 * \param v6blacklist List of IPv6 prefixes to be compared with.
 * \return BLACKLISTED if match was found otherwise ADDR_CLEAR.
 */
int blacklist_check(ur_template_t *ur_in,
                    ur_template_t *ur_out,
                    const void *record,
                    void *detected,
                    const ipv4_mask_map_t &v4mm,
                    const ipv6_mask_map_t &v6mm,
                    const black_list_t &v4blacklist,
                    const black_list_t &v6blacklist)
{
   // determine which blacklist (ipv4/ipv6) we are working with
   const black_list_t &bl = ip_is4(&(ur_get(ur_in, record, F_SRC_IP))) ? v4blacklist : v6blacklist;

   // index of the prefix the source ip fits in (return value of binary search)
   int search_result;

   // port-matching
   uint16_t port;
   uint64_t matched_bitfield;

   // Check source IP
   if ((search_result = ip_binary_search(ur_get_ptr(ur_in, record, F_SRC_IP), v4mm, v6mm, bl)) != IP_NOT_FOUND) {
      if (bl[search_result].in_blacklist == ADAPTIVE_BLACKLIST_INDEX) {
         // Adaptive IP filter mode
         ur_set_string(ur_out, detected, F_ADAPTIVE_IDS, bl[search_result].adaptive_ids.c_str());
      } else {
         ur_set_string(ur_out, detected, F_ADAPTIVE_IDS, "");
      }

      port = ur_get(ur_in, record, F_SRC_PORT);  // source IP was matched

      matched_bitfield = check_ports_get_bitfield(bl[search_result], port);

      if (matched_bitfield != 0) {
         ur_set(ur_out, detected, F_SRC_BLACKLIST, matched_bitfield);
         return BLACKLISTED;
      }

      ur_set(ur_out, detected, F_DST_BLACKLIST, 0x0);

      // Check destination IP
   } else if ((search_result = ip_binary_search(ur_get_ptr(ur_in, record, F_DST_IP), v4mm, v6mm, bl)) != IP_NOT_FOUND) {
      if (bl[search_result].in_blacklist == ADAPTIVE_BLACKLIST_INDEX) {
         ur_set_string(ur_out, detected, F_ADAPTIVE_IDS, bl[search_result].adaptive_ids.c_str());
      } else {
         ur_set_string(ur_out, detected, F_ADAPTIVE_IDS, "");
      }

      port = ur_get(ur_in, record, F_DST_PORT);  // dest IP was matched - mirrored

      matched_bitfield = check_ports_get_bitfield(bl[search_result], port);

      if (matched_bitfield != 0) {
         ur_set(ur_out, detected, F_DST_BLACKLIST, matched_bitfield);
         return BLACKLISTED;
      }

      ur_set(ur_out, detected, F_SRC_BLACKLIST, 0x0);

   }

   return ADDR_CLEAR;
}


/**
 * \brief Function for checking if incoming flow has src/dst port 53.
 */
bool is_dns_traffic(ur_template_t *ur_in, const void *data)
{
   uint16_t src_port = ur_get(ur_in, data, F_SRC_PORT);
   uint16_t dst_port = ur_get(ur_in, data, F_DST_PORT);
   return (src_port == 53) || (dst_port == 53);
}

int main(int argc, char **argv)
{
   int main_retval = 0;
   int retval = 0;
   int send_terminating_unirec = 1;

   // Set default files names
   char *userFile = (char *) SYSCONFDIR
   "/blacklistfilter/ipdetect_config.xml";
   char *ipv4_file = nullptr;
   char *ipv6_file = nullptr;

   // For use with prefixes
   black_list_t v4_list;
   black_list_t v6_list;

   // Mask array for prefixes
   ipv4_mask_map_t v4_masks;
   ipv6_mask_map_t v6_masks;
   create_v4_mask_map(v4_masks);
   create_v6_mask_map(v6_masks);

   // TRAP initialization
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   void *detection = NULL;
   ur_template_t *ur_output = NULL;
   ur_template_t *ur_input = NULL;
   pthread_t watcher_thread = 0;

   // UniRec templates for recieving data and reporting blacklisted IPs
   ur_input = ur_create_input_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST",
                                       NULL);
   ur_output = ur_create_output_template(0,
                                         "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST,"
                                         "SRC_BLACKLIST,DST_BLACKLIST,ADAPTIVE_IDS", NULL);

   if (ur_input == NULL || ur_output == NULL) {
      cerr << "Error: Input or output template could not be created" << endl;
      main_retval = 1;
      goto cleanup;
   }

   // Create detection record, variable size is used for ADAPTIVE_ID
   detection = ur_create_record(ur_output, IP_DETECTION_ALLOC_LEN);
   if (detection == NULL) {
      cerr << "Error: Memory allocation problem (output record)" << endl;
      main_retval = 1;
      goto cleanup;
   }

   int opt;

   // ********** Parse arguments **********
   while ((opt = getopt(argc, argv, "n4:6:c:")) != -1) {
      switch (opt) {
      case 'c': // user configuration file for IPBlacklistFilter
         userFile = optarg;
         break;
      case '4':
         ipv4_file = optarg;
         break;
      case '6':
         ipv6_file = optarg;
         break;
      case 'n': // Do not send terminating Unirec
         send_terminating_unirec = 0;
         break;
      case '?':
         main_retval = 1;
         goto cleanup;
      }
   }

   ip_config_t config;

   if (loadConfiguration((char *) MODULE_CONFIG_PATTERN_STRING, userFile, &config, CONF_PATTERN_STRING)) {
      cerr << "Error: Could not parse XML configuration." << endl;
      main_retval = 1;
      goto cleanup;
   }

   // If blacklist files given from cli, override config
   if (ipv4_file != nullptr) {
      strcpy(config.ipv4_blacklist_file, ipv4_file);
   }
   if (ipv6_file != nullptr) {
      strcpy(config.ipv6_blacklist_file, ipv6_file);
   }

   if (strcmp(config.watch_blacklists, "true") == 0) {
      WATCH_BLACKLISTS_FLAG = true;
   } else {
      WATCH_BLACKLISTS_FLAG = false;
   }

   // Load ip addresses from sources
   retval = reload_blacklists(v4_list, v6_list, &config);

   // If update from bl_file could not be processed, return error
   if (retval == BLIST_FILE_ERROR) {
      cerr << "Error: Unable to read blacklist files" << endl;
      main_retval = 1;
      goto cleanup;
   }

   if (WATCH_BLACKLISTS_FLAG) {
      watcher_wrapper_t watcher_wrapper;
      watcher_wrapper.detector_type = IP_DETECT_ID;
      watcher_wrapper.data = (void *) &config;

      if (pthread_create(&watcher_thread, NULL, watch_blacklist_files, (void *) &watcher_wrapper) > 0) {
         cerr << "Error: Couldnt create watcher thread" << endl;
         main_retval = 1;
         goto cleanup;
      }
   }

   // ***** Main processing loop *****
   while (!stop) {
      const void *data;
      uint16_t data_size;

      // Retrieve data from sender
      retval = TRAP_RECEIVE(0, data, data_size, ur_input);
      TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(retval,
      continue, break);

      // Check the data size
      if (data_size != ur_rec_size(ur_input, data)) {
         if (data_size <= 1) { // end of data
            break;
         } else { // data corrupted
            cerr << "ERROR: Corrupted data or wrong data template was specified. ";
            cerr << "Size computed from record: " << ur_rec_size(ur_input, data) << " ";
            cerr << "Size returned from Trap: " << data_size << endl;
            break;
         }
      }

      // Ignore DNS queries
      if (is_dns_traffic(ur_input, data)) {
         continue;
      }

      // Try to match the IP addresses to blacklist
      retval = blacklist_check(ur_input, ur_output, data, detection, v4_masks, v6_masks, v4_list, v6_list);

      // If IP address was found on blacklist
      if (retval == BLACKLISTED) {
         ur_copy_fields(ur_output, detection, ur_input, data);
         trap_send(0, detection, ur_rec_size(ur_output, detection));
         DBG((stderr, "IP detected on blacklist\n"))
      }

      if (BL_RELOAD_FLAG) {
         DBG((stderr, "Reloading blacklists\n"));
         retval = reload_blacklists(v4_list, v6_list, &config);
         if (retval == BLIST_FILE_ERROR) {
            cerr << "ERROR: Unable to load update blacklist. Will use the old one instead." << endl;
         }

         // this lazy locking is fine, we don't need to reload the blacklists immediately
         // and locking the mutex in every iteration is ineffective
         pthread_mutex_lock(&BLD_SYNC_MUTEX);
         BL_RELOAD_FLAG = 0;
         pthread_mutex_unlock(&BLD_SYNC_MUTEX);
      }
   }

   // If set, send terminating message to modules on output
   if (send_terminating_unirec) {
      trap_send(0, "TERMINATE", 1);
   }

   cleanup:
   // Clean up before termination
   ur_free_record(detection);
   ur_free_template(ur_input);
   ur_free_template(ur_output);
   ur_finalize();

   TRAP_DEFAULT_FINALIZATION();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   if (WATCH_BLACKLISTS_FLAG && watcher_thread != 0) {
      // since watcher hangs on poll(), pthread_cancel is fine (poll is a cancelation point)
      if (pthread_cancel(watcher_thread) == 0) {
         pthread_join(watcher_thread, NULL);
         DBG((stderr, "Watcher thread successfully canceled\n"));
      } else {
         cerr << "Warning: Failed to cancel watcher thread" << endl;
      }
   }

   return main_retval;
}
