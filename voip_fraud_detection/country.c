/**
 * \file country.c
 * \brief VoIP fraud detection module - country
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

#include <linux/limits.h>
#include <stdlib.h>

#include "country.h"
#include "voip_fraud_detection.h"

#ifdef ENABLE_GEOIP

// Load GeoIP databases to memory

void geoip_databases_load()
{
   // read GeoIP databases to memory
   geo_ipv4 = GeoIP_open(GEOIP_DATABASE_IPV4_PATH, GEOIP_MMAP_CACHE | GEOIP_CHECK_CACHE);
   geo_ipv6 = GeoIP_open(GEOIP_DATABASE_IPV6_PATH, GEOIP_MMAP_CACHE | GEOIP_CHECK_CACHE);

   // check return status
   if (geo_ipv4 == NULL) {
      PRINT_ERR("Error opening GeoIP IPv4 database!\n");
   } else {
#ifdef DEBUG
      printf("Loaded GeoIP IPv4 database:%s", GeoIP_database_info(geo_ipv4));
      printf(" (database_type:%i)\n", geo_ipv4->databaseType);
#endif
   }

   if (geo_ipv6 == NULL) {
      PRINT_ERR("Error opening GeoIP IPv6 database!\n");
   } else {
#ifdef DEBUG
      printf("Loaded GeoIP IPv6 database:%s", GeoIP_database_info(geo_ipv6));
      printf(" (database_type:%i)\n", geo_ipv6->databaseType);
#endif
   }
}

// Free GeoIP databases from memory

void geoip_databases_free()
{
   GeoIP_delete(geo_ipv4);
   GeoIP_delete(geo_ipv6);
}

// Check if country exists in storage of the IP address

int country_ip_exists(ip_item_t * ip, const char * country)
{
   int i;

   for (i = 0; i < ip->country_count; i++) {
      if (strncmp(ip->country[i], country, 2) == 0) {
         // country found
         return 1;
      }
   }

   // country not found
   return 0;
}

// Save country to storage of the IP address

void country_ip_save(ip_item_t * ip, const char * country, cc_hash_table_v2_t * hash_table_ip)
{
   if (country == NULL) return;

   // check if country doesn't exist yet
   if (country_ip_exists(ip, country) == 0) {

      if (ip->country_count < COUNTRY_STORAGE_SIZE) {
         strncpy(ip->country[ip->country_count], country, 2);
         ip->country_count++;
      } else {
         PRINT_ERR_LOG("Full country storage of IP address. Increase COUNTRY_STORAGE_SIZE in configuration.h!\n");
      }
   }

   // get actual time
   time_t time_actual;
   time(&time_actual);

   // check if countries file saving interval was expired
   if (COUNTRIES_FILE_SAVING_INTERVAL != 0 && difftime(time_actual, time_last_countries_file_saved) >= COUNTRIES_FILE_SAVING_INTERVAL) {
      countries_save_all_to_file(modul_configuration.countries_file, hash_table_ip);
      time(&time_last_countries_file_saved);
   }

}

// Power off learning countries mode and start detection of calling to different countries

void countries_power_off_learning_mode(int signum)
{
   modul_configuration.countries_detection_mode = COUNTRIES_DETECTION_MODE_ON;
   PRINT_OUT_LOG("Info: Learning countries mode was finished, starting detection of calling to different countries ...\n");
}

// Load all countries from defined file to memory

int countries_load_all_from_file(char * file, cc_hash_table_v2_t * hash_table_ip)
{
   if (file != NULL) {
      FILE * io_countries_file;

      // open countries file (read, text mode)
      io_countries_file = fopen(file, "rt");
      if (io_countries_file == NULL) {
         PRINT_OUT("Warning: Can't open countries file: \"", file, "\"\n");
         return 0;
      }

      ip_item_t * hash_table_item, * last_hash_table_item;
      ip_addr_t ip_address;
      char ip_address_str [INET6_ADDRSTRLEN + 1];
      char allowed_countries_line [MAX_LENGTH_ALLOWED_COUNTRIES_LINE + 1];

      char character = '#';
      last_hash_table_item = NULL;

      // process countries file
      while (character != EOF) {

         character = fgetc(io_countries_file);

         // new line of file

         switch (character) {
            case '#':
            {
               // comment line, ignore it
               while (character != '\n' && character != EOF) character = fgetc(io_countries_file);
               break;
            }

            case 'A':
            {
               // globall allowed countries line (for all IP addresses)

               // check description of line
               if (fgets(allowed_countries_line, MAX_LENGTH_ALLOWED_COUNTRIES_LINE + 1, io_countries_file) == NULL \
                     || strncmp(allowed_countries_line, "LLOWED_COUNTRIES=", 17) != 0 \
                     || modul_configuration.allowed_countries_count != 0) {
                  fclose(io_countries_file);
                  return -1;
               }

               // set first country settings position (after '=')
               unsigned int position = 17;

               // allocate memory for allowed countries
               div_t number_of_allowed_countries;
               number_of_allowed_countries = div(strlen(allowed_countries_line) - position, 3);
               modul_configuration.allowed_countries = (char *) malloc(sizeof (char) * 2 * (number_of_allowed_countries.quot + 1));

               // load allowed countries to memory
               char first_letter, second_letter;
               while (1) {

                  // load 2 chars (country shortcut)
                  first_letter = allowed_countries_line[position++];
                  if (first_letter == '\n' || first_letter == '\0') {
                     break;
                  }
                  second_letter = allowed_countries_line[position++];
                  if (second_letter == '\n' || second_letter == '\0') {
                     fclose(io_countries_file);
                     return -1;
                  }

                  // check separation mark ':'
                  character = allowed_countries_line[position++];
                  if (character != ':') {
                     fclose(io_countries_file);
                     return -1;
                  }

                  // save country
                  modul_configuration.allowed_countries[modul_configuration.allowed_countries_count * 2] = first_letter;
                  modul_configuration.allowed_countries[modul_configuration.allowed_countries_count * 2 + 1] = second_letter;
                  modul_configuration.allowed_countries_count++;
               }

               break;
            }

            case '=':
            {
               // list of countries (separated by ':')

               // check if IP address is defined
               if (last_hash_table_item == NULL) {

                  fclose(io_countries_file);
                  return -1;

               } else {

                  // load countries to memory
                  char first_letter, second_letter;
                  while (1) {

                     // load 2 chars (country shortcut)
                     first_letter = fgetc(io_countries_file);
                     if (first_letter == '\n' || first_letter == EOF) {
                        break;
                     }
                     second_letter = fgetc(io_countries_file);
                     if (second_letter == '\n' || second_letter == EOF) {
                        fclose(io_countries_file);
                        return -1;
                     }

                     // check separation mark ':'
                     character = fgetc(io_countries_file);
                     if (character != ':') {
                        fclose(io_countries_file);
                        return -1;
                     }

                     // save country
                     last_hash_table_item->country[last_hash_table_item->country_count][0] = first_letter;
                     last_hash_table_item->country[last_hash_table_item->country_count][1] = second_letter;
                     last_hash_table_item->country_count++;
                  }
               }

               break;
            }

            case '-':
            {
               // IP address line

               // reset string of IP address
               strcpy(ip_address_str, "");

               // load IP address
               if (fgets(ip_address_str, INET6_ADDRSTRLEN + 1, io_countries_file) == NULL) {
                  fclose(io_countries_file);
                  return -1;
               }

               // remove newline from the end of ip_address_str
               if (ip_address_str[strlen(ip_address_str) - 1] == '\n') ip_address_str[strlen(ip_address_str) - 1] = '\0';

               // check for correct format of IP address
               if (ip_from_str(ip_address_str, &ip_address) == 0) {
                  fclose(io_countries_file);
                  return -1;
               }

               // create new item for hash table
               hash_table_item = (ip_item_t *) malloc(sizeof (ip_item_t));

               // check successful allocation memory
               if (hash_table_item == NULL) {
                  PRINT_ERR("load_all_countries_from_file: hash_table_item: Error memory allocation\n");
                  fclose(io_countries_file);
                  return -1;
               }

               //  initialize hash_table_item (and check for errors)
               if (hash_table_item_initialize(hash_table_item) == -1) {
                  fclose(io_countries_file);
                  return -1;
               }

               // insert item (pointer) into hash table
               ip_item_t * kicked_hash_table_item;
               if ((kicked_hash_table_item = (ip_item_t *) ht_insert_v2(hash_table_ip, (char *) ip_address.bytes, (void *) &hash_table_item)) != NULL) {
                  // free memory of kicked item from hash table
                  hash_table_item_free_inner_memory(*(ip_item_t **) kicked_hash_table_item);
                  free(*(ip_item_t **) kicked_hash_table_item);
                  kicked_hash_table_item = NULL;
#ifdef DEBUG
                  PRINT_OUT("load_all_countries_from_file: Hash table reaches size limit\n");
#endif
               }

               // save indication of IP address settings
               last_hash_table_item = hash_table_item;

               break;
            }

            case EOF:
            case '\n':
            case ' ':
               // ignore new lines, spaces and EOF
               break;

            default:

               // not allowed character (bad syntax of countries file)
               fclose(io_countries_file);
               return -1;
         }
      }

      // close countries file
      fclose(io_countries_file);
   }

   return 0;
}

// Save all countries from memory to defined file

void countries_save_all_to_file(char * file, cc_hash_table_v2_t * hash_table_ip)
{
   if (file != NULL) {
      FILE * io_countries_file;

      // open file (write, text mode)
      io_countries_file = fopen(file, "wt");
      if (io_countries_file == NULL) {
         PRINT_ERR("Error open country file for writing: \"", file, "\"\n");
         return;
      }

      // write countries to file
      fprintf(io_countries_file, "# VOIP_FRAUD_DETECTION - COUNTRIES FILE\n#\n");
      fprintf(io_countries_file, "# =========================================================\n");
      fprintf(io_countries_file, "# WARNING: !!! Backup this file before manually editing !!!\n");
      fprintf(io_countries_file, "# =========================================================\n#\n");
      fprintf(io_countries_file, "# Save time: %s (module version: "MODULE_VERSION")\n", get_actual_time_string());
      fprintf(io_countries_file, "# For description of countries shortcut visit: http://dev.maxmind.com/geoip/legacy/codes/iso3166/\n");
      fprintf(io_countries_file, "# After every country must be placed delimiter \":\"!\n");
      fprintf(io_countries_file, "#\n# Allowed countries for all IP addresses can be defined on the next line. (example: \"ALLOWED_COUNTRIES=CZ:SK:\")\n");
      fprintf(io_countries_file, "ALLOWED_COUNTRIES=");

      unsigned int allowed_countries_id;
      for (allowed_countries_id = 0; allowed_countries_id < modul_configuration.allowed_countries_count; allowed_countries_id++) {
         fprintf(io_countries_file, "%.*s:", 2, &(modul_configuration.allowed_countries[allowed_countries_id * 2]));
      }
      fprintf(io_countries_file, "\n#\n# Next lines contain countries for individual IP addresses ...\n");

      ip_item_t * hash_table_item;
      ip_addr_t ip_address;
      char ip_address_str [INET6_ADDRSTRLEN];

      unsigned int countries_count = 0;

      int table_id, country_id;
      for (table_id = 0; table_id < hash_table_ip->table_size; table_id++) {

         if (hash_table_ip->ind[table_id].valid) {

            memcpy(&ip_address, hash_table_ip->keys[hash_table_ip->ind[table_id].index], sizeof (ip_addr_t));
            ip_to_str(&ip_address, (char *) &ip_address_str);

            hash_table_item = *(ip_item_t **) hash_table_ip->data[hash_table_ip->ind[table_id].index];
            if (hash_table_item->country_count > 0) {
               fprintf(io_countries_file, "-%s\n=", ip_address_str);

               for (country_id = 0; country_id < hash_table_item->country_count; country_id++) {
                  fprintf(io_countries_file, "%.*s:", 2, hash_table_item->country[country_id]);
               }

               fprintf(io_countries_file, "\n");
               countries_count++;
            }
         }
      }

      // write countries to file
      fprintf(io_countries_file, "# END OF FILE - VOIP_FRAUD_DETECTION - COUNTRIES (%u)\n", countries_count);

      // close file
      fclose(io_countries_file);
   }

   // prevention of immediately auto-saving countries file
   time(&time_last_countries_file_saved);
}

// Free all memory allocated for countries

void countries_free()
{
   if (modul_configuration.allowed_countries != NULL) {
      free(modul_configuration.allowed_countries);
      modul_configuration.allowed_countries = NULL;
   }
}

// Get domain name or IP adrress from input URI

char * get_domain(char * str, int str_len)
{
   static char output[MAX_LENGTH_SIP_TO - 3];

   int char_index, end_index;
   for (char_index = 0; char_index < str_len; char_index++) {

      // '@' found
      if (str[char_index] == '@') {
         strncpy(output, &str[char_index + 1], str_len - char_index - 1);

         for (end_index = 0; end_index < strlen(output); end_index++) {
            if (output[end_index] == ':') {
               output[end_index] = '\0';
               return output;
            }
         }
         output[str_len - char_index - 1] = '\0';
         return output;
      }
   }

   // input string doesn't contain '@'
   char * output_pointer;
   if (cut_sip_identifier_from_string(&output_pointer, str, &str_len) == -1) {
      // bad syntax of input string
      return NULL;
   } else {
      return output_pointer;
   }
}

// Detection of calling to different countries and write/send information about it

int country_different_call_detection(cc_hash_table_v2_t * hash_table, ip_item_t * hash_table_item, char *sip_to, int sip_to_len, char *sip_from, char *user_agent, ip_addr_t * ip_src, ip_addr_t * ip_dst)
{
   char * text_domain_part;

   // get text of domain part from called party
   if ((text_domain_part = get_domain(sip_to, sip_to_len)) != NULL) {

      int geoip_id;
      ip_addr_t ip;

      // check if domain text is IP address
      if (ip_from_str(text_domain_part, &ip) != 0) {
         if (ip_is4(&ip)) {
            // IP address is version 4
            geoip_id = GeoIP_id_by_addr_gl(geo_ipv4, text_domain_part, &geoip_lookup);
         } else {
            // IP address is version 6
            geoip_id = GeoIP_id_by_addr_v6_gl(geo_ipv6, text_domain_part, &geoip_lookup);
         }
      } else {
         // try if domain part is FQDN for IP address version 4 (Fully Qualified Domain Name)
         geoip_id = GeoIP_id_by_name_gl(geo_ipv4, text_domain_part, &geoip_lookup);

         // try if domain part is FQDN for IP address version 6 (Fully Qualified Domain Name)
         if (geoip_id <= 0) geoip_id = GeoIP_id_by_name_v6_gl(geo_ipv6, text_domain_part, &geoip_lookup);
      }

      // geoip if country is located
      if (geoip_id > 0) {

         switch (modul_configuration.countries_detection_mode) {
            case COUNTRIES_LEARNING_MODE:

               // save country for defined IP address
               country_ip_save(hash_table_item, GeoIP_code_by_id(geoip_id), hash_table);
               break;

            case COUNTRIES_DETECTION_MODE_ON:

               // check if country isn't in datastore of IP address
               if (country_ip_exists(hash_table_item, GeoIP_code_by_id(geoip_id)) == 0) {

                  char country_allowed = 0;

                  // check allowed countries
                  unsigned int allowed_countries_id;
                  for (allowed_countries_id = 0; allowed_countries_id < modul_configuration.allowed_countries_count; allowed_countries_id++) {
                     if (strcmp(&(modul_configuration.allowed_countries[allowed_countries_id * 2]), GeoIP_code_by_id(geoip_id)) == 0) {
                        // country is globally allowed
                        country_allowed = 1;
                        break;
                     }
                  }

                  // get actual time
                  static time_t time_detected;
                  time(&time_detected);

                  // is country globally allowed?
                  if (country_allowed == 1) {

                     return STATE_NO_ATTACK;

                  } else {

                     /* CALLING TO DIFFERENT COUNTRY ATTACK DETECTED */


                     uint32_t event_id;
                     short attack_continuation = 0;

                     // check if attack continue or the new attack will be reported
                     if (hash_table_item->call_different_country_attack_event_id != 0 \
                             && strncmp(hash_table_item->call_different_country_attack_country, GeoIP_code_by_id(geoip_id), 2) == 0) {

                        // check if detection_pause_after_attack was expired
                        if (difftime(time_detected, hash_table_item->time_attack_detected_call_different_country) >= modul_configuration.detection_pause_after_attack) {

                           // last attack continues
                           event_id = hash_table_item->call_different_country_attack_event_id;
                           attack_continuation = 1;

                        } else {

                           // pause after last attack not expired, stop detection
                           return STATE_NO_ATTACK;

                        }

                     } else {
                        // new attack

                        // increment event_id
                        last_event_id++;

                        event_id = last_event_id;

                        // save attack detection
                        hash_table_item->call_different_country_attack_detected_count++;

                        // add one to statistics of number attacks
                        global_module_statistic.call_different_country_attack_detected_count++;
                     }

                     // save attack detection event
                     hash_table_item->call_different_country_detection_event_count++;

                     // add one to statistics of number detection events
                     global_module_statistic.call_different_country_detection_event_count++;

                     // get IP adresses in text format
                     char ip_src_str[INET6_ADDRSTRLEN + 1], ip_dst_str[INET6_ADDRSTRLEN + 1];
                     ip_to_str(ip_src, ip_src_str);
                     ip_to_str(ip_dst, ip_dst_str);

                     // Write attack information to stdout and log ...
                     PRINT_OUT_LOG("==> Detected Calling to different country");
                     if (attack_continuation == 1) {
                        PRINT_OUT_LOG_NOTDATETIME(" (continuation)");
                     }
                     PRINT_OUT_LOG_NOTDATETIME("!; event_id=", uint_to_str(event_id), "; ");
                     PRINT_OUT_LOG_NOTDATETIME("detection_time=\"", time_t_to_str(time_detected), "\"; ");
                     PRINT_OUT_LOG_NOTDATETIME("SRC_IP=", ip_src_str, "; ");
                     PRINT_OUT_LOG_NOTDATETIME("DST_IP=", ip_dst_str, "; ");
                     PRINT_OUT_LOG_NOTDATETIME("SIP_FROM=\"", sip_from, "\"; ");
                     PRINT_OUT_LOG_NOTDATETIME("SIP_TO=\"", sip_to, "\"; ");
                     PRINT_OUT_LOG_NOTDATETIME("USER_AGENT=\"", user_agent, "\"; ");
                     PRINT_OUT_LOG_NOTDATETIME("COUNTRY_NAME=\"", GeoIP_name_by_id(geoip_id), "\"; ");
                     PRINT_OUT_LOG_NOTDATETIME("COUNTRY_CODE=\"", GeoIP_code_by_id(geoip_id), "\"; "); // name of country in iso-8859-1
                     PRINT_OUT_LOG_NOTDATETIME("CONTINENT=\"", GeoIP_continent_by_id(geoip_id), "\"; ");
                     PRINT_OUT_LOG_NOTDATETIME("IP_detection_event_count=", uint_to_str(hash_table_item->call_different_country_detection_event_count), "; ");
                     PRINT_OUT_LOG_NOTDATETIME("IP_attack_detected_count=", uint_to_str(hash_table_item->call_different_country_attack_detected_count), " <==");

                     PRINT_OUT_LOG_NOTDATETIME("\n");

                     // Send attack information to output interface

                     // fill in fields of detection event
                     ur_set(ur_template_out, detection_record, UR_EVENT_ID, event_id);
                     ur_set(ur_template_out, detection_record, UR_EVENT_TYPE, UR_EVT_T_VOIP_CALL_DIFFERENT_COUNTRY);
                     ur_set(ur_template_out, detection_record, UR_SRC_IP, *ip_src);
                     ur_set(ur_template_out, detection_record, UR_DST_IP, *ip_dst);
                     ur_set(ur_template_out, detection_record, UR_DETECTION_TIME, ur_time_from_sec_msec(time_detected, 0));
                     ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_COUNTRY_CODE, GeoIP_code_by_id(geoip_id), sizeof (char) * LENGTH_COUNTRY_CODE);
                     ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_SIP_FROM, sip_from, sizeof (char) * strlen(sip_from));
                     ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_SIP_TO, sip_to, sizeof (char) * strlen(sip_to));
                     ur_set_dyn(ur_template_out, detection_record, UR_VOIP_FRAUD_USER_AGENT, user_agent, sizeof (char) * strlen(user_agent));

                     // send alert to output interface
                     int return_code = trap_send(0, detection_record, ur_rec_size(ur_template_out, detection_record));
                     TRAP_DEFAULT_SEND_ERROR_HANDLING(return_code,;, PRINT_ERR("Error during sending", UNIREC_OUTPUT_TEMPLATE, " to output interface!\n"););

                     // save attack information to item of hash table
                     hash_table_item->call_different_country_attack_event_id = event_id;
                     strncpy(hash_table_item->call_different_country_attack_country, GeoIP_code_by_id(geoip_id), 2);

                     // save event_id to file
                     event_id_save(modul_configuration.event_id_file);

                     // update time of last attack
                     time(&(hash_table_item->time_attack_detected_call_different_country));

                     // is not disabled saving new country?
                     if (modul_configuration.disable_saving_new_country != 1) {
                        // save country for defined IP address
                        country_ip_save(hash_table_item, GeoIP_code_by_id(geoip_id), hash_table);
                     }

                     return STATE_ATTACK_DETECTED;

                  }

               }

               break;
         }
      }
   }

   return STATE_NO_ATTACK;
}

#endif
