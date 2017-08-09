/**
 * \file smtp_spam.c
 * \brief A SMTP spam detector.
 * \author Ladislav Macoun <macoulad@fit.cvut.cz>
 * \date 2017
 */
/* *****************************************************************************
 * Copyright (C) 2017 CESNET
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
 * ****************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* Detector includes */
#include <stdio.h>
#include <signal.h>
#include <getopt.h>
#include <inttypes.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <unirec/ipaddr.h>
#include "fields.h"
#include "b_plus_tree.h"

/*
 * Detector defenitions
 * */
#define DEFAULT_TH_ALLOC 20 // default size of trash hold allocated memory
/*
 * Definition of basic module information - module name, module
 * description, number of input and output interfaces
 */
#define trash_interval 3600 // define trashhold cleanup interval
#define MODULE_BASIC_INFO(BASIC) \
  BASIC("SMTP spam detection module", \
        "" \
        "" \
        "", 1, 1)
/**
 * Definition of module parameters - every parameter has short_opt, long_opt,
 * description, flag whether an argument is required or it is optional and
 * argument type which is NULL in case the parameter does not need argument.
 * Module parameter argument types: int8, int16, int32, int64, uint8, uint16,
 * uint32, uint64, float, string
 */
#define MODULE_PARAMS(PARAM) \
  PARAM('p', "port", "Port selected for for filtering.",\
         required_argument, "uint16") \
  PARAM('a', "address", "Address selected for filtering.",\
         required_argument, "ipaddr")
//PARAM(char, char *, char *, no_argument  or  required_argument, char *)
/**
 * To define positional parameter ("param" instead of "-m param"
 * or "--mult param"), use the following definition:
 * PARAM('-', "", "Parameter description", required_argument, "string")
 * There can by any argument type mentioned few lines before.
 * This parameter will be listed in Additional parameters in module help output
 *
 * Definition of fields used in unirec templates (for both input and output
 * interfaces) in this example basic flow from flow_meter
 *
 * This module functions as a filter of flows forwarded by flow_meter, I need
 * all fields written below to be forwarded to the next module.
 * */
UR_FIELDS (
   ipaddr DST_IP,
   ipaddr SRC_IP,
   uint64 BYTES,
   uint64 LINK_BIT_FIELD,
   time TIME_FIRST,
   time TIME_LAST,
   uint32 PACKETS,
   uint32 SMTP_2XX_STAT_CODE_COUNT,
   uint32 SMTP_3XX_STAT_CODE_COUNT,
   uint32 SMTP_4XX_STAT_CODE_COUNT,
   uint32 SMTP_5XX_STAT_CODE_COUNT,
   uint32 SMTP_COMMAND_FLAGS,
   uint32 SMTP_MAIL_CMD_COUNT,
   uint32 SMTP_RCPT_CMD_COUNT,
   uint32 SMTP_STAT_CODE_FLAGS,
   uint16 DST_PORT,
   uint16 SRC_PORT,
   uint8 DIR_BIT_FIELD,
   uint8 PROTOCOL,
   uint8 TCP_FLAGS,
   uint8 TOS,
   uint8 TTL,
   string SMTP_DOMAIN,
   string SMTP_FIRST_RECIPIENT,
   string SMTP_FIRST_SENDER
)

#define SMTP_FIELDS ("DST_IP,"\
                     "SRC_IP,"\
                     "BYTES,"\
                     "LINK_BIT_FIELD,"\
                     "TIME_FIRST,"\
                     "TIME_LAST,"\
                     "PACKETS,"\
                     "SMTP_2XX_STAT_CODE_COUNT,"\
                     "SMTP_3XX_STAT_CODE_COUNT,"\
                     "SMTP_4XX_STAT_CODE_COUNT,"\
                     "SMTP_5XX_STAT_CODE_COUNT,"\
                     "SMTP_COMMAND_FLAGS,"\
                     "SMTP_MAIL_CMD_COUNT,"\
                     "SMTP_RCPT_CMD_COUNT,"\
                     "SMTP_STAT_CODE_FLAGS,"\
                     "DST_PORT,"\
                     "SRC_PORT,"\
                     "DIR_BIT_FIELD,"\
                     "PROTOCOL,"\
                     "TCP_FLAGS,"\
                     "TOS,"\
                     "TTL,"\
                     "SMTP_DOMAIN,"\
                     "SMTP_FIRST_RECIPIENT,"\
                     "SMTP_FIRST_SENDER")


// structure for detector parameters
typedef struct detec_param {
   uint32_t trash_hold_interval;
} detect_param_t;

// structure for private smpt flow
typedef struct smtp_flow {
   uint64_t bytes;            // BYTES
   uint64_t link_field;       // LINK_BIT_FIELD
   ur_time_t t_first;         // TIME_FIRST
   ur_time_t t_last;          // TIME_LAST
   uint32_t pct;              // PACKETS
   uint32_t smtp_2xx;         // SMTP_2XX_STAT_CODE_COUNT
   uint32_t smtp_3xx;         // SMTP_3XX_STAT_CODE_COUNT
   uint32_t smtp_4xx;         // SMTP_4XX_STAT_CODE_COUNT
   uint32_t smtp_5xx;         // SMTP_5XX_STAT_CODE_COUNT
   uint32_t smtp_cmd;         // SMTP_COMMAND_FLAG
   uint32_t smtp_mail_cmd;    // SMTP_MAIL_CMD_COUNT
   uint32_t smtp_rcpt_cmd;    // SMTP_RCPT_CMD_COUNT
   uint32_t smtp_stat_code;   // SMTP_STAT_CODE_FLAGS
   uint16_t dst_port;         // DST_PORT
   uint16_t src_port;         // SRC_PORT
   uint8_t dir_bit_field;     // DIR_BIT_FIELD
   uint8_t prot;              // PROTOCOL
   uint8_t tcp_flags;         // TCP_FLAGS
   uint8_t tos;               // TOS
   uint8_t ttl;               // TTL
   } smtp_flow_t;

// structure for email record
typedef struct email_rec {
   ip_addr_t *dst_ip;         // destination ip address
   ip_addr_t *src_ip;         // source ip address
   char *smtp_dom;            // domain name, SMTP_DOMAIN
   char *smtp_first_rec;      // email of first recipient
   char *smtp_first_send;     // email of first sender
   smtp_flow_t *flow;    // additional flow imformation about smtp
} email_rec_t;

// structure for storing email records from senders
// sender has an unique id which is his ip address
typedef struct item {
   ip_addr_t ID;              // unique id of sender email record
   email_rec_t **records;     // email record
   size_t num;                // number of records
   size_t size;               // allocated size of current database
   ur_time_t time;            // timestamp of email record
   // recived
} item_t;

trap_module_info_t *module_info = NULL;
static int stop = 0;

/**
 * Function to handle SIGTERM and SIGINT signals (used to stop the module)
 */
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)
// *****************************************************************************
int ip_comparator(void *lhs, void *rhs)
{
   ip_addr_t *val_lhs, *val_rhs;
   val_lhs = (ip_addr_t *) lhs;
   val_rhs = (ip_addr_t *) rhs;
   return ip_cmp(val_lhs, val_rhs);
}

/*! @brief new email record constructor
 * @return NULL when an error occurs otherwise allocated
 * new email record with filled values from link
 */
email_rec_t *create_new_record(const ur_template_t *in_tmplt,
                              const void *in_rec)
{
   email_rec_t *ret_val = (email_rec_t *) malloc(sizeof(email_rec_t));

   if (!ret_val) {
      fprintf(stderr, "Error: Cannot allocate new email record.\n");
      return NULL;
   }

   ret_val->dst_ip = &ur_get(in_tmplt, in_rec, F_SRC_IP);
   ret_val->src_ip = &ur_get(in_tmplt, in_rec, F_DST_IP);
   // copy strings from unirec
   ret_val->smtp_dom = strndup(&ur_get(in_tmplt, in_rec, F_SMTP_DOMAIN),
                               ur_get_len(in_tmplt, in_rec, F_SMTP_DOMAIN));
   ret_val->smtp_first_rec = strndup(&ur_get(in_tmplt, in_rec, F_SMTP_FIRST_RECIPIENT),
                                     ur_get_len(in_tmplt, in_rec, F_SMTP_FIRST_RECIPIENT));
   ret_val->smtp_first_send = strndup(&ur_get(in_tmplt, in_rec, F_SMTP_FIRST_SENDER),
                                      ur_get_len(in_tmplt, in_rec, F_SMTP_FIRST_SENDER));
   // check for failure
   if (!ret_val->dst_ip || !ret_val->src_ip || !ret_val->smtp_dom ||
       !ret_val->smtp_first_rec || !ret_val->smtp_first_send) {
      fprintf(stderr, "Error: UR_GET bad seed.");
      goto cleanup;
   }
   smtp_flow_t *rec_header = (smtp_flow_t *) calloc(1, sizeof(smtp_flow_t));
   if (!rec_header) {
      fprintf(stderr, "Error: Cannot alllocate new email record header.\n");
      goto cleanup;
   }
   rec_header->dst_port = ur_get(in_tmplt, in_rec, F_DST_PORT);
   // check if destination port is correct
   if (rec_header->dst_port != 25) {
      // todo report wierd behavior dst_port should be 25
   }
   // todo fill more values, now just for debugging
   // assign email additional information to email record
   ret_val->flow = rec_header;
   // return new email record
   return ret_val;
cleanup:
   // todo remove spagheti code - do cleanup codes
   if (ret_val->dst_ip) {
      free(ret_val->dst_ip);
   }
   if (ret_val->src_ip) {
      free(ret_val->src_ip);
   }
   if (ret_val->smtp_dom) {
      free(ret_val->smtp_dom);
   }
   if (ret_val->smtp_first_rec) {
      free(ret_val->smtp_first_rec);
   }
   if (ret_val->smtp_first_send) {
      free(ret_val->smtp_first_send);
   }
   free(ret_val);
   return NULL;
}

int drop_database(bpt_t *db)
{
   int has_next = 0;
   item_t *value_pt = NULL;
   bpt_list_item *b_item = NULL;

   b_item = bpt_list_init(b_plus_tree);
}

/*
 * @bried function adds new email record to database
 *
 * if @param email_recors SRC_IP is already in database
 * record get appended to email records array, otherwise
 * new array is allocated until TRASH_HOLD_CLEANUP_INTERVAL
 * passes
 *
 * @param b_plus_tree is initialized bpt of email_rec_t structers
 * with src_ip as a key
 *
 * @param email_record is email record that should be inserted to
 * the database
 *
 * @retun positive value on succes otherwise negative one
 * */
int insert_to_db(bpt_t *b_plus_tree, email_rec_t *email_record)
{
   // add record to database
   void *new_item = bpt_search_or_insert(b_plus_tree, &email_record->dst_ip);
   if (!new_item) {
      fprintf(stderr, "Error: BTP search or insert failed.\n");
      return -1;
   } else {
      item_t *data = (ip_db_rec_t *) new_item;
      if (data->records) {//SENDER IS IN DB
         // append this record to the sender
         // check allocated memory space
         if (data->num++ >= data->size) { // have to allocate new memory
            // double extened the memory
            data->size *= 2;
            email_rec_t **tmp = (email_rec_t **)
                                realloc(data->records, sizeof(email_rec_t) * data->size);
            if (!tmp) {
               fprintf(stderr, "Error: REALLOC failed.\n");
               return -1;
            }
         }
         // append
         data->records[data->num] = email_record;
         #ifndef DEBUG
         fprintf(stderr, "> rec appended\n");
         #endif

      } else { //SENDER HAS NOT BEEN RECORDED YET, ADD NEW RECORD TO DB

         data->num = 0;
         data->records = (email_rec_t **)
                         malloc(sizeof(email_rec_t *) * DEFAULT_TH_ALLOC);
         if (!data->records) {
            fprintf(stderr, "Error: Data records allocation failed.\n");
         }
         data->records[0] = email_record;
         data->num++;
         #ifndef DEBUG
         fprintf(stderr, "> new rec added\n");
         #endif
      }
   return 1;
   }
}

int main(int argc, char **argv)
{
   int ret;
   signed char opt;
   uint16_t port = 1;
   ip_addr_t ip;

   bpt_t *b_plus_tree = NULL; // database for data

   char buffer1[1024], buffer2[1024];

   /*
    * *** TRAP initialization ****
    * Macro allocates and initializes module_info structure according
    * to MODULE_BASIC_INFO and MODULE_PARAMS definitions on the lines
    * 69 and 77 of this file. It also creates a string with short_opt
    * letters for getopt function called "module_getopt_string" and
    * long_options field for getopt_long function in variable "long_options"
    */
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   /*
    * Let TRAP library parse program arguments, extract its parameters
    * and initialize module interfaces
    */
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   /*
    * Register signal handler.
    */
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   /*
    * Parse program arguments defined by MODULE_PARAMS macro with
    * getopt() function (getopt_long() if available).
    * This macro is defined in config.h file generated by configure script
    */
   while ((opt = TRAP_GETOPT(argc,argv,
                             module_getopt_string,
                             long_options)) != -1) {
      switch (opt) {
      case 'p':
         sscanf(optarg, "%" SCNu16, &port);
         break;
      case 'a':
         ip_from_str(optarg, &ip);
         break;
      default:
         fprintf(stderr, "Invalid arguments.\n");
         FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
         TRAP_DEFAULT_FINALIZATION();
         return -1;
      }
   }
   /* **** Create UniRec templates **** */
   ur_template_t *in_tmplt = ur_create_input_template(0,SMTP_FIELDS, NULL);
   if (in_tmplt == NULL) {
      fprintf(stderr, "Error: Input template could not be created.\n");
      return -1;
   }
   ur_template_t *out_tmplt = ur_create_output_template(0, SMTP_FIELDS, NULL);
   if (out_tmplt == NULL) {
      ur_free_template(in_tmplt);
      fprintf(stderr, "Error: Output template could not be created.\n");
      return -1;
   }
   // Allocate memory for output record
   void *out_rec = ur_create_record(out_tmplt, 0);
   if (out_rec == NULL) {
      ur_free_template(in_tmplt);
      ur_free_template(out_tmplt);
      fprintf(stderr, "Error: Memory allocation problem (output record).\n");
      return -1;
   }
   // Initialize bpt with email_rec_t structure #? 16
   b_plus_tree = bpt_init(16, &ip_comparator,
                          sizeof(item_t),
                          sizeof(ip_addr_t));
   if (b_plus_tree == NULL) {
         fprintf(stderr, "Error: Could not initialize BPT.\n");
         return -1;
   }
   /* **** Main processing loop **** */
   // Read data from input, process them and write to output
   while (!stop) {
      const void *in_rec;
      uint16_t in_rec_size;
      // Receive data from input interface 0.
      // Block if data are not available immediately
      // (unless a timeout is set using trap_ifcctl)
      ret = TRAP_RECEIVE(0, in_rec, in_rec_size, in_tmplt);
      // Handle possible errors
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      // Check size of received data
      if (in_rec_size < ur_rec_fixlen_size(in_tmplt)) {
         if (in_rec_size <= 1) {
            break; // End of data (used for testing purposes)
         } else {
            fprintf(stderr,
                    "Error: data with wrong size received \
                    (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_fixlen_size(in_tmplt), in_rec_size);
            break;
         }
      }
      // In the following code flows with destination input by parameters
      // (ip address and port) are filtered and forwarded on the outgoing
      // interface, other flows are discarded.
      if ( (ur_get(in_tmplt, in_rec, F_DST_PORT) == port) ||
           (ip_cmp(&ur_get(in_tmplt, in_rec, F_DST_IP), &ip) == 0) ) {
         ur_copy_fields(out_tmplt, out_rec, in_tmplt, in_rec);
         ret = trap_send(0, out_rec, ur_rec_fixlen_size(out_tmplt));
         TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, continue, break);
      }
      // Create new SMTP flow record
      email_rec_t *email_record = create_new_record(in_tmplt, in_rec);
      if (!email_record) {
         fprintf(stderr, "Error: Email record bad seed.\n");
         return -1;
      }

      #ifndef DEBUG_VERBOSE
      ip_to_str(email_record->src_ip, buffer1);
      ip_to_str(email_record->dst_ip, buffer2);
      printf("%s %s %i\n", buffer1, buffer2, email_record->flow->dst_port);
      #endif
      if (insert_to_db(b_plus_tree, email_record) < 0) {
         fprintf(stderr, "Insert to db failed.\n");
         return -1;
      }

   }
   /* **** Cleanup **** */
   // Clean BTP database
   btp_clean(b_plus_tree);
   // Do all necessary cleanup in libtrap before exiting
   TRAP_DEFAULT_FINALIZATION();
   // Release allocated memory for module_info structure
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   // Free unirec templates and output record
   ur_free_record(out_rec);
   ur_free_template(in_tmplt);
   ur_free_template(out_tmplt);
   ur_finalize();

   return EXIT_SUCCESS;
}
