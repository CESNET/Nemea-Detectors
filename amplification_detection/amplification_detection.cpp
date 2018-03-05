/**
 * \file amplification_detection.cpp
 * \brief Nemea module for detection of amplification attacks based on NetFlow
 * \author Michal Kovacik <ikovacik@fit.vutbr.cz>
 * \author Pavel Krobot <xkrobo01@cesnet.cz>
 * \date 2013
 * \date 2014
 */

/*
 * Copyright (C) 2013, 2014 CESNET
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

//information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <list>
#include <map>
#include <utility>
#include <algorithm>
#include <getopt.h>
#include <unistd.h>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#include "fields.h"
#ifdef __cplusplus
}
#endif
#include <unirec/unirec.h>
#include "amplification_detection.h"

/**
 * Use this macro to count curently saved bytes/packets/flow only - if there are
 * more then "max_flow_items" (default 100 000) records for one pair. By default
 * all incomming records are counted.
 */
//#define COUNTS_WORKING

//#define DEBUG

using namespace std;

UR_FIELDS(
   ipaddr SRC_IP,      //Source address of a flow
   ipaddr DST_IP,      //Destination address of a flow
   uint16 SRC_PORT,    //Source transport-layer port
   uint16 DST_PORT,    //Destination transport-layer port
   uint8 PROTOCOL,     //L4 protocol (TCP, UDP, ICMP, etc.)
   uint32 PACKETS,     //Number of packets in a flow or in an interval
   uint64 BYTES,       //Number of bytes in a flow or in an interval
   time TIME_FIRST,    //Timestamp of the first packet of a flow
   time TIME_LAST,     //Timestamp of the last packet of a flow
   uint32 REQ_FLOWS,    //Number of flows in an interval (requests)
   uint32 REQ_PACKETS,  //Number of packets in a flow or in an interval (requests)
   uint64 REQ_BYTES,    //Number of packets in a flow or in an interval (responses)
   uint32 RSP_FLOWS,    //Number of flows in an interval (responses)
   uint32 RSP_PACKETS,  //Number of packets in a flow or in an interval (responses)
   uint64 RSP_BYTES,    //Number of bytes in a flow or in an interval (responses)
   uint32 EVENT_ID      //Identification number of reported event
)

trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("amplification_detection","This module detects amplification attacks from NetFlow data. It is based on the flow's analysis of incoming and outgoing packets and bytes. Detection is triggered always when certain time window of src and dst ip is collected.",1,1)

#define MODULE_PARAMS(PARAM) \
   PARAM('d', "log_dir", "path to log files - it has to end with slash ('/'). If the parameter is omitted, no logs are stored.", required_argument, "string") \
   PARAM('p', "port", "port used for detection (53)", required_argument, "int32") \
   PARAM('n', "top", "number of top N values chosen (10)", required_argument, "int32") \
   PARAM('q', "step", "step of histogram (10)", required_argument, "uint32") \
   PARAM('a', "min_ampf", "minimal amplification effect considered an attack (5)", required_argument, "int32") \
   PARAM('t', "min_flow", "minimal threshold for number of flows in TOP-N (1000)", required_argument, "uint32") \
   PARAM('i', "min_count", "minimal normalized threshold for count of flows in TOP-N (0.4)", required_argument, "float") \
   PARAM('y', "min_resp_pack", "minimal threshold for average size of responses in packets in TOP-N (0)", required_argument, "uint32") \
   PARAM('l', "min_resp_byte", "minimal threshold for average size of responses in bytes in TOP-N (1000)", required_argument, "uint32") \
   PARAM('m', "max_query", "maximal threshold for average size of queries in bytes in TOP-N (300)", required_argument, "uint32") \
   PARAM('w', "timeout", "time window of detection / timeout of inactive flow (3600)", required_argument, "int32") \
   PARAM('s', "period", "time window of deletion / period of inactive flows checking(300)", required_argument, "int32") \
   PARAM('S', "record_count", "count of records to store for query / response direction (max size of vector).", required_argument, "uint32")

static int stop = 0;

/* configuration structure */
static config_t config;
/* created history model of flows */
static history_t model;
/* current flow timestamp (seconds) */
static unsigned long actual_timestamp;

bool delete_inactive_flag = false;

static char time_buff[25];

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1)

/**
 * Deletes inactive flows stored in history. Triggered by alarm.
 *
 * @param signum received signal
 */
void mark_deletion(int signum) {
   delete_inactive_flag = true;
   // set next alarm
   alarm(config.del_time);
}

void delete_inactive() {
   delete_inactive_flag = false;

   // iterators
   history_iter iter = model.begin();
   history_iter iterEnd = model.end();

   // loop of erasing
   for ( ; iter != iterEnd; ) {
      if ((actual_timestamp - ur_time_get_sec(iter->second.last_t)) > config.det_window) {
         model.erase(iter++);
      } else {
         ++iter;
      }
   }
}

/**
 * Creates histogram from vector of flows
 *
 * @param flows flow data
 * @param type type of histogram (bytes/packets)
 * @param direction direction of histogram (query/response)
 * @return histogram
 */
histogram_t createHistogram(flow_data_t &flows, int type, int direction) {

   histogram_t histogram;
   histogram_t histogram_q;

   // choose the direction
   if (direction == QUERY) {

      // Create the histogram
      for (vector<flow_item_t>::iterator i = flows.q.begin(); i != flows.q.end(); ++i) {
         // choose base data of histogram
         if (type == PACKETS) {
            ++histogram[i->packets];
         } else if (type == BYTES) {
            ++histogram[i->bytes];
         }
      }

   } else if (direction == RESPONSE) {

   // Create the histogram
      for (vector<flow_item_t>::iterator i = flows.r.begin(); i != flows.r.end(); ++i) {
         if (type == PACKETS) {
            ++histogram[i->packets];
         } else if (type == BYTES) {
            histogram[i->bytes] = histogram[i->bytes]+1;
         }
      }
   }

   // divide by Q according to histogram step
   uint32_t max = config.q;

   for (uint32_t i = 0; i < BYTES_MAX; i+=config.q) {
      for (histogram_iter it = histogram.begin(); it != histogram.end(); ++it) {
         if ((it->first >= i) && (it->first < max)) {
            histogram_q[max] = it->second;
         }
      }
      max += config.q;
   }

   // DEBUG PRINT
   //for (histogram_iter i = histogram_q.begin(); i != histogram_q.end(); ++i) {
   //    printf("!!q! %d : %d \n", i->first, i->second);
   //}

   return histogram_q;
}

/**
 * Creates normalized histogram from histogram
 *
 * @param h input histogram
 * @return normalized histogram
 */
histogram_norm_t normalizeHistogram(histogram_t h) {

   // sum for dividing
   float sum = 0;

   for (histogram_iter it = h.begin(); it != h.end(); it++) {
      sum += it->second;
   }

   histogram_norm_t histogram;

   // create normalized histogram
   for (histogram_iter it = h.begin(); it != h.end(); ++it) {
      histogram[it->first] = it->second / sum;
   }

   // DEBUG PRINT
   //for (histogram_norm_iter i = histogram.begin(); i != histogram.end(); ++i) {
   //    printf(".. %d : %f \n", i->first, i->second);
   //}

   return histogram;
}


/**
 * Takes topN items from histogram
 *
 * @param h input histogram
 * @return topN items as histogram
 */
histogram_t topnHistogram(histogram_t h) {

   histogram_t topn;

   // create vector of pairs from histogram
   vector<pair<unsigned int, unsigned int> > values;

   // fill vector with swapped histogram pairs
   for (histogram_iter it = h.begin(); it != h.end(); ++it) {
      values.push_back(make_pair(it->second, it->first));
   }

   // sort histogram pairs - reversed
   sort(values.rbegin(), values.rend());

   // take only first n items in correct order now
   uint32_t i = 0;
   for (int j = 0; j < config.n; j++) {
      if (i < values.size()) {
         topn[values[i].second] = values[i].first;
         i++;
      }
   }

   return topn;
}


/**
 * Takes topN items from normalized histogram
 *
 * @param h input histogram
 * @return topN items as normalized histogram
 */
histogram_norm_t topnNormHistogram(histogram_norm_t h) {

   histogram_norm_t topn;

   // create vector of pairs from histogram
   vector<pair<float, unsigned int> > values;

   // fill vector with swapped histogram pairs
   for (histogram_norm_iter it = h.begin(); it != h.end(); ++it) {
      values.push_back(make_pair(it->second, it->first));
   }

   // sort histogram pairs - reversed
   sort(values.rbegin(), values.rend());

   // take first n pairs in correct order
   uint32_t i = 0;
   for (int j = 0; j < config.n; j++) {
      if (i < values.size()) {
         topn[values[i].second] = values[i].first;
         i++;
      }
   }

   return topn;
}


/**
 * Calculates sum of value occurence
 *
 * @param h input histogram
 * @param type type of sum - keys or values
 * @return sum
 */
unsigned int sum (histogram_t h, int type) {

   // sum
   unsigned int s = 0;

   for (histogram_iter it = h.begin(); it != h.end(); it++) {

      // choose first or second value of map
      if (type == KEY) {
         s += it->first;
      } else if (type == VALUE) {
         s += it->second;
      }
   }

   return s;
}




/**
 * Calculates sum of value normalized occurence. For sum of KEYs use sum() with correct parameter.
 *
 * @param h input histogram
 * @return sum normalized
 */
float sumN (histogram_norm_t h) {

   // float sum
   float s = 0.0;

   for (histogram_norm_iter it = h.begin(); it != h.end(); ++it) {
      s += it->second;
   }

   return s;
}


/**
 * Calculates average key value
 *
 * @param h input histogram
 * @return average
 */
float sum_average (histogram_t h) {

   // sum and number of items
   unsigned long s = 0;
   unsigned long n = 0;

   for (histogram_iter it = h.begin(); it != h.end(); ++it) {
      s += (it->first * it->second);
      n += it->second;
   }

   // check for returning zero
   if (n == 0)
      return 0;
   else
      return (s/n);
}

/**
 * Calculates maximum packet count in vecotr of given direction
 *
 * @param vec input vector
 * @return maximum packet count
 */
uint32_t max_packets (vector<flow_item_t> &vec) {

   uint32_t max = 0;

   for (vector<flow_item_t>::iterator it = vec.begin(); it != vec.end(); ++it) {
      if (it->packets > max){
         max = it->packets;
      }
   }

   return (max);
}

/**
 * Calculates maximum byte count in vecotr of given direction
 *
 * @param vec input vector
 * @return maximum byte count
 */
uint64_t max_bytes (vector<flow_item_t> &vec) {

   uint64_t max = 0;

   for (vector<flow_item_t>::iterator it = vec.begin(); it != vec.end(); ++it) {
      if (it->bytes > max){
         max = it->bytes;
      }
   }

   return (max);
}

void time2str(ur_time_t t)
{
   time_t sec = ur_time_get_sec(t);
   int msec = ur_time_get_msec(t);
   strftime(time_buff, 25, "%Y-%m-%d %H:%M:%S", gmtime(&sec));
   sprintf(time_buff + 19, ".%03i", msec);
}


/**
 * Main function.
 *
 * @param argc
 * @param argv
 */
int main (int argc, char** argv)
{
   INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);

   int ret;       // return value

   uint32_t unique_id = 0;
   ofstream log;
   ostringstream filename;
   string log_path = "";

   uint16_t src_port;      // actual source port
   uint16_t dst_port;      // actual destination flows
   bool qr;

   // initialize TRAP interface
   TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
   // set signal handling for termination
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // parse parameters
   signed char opt;
   while ((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
      switch (opt) {
         case 'd':
            log_path = optarg;
            break;
         case 'p':
            config.port = atoi(optarg);
            break;
         case 'n':
            config.n = atoi(optarg);
            break;
         case 't':
            config.min_flows = atoi(optarg);
            break;
         case 'q':
            config.q = atoi(optarg);
            break;
         case 'a':
            config.min_a = atoi(optarg);
            break;
         case 'I':
            config.min_flows_norm = atof(optarg);
            break;
         case 'l':
            config.min_resp_bytes = atoi(optarg);
            break;
         case 'y':
            config.min_resp_packets = atoi(optarg);
            break;
         case 'm':
            config.max_quer_bytes = atoi(optarg);
            break;
         case 'w':
            config.det_window = atoi (optarg);
            break;
         case 's':
            config.del_time = atoi (optarg);
            break;
         case 'D':
            config.max_quer_flow_packets = atoi (optarg);
            break;
         case 'E':
            config.max_quer_flow_bytes = atoi (optarg);
            break;
         case 'F':
            config.max_resp_flow_packets = atoi (optarg);
            break;
         case 'G':
            config.max_resp_flow_bytes = atoi (optarg);
            break;
         case 'S':
            config.max_flow_items = atoi (optarg);
            break;
         default:
            cerr <<  "Error: Invalid arguments." << endl;
            trap_finalize();
            FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
            return ERROR;
      }
   }

   if (config.max_flow_items < MINIMAL_RECORD_VECTOR_SIZE){
      cerr << "Error: Wrong record vector(s) settings." << endl;
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return ERROR;
   }

   if (trap_ifcctl(TRAPIFC_INPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_WAIT) != TRAP_E_OK){
      cerr << "Error: Unable to set up intput timeout." << endl;
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return ERROR;
   }

   if (trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_SETTIMEOUT, TRAP_HALFWAIT) != TRAP_E_OK){
      cerr << "Error: Unable set up output timeout." << endl;
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return ERROR;
   }

   // declare demplates
   char * errstr = NULL;
   ur_template_t *unirec_in = ur_create_input_template(0, "SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST", &errstr);
   // check created templates
   if (unirec_in == NULL) {
      cerr << "Error: Invalid UniRec specifier." << endl;
      if(errstr != NULL){
        fprintf(stderr, "%s\n", errstr);
        free(errstr);
      }
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return ERROR;
   }
   ur_template_t* unirec_out = ur_create_output_template(0, "SRC_IP,DST_IP,SRC_PORT,REQ_FLOWS,REQ_PACKETS,REQ_BYTES,RSP_FLOWS,RSP_PACKETS,RSP_BYTES,TIME_FIRST,TIME_LAST,EVENT_ID", &errstr);
   // check created templates
   if (unirec_out == NULL) {
      cerr << "Error: Invalid UniRec specifier." << endl;
      if(errstr != NULL){
        fprintf(stderr, "%s\n", errstr);
        free(errstr);
      }
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS);
      return ERROR;
   }

   // prepare detection record
   void *detection = ur_create_record(unirec_out, 0);
   if (detection == NULL) {
      cerr << "Error: No memory available for detection record. Unable to continue." << endl;
      ur_free_template(unirec_in);
      ur_free_template(unirec_out);
      ur_free_record(detection);
      trap_finalize();
      FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
      return ERROR;
   }


   // set signal for inactive flow deletion
   signal(SIGALRM, mark_deletion);
   alarm(config.del_time);

   // data buffer
   const void *data;
   uint16_t data_size;

   // ***** Main processing loop *****
   while (!stop) {
      // retrieve data from server
      ret = TRAP_RECEIVE(0, data, data_size, unirec_in);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);

      // check the data size
      if ((data_size != ur_rec_fixlen_size(unirec_in))) {
         if (data_size <= 1) { // end of data
            break;
         } else { // data corrupted
            cerr << "ERROR: Wrong data size. Expected: " <<  ur_rec_fixlen_size(unirec_in);
            cerr << ", recieved: " << data_size << "." << endl;
            break;
         }
      }

      // get ports of flow
      src_port = ur_get(unirec_in, data, F_SRC_PORT);
      dst_port = ur_get(unirec_in, data, F_DST_PORT);

      // create actualy inspected key
      flow_key_t actual_key;

      // check if src or dst port is expected, otherwise next flow
      if (dst_port == config.port) {
         qr = BOOL_QUERY;
         actual_key.dst = ur_get(unirec_in, data, F_SRC_IP);
         actual_key.src = ur_get(unirec_in, data, F_DST_IP);
      } else if (src_port == config.port) {
         qr = BOOL_RESPONSE;
         actual_key.src = ur_get(unirec_in, data, F_SRC_IP);
         actual_key.dst = ur_get(unirec_in, data, F_DST_IP);
      } else  {
         continue;
      }

      if (actual_timestamp < ur_time_get_sec(ur_get(unirec_in, data, F_TIME_LAST))){ // since timestamps are not always ordered
         actual_timestamp = ur_time_get_sec(ur_get(unirec_in, data, F_TIME_LAST));
      }

      // iterator through history model
      history_iter it;

      if ((it = model.find(actual_key)) != model.end()) {
         // record exists - update information and add flow
         if (it->second.last_t < ur_get(unirec_in, data, F_TIME_LAST)){
            it->second.last_t = ur_get(unirec_in, data, F_TIME_LAST);
         }

         // create new flow information structure
         flow_item_t i;
         i.t = ur_get(unirec_in, data, F_TIME_FIRST);
         i.bytes = ur_get(unirec_in, data, F_BYTES);
         i.packets = ur_get(unirec_in, data, F_PACKETS);

         // add new flow
         if (qr == BOOL_QUERY){
            it->second.total_bytes[QUERY] += ur_get(unirec_in, data, F_BYTES);
            it->second.total_packets[QUERY] += ur_get(unirec_in, data, F_PACKETS);
            it->second.total_flows[QUERY] += 1;

            if (it->second.q.size() < config.max_flow_items){
               it->second.q.push_back(i);
            } else {
               if (it->second.q_rem_pos == 0){
                  it->second.q.reserve(config.max_flow_items);
               }
               #ifdef COUNTS_WORKING
               it->second.total_bytes[QUERY] -=  it->second.q[it->second.q_rem_pos].bytes;
               it->second.total_packets[QUERY] -=  it->second.q[it->second.q_rem_pos].packets;
               it->second.total_flows[QUERY] -= 1;
               #endif

               it->second.q[it->second.q_rem_pos] = i;
               it->second.q_rem_pos = (it->second.q_rem_pos + 1) % config.max_flow_items;
            }
         } else {
            it->second.total_bytes[RESPONSE] += ur_get(unirec_in, data, F_BYTES);
            it->second.total_packets[RESPONSE] += ur_get(unirec_in, data, F_PACKETS);
            it->second.total_flows[RESPONSE] += 1;

            if (it->second.r.size() < config.max_flow_items){
               it->second.r.push_back(i);
            } else {
               if (it->second.r_rem_pos == 0){
                  it->second.r.reserve(config.max_flow_items);
               }
               #ifdef COUNTS_WORKING
               it->second.total_bytes[RESPONSE] -= it->second.r[it->second.r_rem_pos].bytes;
               it->second.total_packets[RESPONSE] -= it->second.r[it->second.r_rem_pos].packets;
               it->second.total_flows[RESPONSE] -= 1;
               #endif

               it->second.r[it->second.r_rem_pos] = i;
               it->second.r_rem_pos = (it->second.r_rem_pos + 1) % config.max_flow_items;
            }
         }

         long t1 = ur_time_get_sec(ur_get(unirec_in, data, F_TIME_LAST));
         long t2 = ur_time_get_sec(it->second.first_t);
         long t = t1 - t2;
         /// -------------------------------------------------------------------
         /// ---- Detection ---- >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
         // check if detection window for the key is met
         if (t > config.det_window) {
            // create histograms
            histogram_t hvqb, hvqp, hvrb, hvrp;
            histogram_norm_t hvrb_n;
            hvqb = createHistogram(it->second, BYTES, QUERY);
            hvqp = createHistogram(it->second, PACKETS, QUERY);
            hvrb = createHistogram(it->second, BYTES, RESPONSE);
            hvrp = createHistogram(it->second, PACKETS, RESPONSE);

            int report_this = DO_NOT_REPORT;
            //int report_this = NO;

            if (it->second.total_flows[QUERY] && it->second.total_flows[RESPONSE]){
               if (it->second.total_packets[QUERY] >= 30 && (it->second.total_packets[RESPONSE] / it->second.total_packets[QUERY]) >= 5){
                  if (max_packets(it->second.q) > config.max_quer_flow_packets || max_bytes(it->second.r) > config.max_resp_flow_bytes) {
                     //if ( (sum(topnHistogram(hvrb), KEY) / sum(topnHistogram(hvqb), KEY)) > config.min_a ) {
                     if (it->second.r.size() > 0 && it->second.q.size() > 0)
                     if ((max_bytes(it->second.r) / max_bytes(it->second.q)) > config.min_a) {
                        report_this = REPORT_BIG;
                        //report_this = COND1;
                     }
                  }
               } else if ( (sumN(topnNormHistogram(normalizeHistogram(hvrb))) > config.min_flows_norm) && (sum(topnHistogram(hvrb), VALUE) > config.min_flows) ) {
                  if ( (sum_average(topnHistogram(hvrp)) > config.min_resp_packets) && (sum_average(topnHistogram(hvrb)) > config.min_resp_bytes) && (sum_average(topnHistogram(hvqb)) < config.max_quer_bytes) ) {
                     if (sum(topnHistogram(hvqb), BYTES) > 0) {
                        if ( ((sum(topnHistogram(hvrb), KEY) / topnHistogram(hvrb).size()) / (sum(topnHistogram(hvqb), KEY) / topnHistogram(hvqb).size())) > config.min_a ) {
                           report_this = REPORT_COMPLEX;
                           //report_this = COND2;
                        } //if (det. - cond4)
                     } //if (det. - cond3)
                  } //if (det. - cond2)
               } //if (det. - cond1)
            }
            /// Report event >>>
            if (report_this){

               if (it->second.identifier == 0){
                  it->second.identifier = ++unique_id;
               }

               if (report_this == REPORT_COMPLEX){
                  ur_set(unirec_out, detection, F_SRC_IP, it->first.src);
                  ur_set(unirec_out, detection, F_DST_IP, it->first.dst);
                  ur_set(unirec_out, detection, F_SRC_PORT, config.port);
                  ur_set(unirec_out, detection, F_RSP_FLOWS, it->second.total_flows[RESPONSE] - it->second.total_flows[R_REPORTED]);
                  ur_set(unirec_out, detection, F_RSP_PACKETS, it->second.total_packets[RESPONSE] - it->second.total_packets[R_REPORTED]);
                  ur_set(unirec_out, detection, F_RSP_BYTES, it->second.total_bytes[RESPONSE] - it->second.total_bytes[R_REPORTED]);
                  ur_set(unirec_out, detection, F_REQ_FLOWS, it->second.total_flows[QUERY] - it->second.total_flows[Q_REPORTED]);
                  ur_set(unirec_out, detection, F_REQ_PACKETS, it->second.total_packets[QUERY] - it->second.total_packets[Q_REPORTED]);
                  ur_set(unirec_out, detection, F_REQ_BYTES, it->second.total_bytes[QUERY] - it->second.total_bytes[Q_REPORTED]);
                  ur_set(unirec_out, detection, F_TIME_FIRST, it->second.first_t);
                  ur_set(unirec_out, detection, F_TIME_LAST, ur_get(unirec_in, data, F_TIME_LAST));
                  ur_set(unirec_out, detection, F_EVENT_ID, it->second.identifier);

                  // send alert
                  ret = trap_send(0, detection, ur_rec_size(unirec_out, detection));
                  TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, ;, break); // continue normally on timeout
               }

               // LOG QUERY/RESPONSE VECTORS
               size_t pos[2] = {0,0};
               int shorter;
               int longer;
               ur_time_t tmp_t_r = 0;
               ur_time_t tmp_t_q = 0;
               ur_time_t sooner_end;
               ur_time_t later_end;
               for (vector<flow_item_t>::iterator it_end = it->second.q.begin(); it_end != it->second.q.end(); ++it_end) {
                  if (it_end->t > tmp_t_q) {
                     tmp_t_q = it_end->t;
                  }
               }
               for (vector<flow_item_t>::iterator it_end  = it->second.r.begin(); it_end  != it->second.r.end(); ++it_end ) {
                  if (it_end ->t > tmp_t_r) {
                     tmp_t_r = it_end ->t;
                  }
               }

               if (tmp_t_r < tmp_t_q){
                  shorter = RESPONSE;
                  longer = QUERY;
                  sooner_end = it->second.r.size();
                  later_end = it->second.q.size();
               } else {
                  shorter = QUERY;
                  longer = RESPONSE;
                  sooner_end = it->second.q.size();
                  later_end = it->second.r.size();
               }

               char addr_buff[INET6_ADDRSTRLEN];
               if (log_path.compare("") != 0) {
                  filename.str("");
                  filename.clear();
                  filename << log_path;
                  if (report_this == REPORT_BIG){
                     filename << "BIG/";
                  }
                  ip_to_str(&actual_key.src, addr_buff);
                  filename << LOG_FILE_PREFIX << addr_buff;
                  ip_to_str(&actual_key.dst, addr_buff);
                  filename << "-" << addr_buff << LOG_FILE_SUFFIX;

                  log.open(filename.str().c_str(), ofstream::app);

                  if (log.is_open()){
                     ip_to_str(&actual_key.src, addr_buff);
                     log << "Abused server IP: " << addr_buff;
                     ip_to_str(&actual_key.dst, addr_buff);
                     log << "   Target IP: " << addr_buff << "\n";
                     while (pos[shorter] < sooner_end){
                        if (it->second.q[pos[QUERY]].t <= it->second.r[pos[RESPONSE]].t) {
                           time2str(it->second.q[pos[QUERY]].t);
                           log << time_buff << "\tQ\t" << it->second.q[pos[QUERY]].packets << "\t" << it->second.q[pos[QUERY]].bytes << endl;
                           ++pos[QUERY];
                        } else {
                           time2str(it->second.r[pos[RESPONSE]].t);
                           log << time_buff << "\tR\t" << it->second.r[pos[RESPONSE]].packets << "\t" << it->second.r[pos[RESPONSE]].bytes << endl;
                           ++pos[RESPONSE];
                        }
                     }
                     for (pos[longer] = pos[shorter]; pos[longer] < later_end; ++pos[longer]) {
                        if (longer == QUERY){
                           time2str(it->second.q[pos[QUERY]].t);
                           log << time_buff << "\tQ\t" << it->second.q[pos[QUERY]].packets << "\t" << it->second.q[pos[QUERY]].bytes << endl;
                        } else {
                           time2str(it->second.r[pos[RESPONSE]].t);
                           log << time_buff << "\tR\t" << it->second.r[pos[RESPONSE]].packets << "\t" << it->second.r[pos[RESPONSE]].bytes << endl;
                        }
                     }
                     log.close();
                  } else {
                     cerr << "Error: Cannot open log file [" << filename.str() << "]." << endl;
                  }
               }
            }
            /// Report event <<<
            /// DELETION OF WINDOW
            // delete flows from queries
            for (vector<flow_item_t>::iterator del = it->second.q.begin(); del != it->second.q.end(); ) {
               //F_TIME_LAST is used since F_TIME_FIRST could be occasionally more in past
               if ((ur_time_get_sec(ur_get(unirec_in, data, F_TIME_LAST)) - ur_time_get_sec(del->t)) > (config.det_window - config.del_time)) {
                  del = it->second.q.erase(del);
                  it->second.q_rem_pos = 0;
               } else {
                  ++del;
               }
            }

            // delete flows from responses
            for (vector<flow_item_t>::iterator del = it->second.r.begin(); del != it->second.r.end(); ) {
               //F_TIME_LAST is used since F_TIME_FIRST could be occasionally more in past
               if ((ur_time_get_sec(ur_get(unirec_in, data, F_TIME_LAST)) - ur_time_get_sec(del->t)) > (config.det_window - config.del_time)) {
                  del = it->second.r.erase(del);
                  it->second.r_rem_pos = 0;
               } else {
                  ++del;
               }
            }

            if (it->second.r.empty() && it->second.q.empty()){
               model.erase(it);
            } else {
               // determine new first time of key was spotted
               ur_time_t min_time = ur_get(unirec_in, data, F_TIME_FIRST);

               it->second.total_bytes[QUERY] = 0;
               it->second.total_packets[QUERY] = 0;
               it->second.total_flows[QUERY] = 0;
               for (vector<flow_item_t>::iterator it_min = it->second.q.begin(); it_min != it->second.q.end(); it_min++) {
                  it->second.total_bytes[QUERY] += it_min->bytes;
                  it->second.total_packets[QUERY] += it_min->packets;
                  it->second.total_flows[QUERY] += 1;
                  if (it_min->t < min_time) {
                     min_time = it_min->t;
                  }
               }

               it->second.total_bytes[RESPONSE] = 0;
               it->second.total_packets[RESPONSE] = 0;
               it->second.total_flows[RESPONSE] = 0;
               for (vector<flow_item_t>::iterator it_min = it->second.r.begin(); it_min != it->second.r.end(); it_min++) {
                  it->second.total_bytes[RESPONSE] += it_min->bytes;
                  it->second.total_packets[RESPONSE] += it_min->packets;
                  it->second.total_flows[RESPONSE] += 1;
                  if (it_min->t < min_time) {
                     min_time = it_min->t;
                  }
               }

               it->second.first_t = min_time;

               // store counters for data, which was reported and which is still in history
               it->second.total_bytes[Q_REPORTED] = it->second.total_bytes[QUERY];
               it->second.total_packets[Q_REPORTED] = it->second.total_packets[QUERY];
               it->second.total_flows[Q_REPORTED] = it->second.total_flows[QUERY];

               // store counters for data, which was reported and which is still in history
               it->second.total_bytes[R_REPORTED] = it->second.total_bytes[RESPONSE];
               it->second.total_packets[R_REPORTED] = it->second.total_packets[RESPONSE];
               it->second.total_flows[R_REPORTED] = it->second.total_flows[RESPONSE];
            }
         } //if (time > detection_window)
         /// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<---- Detection ----
         /// -------------------------------------------------------------------
      } else { // does not exist - create new one
         // create flow data structure and fill it
         flow_data_t d;

         d.first_t = ur_get(unirec_in, data, F_TIME_FIRST);
         d.last_t = ur_get(unirec_in, data, F_TIME_LAST);
         d.last_logged = 0;
         d.identifier = 0;
         d.q_rem_pos = 0;
         d.r_rem_pos = 0;

         // create flow item
         flow_item_t i;
         i.t = ur_get(unirec_in, data, F_TIME_FIRST);
         i.bytes = ur_get(unirec_in, data, F_BYTES);
         i.packets = ur_get(unirec_in, data, F_PACKETS);

         // add flow item
         if (qr == BOOL_RESPONSE) {
            d.total_bytes[RESPONSE] = ur_get(unirec_in, data, F_BYTES);
            d.total_packets[RESPONSE] = ur_get(unirec_in, data, F_PACKETS);
            d.total_flows[RESPONSE] = 1;
            d.total_bytes[QUERY] = 0;
            d.total_packets[QUERY] = 0;
            d.total_flows[QUERY] = 0;

            d.r.push_back(i);
         } else {
            d.total_bytes[QUERY] = ur_get(unirec_in, data, F_BYTES);
            d.total_packets[QUERY] = ur_get(unirec_in, data, F_PACKETS);
            d.total_flows[QUERY] = 1;
            d.total_bytes[RESPONSE] = 0;
            d.total_packets[RESPONSE] = 0;
            d.total_flows[RESPONSE] = 0;

            d.q.push_back(i);
         }
         d.total_bytes[Q_REPORTED] = 0;
         d.total_packets[Q_REPORTED] = 0;
         d.total_flows[Q_REPORTED] = 0;
         d.total_bytes[R_REPORTED] = 0;
         d.total_packets[R_REPORTED] = 0;
         d.total_flows[R_REPORTED] = 0;


         // assign key to history model
         model[actual_key] = d;
      }

      if (delete_inactive_flag){
         delete_inactive();
      }
   }

   // send terminate message
   ret  = trap_send(0, data, 1);
   TRAP_DEFAULT_SEND_ERROR_HANDLING(ret, ;, ;);

   // clean up before termination
   ur_free_template(unirec_in);
   ur_free_template(unirec_out);
   ur_free_record(detection);

   trap_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
   return OK;
}
