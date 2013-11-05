/**
 * \file dns_amplification.cpp
 * \brief Nemea module for detection of DNS amplification attacks based on NetFlow
 * \author Michal Kovacik <ikovacik@fit.vutbr.cz>#
 * \date 25.10.2013
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
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <algorithm>
#include <list>
#include <map>
#include <utility>
#include <algorithm>

#ifdef __cplusplus
extern "C" {   
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif
#include "../../unirec/unirec.h"
#include "../../unirec/ipaddr.h"
#include "dns_amplification.h"

using namespace std;

trap_module_info_t module_info = {
    (char *) "NetFlow DNS Amplification detection module", // Module name
    // Module description
    (char *) "This module detects DNS Amplification attacks from NetFlow data\n"
    "It is based on the flow's analysis of incoming and outgoing packets and bytes.\n"
    "Detection is triggered always when certain time window of src and dst ip is collected.\n"
    "Interfaces:\n"
    "   Inputs: 1 (UniRec record -- <COLLECTOR_FLOW)\n"
    "   Outputs: 1 (UniRec record -- <AMPLIFICATION_ALERT)\n"
    "Additional parameters:\n"
    "   -p <port>    	 port used for detection (53)\n"
    "   -n <num>    	 number of topN values chosen (10)\n"
    "   -q <step>        step of histogram (10)\n"
    "   -a <num>         minimal amplification effect considered an attack (5)\n"
    "   -t <num>         minimal threshold for number of flows in TOP-N (1000)\n"
    "   -i <num>         minimal normalized threshold for count of flows in TOP-N (0.4)\n"
    "   -y <num>         minimal threshold for average size of responses in packets in TOP-N (0)\n"
    "   -l <num>         minimal threshold for average size of responses in bytes in TOP-N (1000)\n"
    "   -m <num>         maximal threshold for average size of queries in bytes in TOP-N (300)\n"
    "   -h <sec>         time window of detection (3600)\n"
    "   -s <sec>         time window of deletion (300)\n",
    1, // Number of input interfaces
    1, // Number of output interfaces
};

static int stop = 0;
/* configuration structure */
static config_t config;

TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * Creates histogram from vector of flows
 *
 * @param flows flow data
 * @param type type of histogram (bytes/packets)
 * @param direction direction of histogram (query/response)
 * @return histogram
 */
histogram_t createHistogram(flow_data_t flows, int type, int direction) {
    
    histogram_t histogram;
    histogram_t histogram_q;

    // choose the direction
    if (direction == QUERY) {

        // Create the histogram
	for (vector<flow_item_t>::iterator i = flows.q.begin(); i != flows.q.end(); ++i) {
	      // choose base data of histogram
	      if (type == PACKETS) {
		  ++histogram[i->packets];
		  }
	      else if (type == BYTES) {
		  histogram[i->bytes] = histogram[i->bytes]+1;
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
    int max = config.q;
	
    for (int i = 0; i < BYTES_MAX; i+=config.q) {
	for (histogram_iter it = histogram.begin(); it != histogram.end(); ++it) {
	    if ((it->first >= i) && (it->first < max)) {
		histogram_q[max] = it->second;
		}
	}
	max += config.q;
    }
    
    // DEBUG
    //for (histogram_iter i = histogram_q.begin(); i != histogram_q.end(); ++i) {
    //		printf("!!q! %d : %d \n", i->first, i->second);
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

    // DEBUG
    //for (histogram_norm_iter i = histogram.begin(); i != histogram.end(); ++i) {
    //		printf(".. %d : %f \n", i->first, i->second);
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

    histogram_t tmp, topn;
    
    // swap histogram pairs to sort them
    vector<pair<unsigned int, unsigned int> > values;
    for (histogram_iter it = h.begin(); it != h.end(); ++it) {
	values.push_back(make_pair(it->second, it->first));
    }
    
    sort(values.rbegin(), values.rend());
    
    // take only n items
    int i = 0;
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
    map<float, unsigned int> tmp;
    
    // swap pairs
    for (histogram_norm_iter it = h.begin(); it != h.end(); ++it) {
	tmp[it->second] = it->first;
    }
    
    // take n pairs
    map<float, unsigned int>::iterator it = tmp.begin();
    for (int i = 0; i < config.n; i++) {
	if (it != tmp.end()) {
	    topn[it->second] = it->first;
	    it++;
	}
    }
        
    return topn;
}


/**
 * Calculates sum of value occurence
 *
 * @param h input histogram
 * @return sum
 */
unsigned int sum (histogram_t h, int type) {
	
	unsigned int s = 0;
	
	for (histogram_iter it = h.begin(); it != h.end(); it++) {
	    if (type == BYTES) {
		s += it->first;
	    } else if (type == PACKETS) {
		s += it->second;
	    }
	}

	return s;
}


/**
 * Calculates sum of value normalized occurence
 *
 * @param h input histogram
 * @return sum normalized
 */
float sumN (histogram_norm_t h) {
	
	
	float s = 0.0;
	
	for (histogram_norm_iter it = h.begin(); it != h.end(); ++it) {
	    s += it->second;
	}

	return s;
}


/**
 * Calculates sum of values
 *
 * @param h input histogram
 * @return sum of values
 */
unsigned int sumv (histogram_t h) {
	
	unsigned int s = 0;
	
	for (histogram_iter it = h.begin(); it != h.end(); ++it) {
	    s += it->first;
	}

	return s;
}


/**
 * Calculates average value
 *
 * @param h input histogram
 * @return average
 */
float sum_average (histogram_t h) {
	
	
	unsigned int s = 0;
	unsigned int n = 0;
	
	for (histogram_iter it = h.begin(); it != h.end(); ++it) {
	    s += it->first;
	    n++;
	}
	
	if (n == 0)
	    return 0;
	else
	    return (s/n);
}

/*
 * MAIN FUNCTION
 */
int main (int argc, char** argv)
{
   int ret;
  
   history_t model;		// created history model of flows
   uint16_t src_port;		// actual source port
   uint16_t dst_port;		// actual destination flows
   bool qr;			// query=false, response=true
   
   // initialize TRAP interface
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   // set signal handling for termination
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   
   // initialize configuration structure
   config.port = 53;
   config.n = 10;
   config.q = 10;
   config.min_flows = 1000;
   config.min_flows_norm = 0.4;
   config.min_resp_packets = 0;
   config.min_resp_bytes = 1000;
   config.max_quer_bytes = 300;
   config.min_a = 5;
   config.det_window = 3600;
   config.del_time = 300;
  
   // parse parameters
   char opt;
   while ((opt = getopt(argc, argv, "p:n:t:q:a:i:l:m:h:s:")) != -1) {
      switch (opt) {
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
	case 'i':
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
        case 'h':
	    config.det_window = atoi (optarg);
	    break;
        case 's':
	    config.del_time = atoi (optarg);
	    break;
        default:
            fprintf(stderr, "Invalid arguments.\n");
            return 3;
      }
   }
   
   // declare demplates
   ur_template_t *unirec_in = ur_create_template("<COLLECTOR_FLOW>");
   ur_template_t* unirec_out = ur_create_template("<AMPLIFICATION_ALERT>");
   
   // check created templates
   if ((unirec_in == NULL) || (unirec_out == NULL)) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return ERROR;
   }

   // prepare detection record
   void *detection = ur_create(unirec_out, 0);
   if (detection == NULL) {
        fprintf(stderr,"ERROR: No memory available for detection record. Unable to continue.\n");
        ur_free_template(unirec_in);
        ur_free_template(unirec_out);
        ur_free(detection);
        return ERROR;
   }
   
   // data buffer
   const void *data;
   uint16_t data_size;
 
    // ***** Main processing loop *****
   while (!stop) {
               
        // retrieve data from server
        ret = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

        // check the data size
        if ((data_size != ur_rec_static_size(unirec_in))) {
            if (data_size <= 1) { // end of data
                break;
            } else { // data corrupted
                fprintf(stderr, "ERROR: Wrong data size. Expected: %lu Recieved: %lu.", ur_rec_static_size(unirec_in), data_size);
                break;
            }
        }        
        
        // get ports of flow
        src_port = ur_get(unirec_in, data, UR_SRC_PORT); 
	dst_port = ur_get(unirec_in, data, UR_DST_PORT);
	
	// create actualy inspected key
        flow_key_t actual_key;
	
        // check if src or dst port is expected, otherwise next flow
        if (src_port == config.port) {
	    qr = true;
	    actual_key.src = ur_get(unirec_in, data, UR_SRC_IP);
    	    actual_key.dst = ur_get(unirec_in, data, UR_DST_IP);
	} else if (dst_port == config.port) { 
	    qr = false;
	    actual_key.dst = ur_get(unirec_in, data, UR_SRC_IP);
    	    actual_key.src = ur_get(unirec_in, data, UR_DST_IP);
	} else {
	    continue;
        }
        
        //char ip1[INET6_ADDRSTRLEN];
        //char ip2[INET6_ADDRSTRLEN];
        //char ip3[INET6_ADDRSTRLEN] = "147.229.2.221";
        //char ip4[INET6_ADDRSTRLEN] = "77.66.30.195";
        //bool flag = false;
        //ip_to_str(&actual_key.src, ip1);
        //ip_to_str(&actual_key.dst, ip2);

        //if ((strcmp(ip1, ip3) == 0) && (strcmp(ip2, ip4) == 0)) { 
            //cout << "SOURCE " <<  ip1 << " " << " " <<endl;
    	//    cout.flush();
    	//    flag = true;
    	//    flagg = true;
    	//} else if (strcmp(ip2, ip4) == 0) {
    	    //cout << "DESTINATION " << ip2 << endl;
    	//    cout.flush();
    	    //flag = true;
    	//}
	
	// iterate through history
	history_iter it;
	if ((it = model.find(actual_key)) != model.end()) {
	    
	    // record exists - update information and add flow

	    it->second.total_bytes += ur_get(unirec_in, data, UR_BYTES);
	    it->second.total_packets += ur_get(unirec_in, data, UR_PACKETS);
	    
	    // creeate new flow information structure
	    flow_item_t i;
	    i.t = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));
	    i.bytes = ur_get(unirec_in, data, UR_BYTES);
	    i.packets = ur_get(unirec_in, data, UR_PACKETS);
	    
	    // add new flow
	    if (qr)
	      it->second.r.push_back(i);
	    else
	      it->second.q.push_back(i);
	    
	    // check if detection window for the key is met
	    if ((ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST)) - it->second.first_t) > config.det_window) {
		
		// DETECTION PROCESS
		//if (flag) 
		//    cout << "det " << ip1 << " " << ip2 << " ";
		    
		// create histograms
		histogram_t hvqb, hvqp, hvrb, hvrp;
		histogram_norm_t hvrb_n;
		hvqb = createHistogram(it->second, BYTES, QUERY);
		hvqp = createHistogram(it->second, PACKETS, QUERY);
		hvrb = createHistogram(it->second, BYTES, RESPONSE);
		hvrp = createHistogram(it->second, PACKETS, RESPONSE);
		
		//if (flag) 
		//    printf("!1! %f %f %d %d\n", sumN(topnNormHistogram(normalizeHistogram(hvrb))), config.min_flows_norm, sum(topnHistogram(hvrb), BYTES),config.min_flows);
		
		// detection algorithm
		if ( (sumN(topnNormHistogram(normalizeHistogram(hvrb))) > config.min_flows_norm) && (sum(topnHistogram(hvrb), BYTES) > config.min_flows) ) {
		
		//    if (flag) 
		//	printf("!2! %f %d %f %d %f %d\n", sum_average(topnHistogram(hvrp)), config.min_flows, sum_average(topnHistogram(hvrb)),config.min_resp_bytes, sum_average(topnHistogram(hvqb)),config.max_quer_bytes);
		
		    if ( (sum_average(topnHistogram(hvrp)) > config.min_resp_packets) && (sum_average(topnHistogram(hvrb)) > config.min_resp_bytes) && (sum_average(topnHistogram(hvqb)) < config.max_quer_bytes) ) {
			
		//	if (flag) 
		//	    cout << "!3! " << sum(topnHistogram(hvrb), BYTES) << " " << sum(topnHistogram(hvqb), BYTES) << " " << config.min_a << endl;
			
			if (sum(topnHistogram(hvqb), BYTES) > 0) {
				if ( (sum(topnHistogram(hvrb), BYTES) / sum(topnHistogram(hvqb), BYTES)) > config.min_a ) {
					//send(<AMPLIFICATION_ALERT>);
		//			if (flag) 
		//			    cout << "!4!" << endl;
		//			cout.flush();
					
					// set detection alert template fields
					ur_set(unirec_out, detection, UR_SRC_IP, ur_get(unirec_in, data, UR_SRC_IP));
					ur_set(unirec_out, detection, UR_DST_IP, ur_get(unirec_in, data, UR_DST_IP));
					ur_set(unirec_out, detection, UR_SRC_PORT, config.port);
					ur_set(unirec_out, detection, UR_FLOWS, (it->second.q.size()+it->second.r.size()));
					ur_set(unirec_out, detection, UR_PACKETS, it->second.total_packets);
					ur_set(unirec_out, detection, UR_BYTES, it->second.total_bytes);
					ur_set(unirec_out, detection, UR_TIME_FIRST, it->second.first_t);
					ur_set(unirec_out, detection, UR_TIME_LAST, ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST)));
					
					// send alert
					trap_send_data(0, detection, ur_rec_size(unirec_out, detection), TRAP_HALFWAIT);
				}
			}
		    }
		}
		
		// DELETION OF WINDOW
		
		// delete flows from queries
		for (vector<flow_item_t>::iterator del = it->second.q.begin(); del != it->second.q.end(); ) {
		
			if ((ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST)) - del->t) > (config.det_window - config.del_time)) {
				it->second.total_bytes -= del->bytes;
				it->second.total_packets -= del->packets;
				del = it->second.q.erase(del);
			} else {
				++del;
			}
		}
		
		
		// delete flows from responses
		for (vector<flow_item_t>::iterator del = it->second.r.begin(); del != it->second.r.end(); ) {
		
			
			if ((ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST)) - del->t) > (config.det_window - config.del_time)) {
				
				it->second.total_bytes -= del->bytes;
				it->second.total_packets -= del->packets;
				del = it->second.r.erase(del);
			} else {
				++del;
			}
		}
		
		// determine new first time of key was spotted
		ur_time_t min_time = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));
		
		for (vector<flow_item_t>::iterator del = it->second.q.begin(); del != it->second.q.end(); del++) {
		
			if (del->t < min_time) {
				min_time = del->t;
			}
		}
		
		
		for (vector<flow_item_t>::iterator del = it->second.r.begin(); del != it->second.r.end(); del++) {
		
			if (del->t < min_time) {
				min_time = del->t;
			}
		}
		
		it->second.first_t = min_time;
		
	    }
	
	} else {	// does not exist - create new one
	    
	    // create flow data structure and fill it
	    flow_data_t d;

	    d.total_bytes = ur_get(unirec_in, data, UR_BYTES);
	    d.total_packets = ur_get(unirec_in, data, UR_PACKETS);
	    d.first_t = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));
	    
	    // create flow item
	    flow_item_t i;
	    i.t = d.first_t;
	    i.bytes = d.total_bytes;
	    i.packets = d.total_packets;
	    
	    // add flow item
	    if (qr) {
	      d.r.push_back(i);
	    } else {
	      d.q.push_back(i);
	    }
	    // assign key to history model
	    model[actual_key] = d;

	}
   }

   // send terminate message
   trap_send_data(0, data, 1, TRAP_HALFWAIT);

   // clean up before termination
   ur_free_template(unirec_in);
   ur_free_template(unirec_out);
   ur_free(detection);

   trap_finalize();

   return OK;
}   
