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
    "   -p <port>        port used for detection (53)\n"
    "   -n <num>         number of topN values chosen (10)\n"
    "   -q <step>        step of histogram (10)\n"
    "   -a <num>         minimal amplification effect considered an attack (5)\n"
    "   -t <num>         minimal threshold for number of flows in TOP-N (1000)\n"
    "   -i <num>         minimal normalized threshold for count of flows in TOP-N (0.4)\n"
    "   -y <num>         minimal threshold for average size of responses in packets in TOP-N (0)\n"
    "   -l <num>         minimal threshold for average size of responses in bytes in TOP-N (1000)\n"
    "   -m <num>         maximal threshold for average size of queries in bytes in TOP-N (300)\n"
    "   -w <sec>         time window of detection / timeout of inactive flow (3600)\n"
    "   -s <sec>         time window of deletion / period of inactive flows checking(300)\n",
    1, // Number of input interfaces
    1, // Number of output interfaces
};

static int stop = 0;

/* configuration structure */
static config_t config;
/* created history model of flows */
static history_t model;
/* actual flow timestamp  */
static ur_time_t actual_timestamp;


TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);


/**
 * Deletes inactive flows stored in history. Triggered by alarm.
 *
 * @param signum received signal
 */
void delete_inactive(int signum) {

	// iterators
	history_iter iter = model.begin();
	history_iter iterEnd = model.end();

	// loop of erasing
	for ( ; iter != iterEnd; ) {

		if (((long)actual_timestamp - (long)iter->second.last_t) > config.det_window) {
			model.erase(iter++);
		} else {
			++iter;
		}
	}

	// set next alarm
	alarm(config.del_time);
}


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
	int max = config.q;

	for (int i = 0; i < BYTES_MAX; i+=config.q) {
		for (histogram_iter it = histogram.begin(); it != histogram.end(); ++it) {
			if ((it->first >= i) && (it->first < max)) {
				histogram_q[max] = it->second;
			}
		}
		max += config.q;
	}

	// DEBUG PRINT
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

	// DEBUG PRINT
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

	// create vector of pairs from histogram
	vector<pair<float, unsigned int> > values;

	// fill vector with swapped histogram pairs
	for (histogram_norm_iter it = h.begin(); it != h.end(); ++it) {
		values.push_back(make_pair(it->second, it->first));
	}

	// sort histogram pairs - reversed
	sort(values.rbegin(), values.rend());

	// take first n pairs in correct order
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
 * Main function.
 *
 * @param argc
 * @param argv
 */
int main (int argc, char** argv) {

	int ret;			// return value

	uint16_t src_port;		// actual source port
	uint16_t dst_port;		// actual destination flows
	bool qr;			// query=false, response=true

	// initialize TRAP interface
	TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
	// set signal handling for termination
	TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

	// parse parameters
	char opt;
	while ((opt = getopt(argc, argv, "p:n:t:q:a:I:l:y:m:w:s:")) != -1) {
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
			default:
				fprintf(stderr, "Invalid arguments.\n");
				return ERROR;
		}
	}

	// set signal for inactive flow deletion
	signal(SIGALRM, delete_inactive);
	alarm(config.del_time);

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

	actual_timestamp = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));

	// iterator through history model
	history_iter it;

	if ((it = model.find(actual_key)) != model.end()) {

		// record exists - update information and add flow

		it->second.total_bytes += ur_get(unirec_in, data, UR_BYTES);
		it->second.total_packets += ur_get(unirec_in, data, UR_PACKETS);
		it->second.last_t = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));

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

		long t1 = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));
		long t2 = it->second.first_t;
		long t = t1 - t2;

		// check if detection window for the key is met
		if (t > config.det_window) {

			// create histograms
			histogram_t hvqb, hvqp, hvrb, hvrp;
			histogram_norm_t hvrb_n;
			hvqb = createHistogram(it->second, BYTES, QUERY);
			hvqp = createHistogram(it->second, PACKETS, QUERY);
			hvrb = createHistogram(it->second, BYTES, RESPONSE);
			hvrp = createHistogram(it->second, PACKETS, RESPONSE);

			//printf("!1! %f %f %d %d\n", sumN(topnNormHistogram(normalizeHistogram(hvrb))), config.min_flows_norm, sum(topnHistogram(hvrb), VALUE),config.min_flows);

			// detection algorithm
			if ( (sumN(topnNormHistogram(normalizeHistogram(hvrb))) > config.min_flows_norm) && (sum(topnHistogram(hvrb), VALUE) > config.min_flows) ) {

				//printf("!2! %f %d %f %d %f %d\n", sum_average(topnHistogram(hvrp)), config.min_flows, sum_average(topnHistogram(hvrb)),config.min_resp_bytes, sum_average(topnHistogram(hvqb)),config.max_quer_bytes);

				if ( (sum_average(topnHistogram(hvrp)) > config.min_resp_packets) && (sum_average(topnHistogram(hvrb)) > config.min_resp_bytes) && (sum_average(topnHistogram(hvqb)) < config.max_quer_bytes) ) {

					//cout << "!3! " << sum(topnHistogram(hvrb), KEY) << " " << sum(topnHistogram(hvqb), KEY) << " " << config.min_a << endl;

					if (sum(topnHistogram(hvqb), BYTES) > 0) {

						if ( (sum(topnHistogram(hvrb), KEY) / sum(topnHistogram(hvqb), KEY)) > config.min_a ) {

							//send(<AMPLIFICATION_ALERT>);

							//cout << "!4!" << endl;

							// set detection alert template fields
							ur_set(unirec_out, detection, UR_SRC_IP, it->first.src);
							ur_set(unirec_out, detection, UR_DST_IP, it->first.dst);
							ur_set(unirec_out, detection, UR_SRC_PORT, config.port);
							ur_set(unirec_out, detection, UR_FLOWS, (it->second.q.size()+it->second.r.size()));
							ur_set(unirec_out, detection, UR_PACKETS, it->second.total_packets);
							ur_set(unirec_out, detection, UR_BYTES, it->second.total_bytes);
							ur_set(unirec_out, detection, UR_TIME_FIRST, ur_time_from_sec_msec(it->second.first_t, 0));
							ur_set(unirec_out, detection, UR_TIME_LAST, ur_get(unirec_in, data, UR_TIME_FIRST));

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
					del = it->second.q.erase(del);
				} else {
					++del;
				}
			}

			// delete flows from responses
			for (vector<flow_item_t>::iterator del = it->second.r.begin(); del != it->second.r.end(); ) {

				if ((ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST)) - del->t) > (config.det_window - config.del_time)) {
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
			d.last_t = ur_time_get_sec(ur_get(unirec_in, data, UR_TIME_FIRST));

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
