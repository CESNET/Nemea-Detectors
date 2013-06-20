/**
 * \file spoofing.cpp
 * \brief IP spoofing detector for Nemea
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdint.h>
#include <signal.h>
#include <libtrap/trap.h>
#include "../unirec.h"
#include "../ipaddr.h"
#include "spoofing.h"

using namespace std;

/**
 * Filter for checking ip for bogon prefixes
 * @param analyzed Record that's being analyzed
 * @return SPOOF_POSITIVE if address fits the bogon prefix else SPOOF_NEGATIVE
 */

static int stop = 0;

void signal_handler(int signal)
{
    if (signal == SIGTERM || signal == SIGINT) {
        stop = 1;
        trap_terminate();
    }
}

int load_pref (pref_list_t& prefix_list)
{
    ip_prefix_t *pref;
    ifstream pref_file;
    char linebuf[INET6_ADDRSTRLEN];

    pref_file.open("adr.txt", fstream::in);

    if (!pref_file.is_open()) {
        cerr << "File with bogon prefixes couldn't be loaded. Unable to continue." << endl;
        return 1;
    }

    while (pref_file.good()) {
        pref = new ip_prefix_t;
        pref_file.getline(linebuf, 33, '/');
        string raw_ip = string(linebuf);
        
        ip_from_str(raw_ip.c_str(), &(pref->ip));

        cout <<  raw_ip;
        cout << " --> ";
        cout << ip_get_v4_as_int(&(pref->ip)) << endl;        
        
        pref_file.getline(linebuf,4, '\n');
        pref->pref_length = atoi(linebuf);
    }
    return 0;
}


int bogon_filter(ur_basic_flow_t *analyzed)
{
    //load file with bogon prefixes
    //check source address of the record with each prefix
//    if  fits the bogon prefix
//        return SPOOF_POSITIVE;
//    else
        return SPOOF_NEGATIVE;
}
int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec;

    ur_basic_flow_t *record;

    pref_list_t  bogon_list;
    // Initialize TRAP library (create and init all interfaces)
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP initialization failed: ";
        cerr <<  trap_last_error_msg << endl;
    }
    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    // ***** Main processing loop *****
    while (!stop) {
        const void *data;
        uint16_t data_size;

        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) {
                break;
            } else {
                cerr << "ERROR: Unable to get data. Return value " + retval;
                cerr << " (";
                cerr <<  trap_last_error_msg;
                cerr << ")" << endl;
                break;
            }
        }

    // Interpret data as unirec flow record
    record = (ur_basic_flow_t *) data;

    //go through all filters

    // ***** 1. bogon prefix filter *****
    // we don't have list of bogon prefixes loaded (usually first run)
    if (bogon_list.empty()) {
        load_pref(bogon_list);
    }

    retval = bogon_filter(record, bogon_list);
    if (retval == SPOOF_POSITIVE) {
        cout << "Spoofed address found." << endl;
    }
    //2. symetric routing filter
    //3. asymetric routing filter (will be implemented later)
    //4. new flow count check


    //return spoofed or not
    }
}
