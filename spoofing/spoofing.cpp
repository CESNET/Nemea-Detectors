/**
 * \file spoofing.cpp
 * \brief IP spoofing detector for Nemea
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <string>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdint.h>
#include <signal.h>
#ifdef __cplusplus
extern "C" {
#endif
#include <libtrap/trap.h>
#ifdef __cplusplus
}
#endif
#include "../unirec.h"
#include "../ipaddr.h"
#include "spoofing.h"

using namespace std;


trap_module_info_t module_info = {
    "Flow-counter module", // Module name
    // Module description
    "Example module for counting number of incoming flow records.\n"
    "Interfaces:\n"
    "   Inputs: 1 (ur_basic_flow)\n"
    "   Outputs: 0\n",
    1, // Number of input interfaces
    0, // Number of output interfaces
};


static int stop = 0;

/**
 * Procedure for handling signals SIGTERM and SIGINT (Ctrl-C)
 */
void signal_handler(int signal)
{
    if (signal == SIGTERM || signal == SIGINT) {
        stop = 1;
        trap_terminate();
    }
}
/**
 * Function for creating masks for IPv4 addresses.
 * Function fills the given array with every possible netmask for IPv4 address.
 * Size of this array is 33 items (see header file)
 *
 * @param m Array to be filled
 */
void create_v4_mask_map(ipv4_mask_map_t& m)
{
    m[0] = 0x00000000; // explicitly inserted or else it will be 0xFFFFFFFF
    for (int i = 1; i <= 32; i++) {
        m[i] = (0xFFFFFFFF << (32 - i));
    }
}

void create_v6_mask_map(ipv6_mask_map_t& m)
{
    m[0][0] = m[0][1] = 0;

    for (int i = 1; i <= 128; i++) {
        if (i < 64) {
            m[i][0] = 0xFFFFFFFFFFFFFFFF << (64 - i);
            m[i][1] = 0x0;
        } else {
            m[i][0] = 0xFFFFFFFFFFFFFFFF;
            m[i][1] = 0xFFFFFFFFFFFFFFFF << (64 - i);
        }
    }
}


/**
 * Function for loading prefix file.
 * Function reads file with network prefixes and creates a vector for use
 * filters. This function should be called only once, since loading 
 * prefixes is needed only on "cold start of the detector" or if we want to 
 * teach the detector new file. (Possile changes to get signal for loading).
 *
 * @param prefix_list Reference to a structure for containing all prefixes
 * @return 0 if everything goes smoothly else 1
 *
 */
int load_pref (pref_list_t& prefix_list)
{
    ip_prefix_t *pref;
    ifstream pref_file;
    char linebuf[INET6_ADDRSTRLEN];

    pref_file.open("bogons.txt");

    if (!pref_file.is_open()) {
        cerr << "ERROR: File with bogon prefixes couldn't be loaded. Unable to continue." << endl;
        return 1;
    }

    while (pref_file.good()) {
        pref = new ip_prefix_t;
        
        pref_file.getline(linebuf, INET6_ADDRSTRLEN, '/');
        string raw_ip = string(linebuf);
        raw_ip.erase(remove_if(raw_ip.begin(), raw_ip.end(), ::isspace), raw_ip.end());
        
        ip_from_str(raw_ip.c_str(), &(pref->ip));      
        
        pref_file.getline(linebuf,4, '\n');
        pref->pref_length = strtoul(linebuf, NULL, 0);

        prefix_list.push_back(pref);
    }
    pref_file.close();
    return 0;
}

/**
 * Filter for checking ip for bogon prefixes
 * @param analyzed Record that's being analyzed
 * @return SPOOF_POSITIVE if address fits the bogon prefix else SPOOF_NEGATIVE
 */
int v4_bogon_filter(ip_addr_t *checked, pref_list_t& prefix_list, ipv4_mask_map_t& v4mm)
{
    //check source address of the record with each prefix
    for (int i = 0; i < prefix_list.size(); i++) {
        
        if (ip_is6(&(prefix_list[i]->ip))) {
            continue;
        }
 
        char debug_ip_src[INET6_ADDRSTRLEN];
        char debug_ip_pref[INET6_ADDRSTRLEN];
        ip_to_str(checked, debug_ip_src);
        ip_to_str(&(prefix_list[i]->ip), debug_ip_pref);

        if ((ip_get_v4_as_int(checked) & v4mm[prefix_list[i]->pref_length])
            == ip_get_v4_as_int(&(prefix_list[i]->ip))) {
            cout << "Possible spoofing found: ";
            cout << debug_ip_src;
            cout << " fits bogon prefix ";
            cout << debug_ip_pref << endl;
            return SPOOF_POSITIVE;
        }
        //else continue
    }

    // doesn't fit any bogon prefix
    return SPOOF_NEGATIVE;
}

int v6_bogon_filter(ip_addr_t *checked, pref_list_t& prefix_list, ipv6_mask_map_t& v6mm)
{
    for (int i = 0; i < prefix_list.size(); i++) {
        
        if (ip_is4(&(prefix_list[i]->ip))) {
            continue;
        }

        char debug_ip_src[INET6_ADDRSTRLEN];
        char debug_ip_pref[INET6_ADDRSTRLEN];
        ip_to_str(checked, debug_ip_src);
        ip_to_str(&(prefix_list[i]->ip), debug_ip_pref);
        
        if (prefix_list[i]->pref_length <= 64) {
            if ((checked->ui64[0] & v6mm[prefix_list[i]->pref_length][0]) == prefix_list[i]->ip.ui64[0]) {                              
                cout << "Possible spoofing found: ";
                cout << debug_ip_src;
                cout << " fits bogon prefix ";
                cout << debug_ip_pref << endl;
                return SPOOF_POSITIVE;
            }
        } else {      
            if ((checked->ui64[1] & v6mm[prefix_list[i]->pref_length][1]) == prefix_list[i]->ip.ui64[1]
                && checked->ui64[0] == prefix_list[i]->ip.ui64[0]) {                              
                cout << "Possible spoofing found: ";
                cout << debug_ip_src;
                cout << " fits bogon prefix ";
                cout << debug_ip_pref << endl;
                return SPOOF_POSITIVE;
            }
        }
    }
    return SPOOF_NEGATIVE;   
}
/**
 * Procedure for freeing memory used by prefix list.
 * Procedure goes through the vector and frees all memory used by its elements.
 * @param prefix_list List to be erased.
 */
void clear_bogon_filter(pref_list_t& prefix_list)
{
    for (int i = 0; i < prefix_list.size(); i++) {
        delete prefix_list[i];
    }
    prefix_list.clear();
}


int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec;

    ur_basic_flow_t *record;

    pref_list_t bogon_list;

    ipv4_mask_map_t v4_masks;
    ipv6_mask_map_t v6_masks;

    // Initialize TRAP library (create and init all interfaces)
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP initialization failed: ";
        cerr <<  trap_last_error_msg << endl;
        return retval;
    }

    retval = trap_init(&module_info, ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "TRAP INIT ERROR" << endl;
        return retval;
    }
    // free interface specification structure
    trap_free_ifc_spec(ifc_spec);

    // set signal handling for termination
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    create_v4_mask_map(v4_masks);
    
    create_v6_mask_map(v6_masks);
    // we don't have list of bogon prefixes loaded (usually first run)
    if (bogon_list.empty()) {
       retval = load_pref(bogon_list);
       if (retval) {
            return retval;
        }
    }


    int v4 = 0;
    int v6 = 0;
    int spoof_count = 0;
    // ***** Main processing loop *****
    while (!stop) {
        const void *data;
        uint16_t data_size;

        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) {
                break;
            } else {
                cerr << "ERROR: Unable to get data. Return value ";
                cerr << dec << retval;
                cerr << " (";
                cerr <<  trap_last_error_msg;
                cerr << ")" << endl;
                    break;
            }
        }

        if (data_size != sizeof(ur_basic_flow_t)) {
            if (data_size <= 1) {
                break;
            } else {
                cerr << "ERROR: Wrong data size.";
                cerr << "Expected: " + sizeof(ur_basic_flow_t);
                cerr << "Recieved: " + data_size << endl;
                break;
            }
        }

        // Interpret data as unirec flow record
        record = (ur_basic_flow_t *) data;

        if (ip_is4(&(record->src_addr))) {
            ++v4;
        } else {
            ++v6;
        }
        //go through all filters
        

        // ***** 1. bogon prefix filter *****
        if (ip_is4(&(record->src_addr))) {
            retval = v4_bogon_filter(&(record->src_addr), bogon_list, v4_masks);
        } else {
            retval = v6_bogon_filter(&(record->src_addr), bogon_list, v6_masks);
        }

        if (retval == SPOOF_POSITIVE) {
            ++spoof_count;
            retval = 0;
        }
        //2. symetric routing filter (TBA)
        //3. asymetric routing filter (will be implemented later)
        //4. new flow count check (TBA)


        //return spoofed or not
    }
    cout << "IPv4: ";
    cout << dec << v4 << endl;

    cout << "IPv6: ";
    cout << dec << v6 << endl;
    cout << "No. of possible spoofed addresses: ";
    cout << dec << spoof_count << endl;

    if (retval != 0)
        clear_bogon_filter(bogon_list);
    return 0;

}
