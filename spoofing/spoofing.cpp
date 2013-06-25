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

#define DEBUG 1

using namespace std;

trap_module_info_t module_info = {
    "IP spoofing detection module", // Module name
    // Module description
    "This module checks ip addresses in data flows for possible IP spoofing.\n"
    "It uses four conditions to determine this:\n"
    "1. Testing for bogon prefixes\n"
    "2. Checking symetric routes\n"
    "3. Checking asymetric routes\n"
    "4. Counting new flows\n"
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

// **********   BOGON PREFIX FILTER   **********
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

/**
 * Function for creating masks for IPv6 addresses.
 * Functions fills the given array with every possible netmask for IPv6 address.
 * Size of the array is 129 items each containing 2 parts of IPv6 mask.
 *
 * @ param m Array to be filled
 */

void create_v6_mask_map(ipv6_mask_map_t& m)
{
    // explicitly inserted or else it will be 0xFF in every byte
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
 */
int load_pref (pref_list_t& prefix_list, char *bogon_file)
{
    ip_prefix_t *pref;
    ifstream pref_file;
    char linebuf[INET6_ADDRSTRLEN];
    
    // open file with prefixes (hardcoded for now -- may be changed)
    pref_file.open(bogon_file);

    // unable to open prefix file
    if (!pref_file.is_open()) {
        cerr << "ERROR: File with bogon prefixes couldn't be loaded.";
        cerr << " Unable to continue." << endl;
        return BOGON_FILE_ERROR;
    }

    // loading the prefixes to memory
    while (pref_file.good()) {

        // allocate memory for new item
        pref = new ip_prefix_t;
        if (pref == NULL) {
            cerr << "ERROR: Cannot allocate memory for bogon list item.";
            cerr << " Unable to continue." << endl;
            return BOGON_FILE_ERROR;
        }
        
        pref_file.getline(linebuf, INET6_ADDRSTRLEN, '/');
        string raw_ip = string(linebuf);

        // trim whitespaces from the input
        raw_ip.erase(remove_if(raw_ip.begin(), raw_ip.end(), ::isspace), raw_ip.end());
        
        /*
         * Convert input to ip address for use in program
         * If it fails (invalid ip address) free the memory and continue 
         * to next line.
         */
        if (!ip_from_str(raw_ip.c_str(), &(pref->ip))) {
            delete pref;
            continue;
        }

        // load prefix length (netmask
        pref_file.getline(linebuf,4, '\n');

        // convert to number
        pref->pref_length = strtoul(linebuf, NULL, 0);

        // save to the prefix list
        prefix_list.push_back(pref);
    }
    pref_file.close();
    return ALL_OK;
}

/**
 * Filter for checking ipv4 for bogon prefixes.
 * This function checks the given ip address  whether it matches 
 * any of the bogon prefixes in list. If it does filter returns 
 * positive spoofing constant and spoofing counter is increased.
 * 
 * @param checked IP address that is being checked
 * @param prefix_list List of bogon prefixes used for checking
 * @param v4mm Array of every possible netmasks for protocol
 * @return SPOOF_POSITIVE if address fits the bogon prefix otherwise SPOOF_NEGATIVE
 */
int v4_bogon_filter(ip_addr_t *checked, pref_list_t& prefix_list, ipv4_mask_map_t& v4mm)
{
    //check source address of the record with each prefix
    for (int i = 0; i < prefix_list.size(); i++) {
        
        // we don't need to try IPv6 prefixes
        if (ip_is6(&(prefix_list[i]->ip))) {
            continue;
        }

#ifdef DEBUG
        char debug_ip_src[INET6_ADDRSTRLEN];
        char debug_ip_pref[INET6_ADDRSTRLEN];
        ip_to_str(checked, debug_ip_src);
        ip_to_str(&(prefix_list[i]->ip), debug_ip_pref);
#endif

        /* 
         * Matching address to prefix
         * Perform bitwise AND operation on integer value of ip address
         * and mask of the bogon prefix. Spoofing is positive if the result
         * of this operation is equal to integer value of bogon ip address.
         */
        if ((ip_get_v4_as_int(checked) & v4mm[prefix_list[i]->pref_length])
            == ip_get_v4_as_int(&(prefix_list[i]->ip))) {

#ifdef DEBUG
            cout << "Possible spoofing found: ";
            cout << debug_ip_src;
            cout << " fits prefix ";
            cout << debug_ip_pref;
            cout <<"/";
            short a;
            cout << dec <<  (a = prefix_list[i]->pref_length) << endl;
#endif

            return SPOOF_POSITIVE;
        }
        //else continue
    }

    // doesn't fit any bogon prefix
    return SPOOF_NEGATIVE;
}

/**
 * Filter for checking ipv6 for bogon prefixes.
 * This function checks the given ip address  whether it matches 
 * any of the bogon prefixes in list. If it does filter returns 
 * positive spoofing constant and spoofing counter is increased.
 * 
 * @param checked IP address that is being checked
 * @param prefix_list List of bogon prefixes used for checking
 * @param v4mm Array of every possible netmasks for protocol
 * @return SPOOF_POSITIVE if address fits the bogon prefix otherwise SPOOF_NEGATIVE
 */
int v6_bogon_filter(ip_addr_t *checked, pref_list_t& prefix_list, ipv6_mask_map_t& v6mm)
{
    for (int i = 0; i < prefix_list.size(); i++) {
        
        // we don't need to try IPv4 prefixes
        if (ip_is4(&(prefix_list[i]->ip))) {
            continue;
        }

#ifdef DEBUG
        char debug_ip_src[INET6_ADDRSTRLEN];
        char debug_ip_pref[INET6_ADDRSTRLEN];
        ip_to_str(checked, debug_ip_src);
        ip_to_str(&(prefix_list[i]->ip), debug_ip_pref);
#endif
        
        /* 
         * Matching address to prefix
         * We can decide which part to AND with bogon prefix by the length.
         * If the length of the bogon prefix is shorter or equal to 64 bits
         * we need to bitwise AND only the first half of the ip addre 
         * and then compare it to the value of the first half of the bogon
         * prefix. If it's longer then we AND the second half of the ip address 
         * and then we compare the whole result with the bogon prefix. Spoofing 
         * is positive when the result of comparison fits the prefix.
         */

        // Swap the halves of the addresses again
        *checked = ip_from_16_bytes_le((char *) checked);
        uint64_t tmp;
        tmp = checked->ui64[1];
        checked->ui64[1] = checked->ui64[0];
        checked->ui64[0] = tmp;

        if (prefix_list[i]->pref_length <= 64) {
            if ((checked->ui64[0] & v6mm[prefix_list[i]->pref_length][0]) 
                 == prefix_list[i]->ip.ui64[0]) {
#ifdef DEBUG
                cout << "Possible spoofing found: ";
                cout << debug_ip_src;
                cout << " fits prefix ";
                cout << debug_ip_pref;
                cout <<"/";
                short a;
                cout << dec <<  (a = prefix_list[i]->pref_length) << endl;
#endif
                return SPOOF_POSITIVE;
            }
        } else {
            if ((checked->ui64[1] & v6mm[prefix_list[i]->pref_length][1]) 
                 == prefix_list[i]->ip.ui64[1]
                 && checked->ui64[0] == prefix_list[i]->ip.ui64[0]) {
#ifdef DEBUG
                cout << "Possible spoofing found: ";
                cout << debug_ip_src;
                cout << " fits bogon prefix ";
                cout << debug_ip_pref;
                cout <<"/";
                short a;
                cout << dec <<  (a = prefix_list[i]->pref_length) << endl;
#endif
                return SPOOF_POSITIVE;
            }
        }
  }
    return SPOOF_NEGATIVE;   
}
/**
 * Procedure for freeing memory used by prefix list.
 * Procedure goes through the vector and frees all memory used by its elements.
 *
 * @param prefix_list List to be erased.
 */
void clear_bogon_filter(pref_list_t& prefix_list)
{
    for (int i = 0; i < prefix_list.size(); i++) {
        delete prefix_list[i];
    }
    prefix_list.clear();
}


// **********   SYMETRIC ROUTING FILTER   **********

/**
 * Function for checking routing symetry for IPv4.
 * Function takes the direction flag from the record and based on its value 
 * it decides whether to associate the link with its source IP or to check 
 * the link used by the communication. Checking of the communication is 
 * done based on the map of links their respective source IP address. The map 
 * is filled from outgoing communication by the destination address. If the 
 * communication flow is incomming then the source address is used as a key 
 * to the map to get the link used by this communiation. If the link fits 
 * the bitmask stored on this location then the communication is considered 
 * legit (the route is symetric). If the result of masking  AND operation is
 * 0x0 then there is no valid link for this communication and the source IP is 
 * flagged as spoofed.
 *
 * @param record Record (unirec format) that is being analyzed.
 * @param src Map with link masks associated to their respective sources.
 * @return SPOOF_NEGATIVE if the route is symetric otherwise SPOOF_POSITIVE.
 */

int check_symetry_v4(ur_basic_flow_t *record, v4_sym_sources_t& src)
{

#ifdef DEBUG
    char debug_ip_src[INET6_ADDRSTRLEN];
    char debug_ip_dst[INET6_ADDRSTRLEN];
    ip_to_str(&(record->src_addr), debug_ip_src);
    ip_to_str(&(record->dst_addr), debug_ip_dst);
#endif


    int v4_numeric;
    
    // check incomming/outgoing traffic
    if (record->dirbitfield == 0x0) {// outgoing trafic
        // mask with 24-bit long prefix
        v4_numeric = ip_get_v4_as_int(&(record->dst_addr)) & 0xFFFFFF00;

        if (src.count(v4_numeric)) {
            src[v4_numeric].link |= record->linkbitfield;
//            src[v4_numeric].timestamp = "timestamp from unirec"
        } else {
            sym_src_t src_rec;
            src_rec.link = record->linkbitfield;
//            src_rec.timestamp = "timestamp from unirec"
            src.insert(pair<int, sym_src_t>(v4_numeric, src_rec));
        }

    } else { // incomming traffic --> check for validity
        // mask with 24-bit long prefix
        v4_numeric = ip_get_v4_as_int(&(record->src_addr)) & 0xFFFFFF00;
        if (src.count(v4_numeric)) {
            int valid = src[v4_numeric].link & record->linkbitfield;
            if (valid == 0x0) {
                //no valid link found => possible spoofing
#ifdef  DEBUG
                cout << debug_ip_src << " ---> " << debug_ip_dst << endl;
                cout << "Flow goes through " << (long long) record->linkbitfield << " while stored is " << (long long) src[v4_numeric].link  << endl;
                cout << "Possible spoofing found: tested route is asymetric." << endl;
#endif
                return SPOOF_POSITIVE;
            } else {
                // trafic went through the valid link
                return SPOOF_NEGATIVE;
            }
        } else { // no bit record found
            return SPOOF_NEGATIVE;
        }
    }
    return SPOOF_NEGATIVE;
}

/**
 * Function for checking routing symetry for IPv6.
 * Function takes the direction flag from the record and based on its value 
 * it decides whether to associate the link with its source IP or to check 
 * the link used by the communication. Checking of the communication is 
 * done based on the map of links their respective source IP address. The map 
 * is filled from outgoing communication by the destination address. If the 
 * communication flow is incomming then the source address is used as a key 
 * to the map to get the link used by this communiation. If the link fits 
 * the bitmask stored on this location then the communication is considered 
 * legit (the route is symetric). If the result of masking  AND operation is
 * 0x0 then there is no valid link for this communication and the source IP is 
 * flagged as spoofed.
 *
 * @param record Record (unirec format) that is being analyzed.
 * @param src Map with link masks associated to their respective sources.
 * @return SPOOF_NEGATIVE if the route is symetric otherwise SPOOF_POSITIVE.
 */

int check_symetry_v6(ur_basic_flow_t *record, v6_sym_sources_t& src)
{

#ifdef DEBUG
    char debug_ip_src[INET6_ADDRSTRLEN];
    char debug_ip_dst[INET6_ADDRSTRLEN];
    ip_to_str(&(record->src_addr), debug_ip_src);
    ip_to_str(&(record->dst_addr), debug_ip_dst);
#endif

    //  Swap the halves of the addresses again
    //  No idea why the address from recieved record is messed up
    record->src_addr = ip_from_16_bytes_le((char *) &(record->src_addr));
    record->dst_addr = ip_from_16_bytes_le((char *) &(record->dst_addr));

    uint64_t tmp;
    tmp = record->src_addr.ui64[1];
    record->src_addr.ui64[1] = record->src_addr.ui64[0];
    record->src_addr.ui64[0] = tmp;

    tmp = record->dst_addr.ui64[1];
    record->dst_addr.ui64[1] = record->dst_addr.ui64[0];
    record->dst_addr.ui64[0] = tmp;


    // check incomming/outgoing traffic
    if (record->dirbitfield == 0x0) {// outgoing traffic
        // for future use with /48 prefix length
        // record->dst_addr.ui64[0] &= 0xFFFFFFFFFFFF0000;

        if (src.count(record->dst_addr.ui64[0] /* && timestamp is not older than given value*/)) {
            src[record->dst_addr.ui64[0]].link |= record->linkbitfield;
//            src[record->dst_addr.ui64[0]].timestamp = "timestamp from unirec"
        } else {
            sym_src_t src_rec;
            src_rec.link = record->linkbitfield;
//            src_rec.timestamp = "timestamp from unirec"
            src.insert(pair<uint64_t, sym_src_t>(record->dst_addr.ui64[0], src_rec));
        }

    } else { // incomming traffic --> check for validity
        // for future use with /48 prefix length
        //record->src_addr.ui64[0] &= 0xFFFFFFFFFFFF0000;

        if (src.count(record->src_addr.ui64[0])) {
            int valid = src[record->src_addr.ui64[0]].link & record->linkbitfield;
            if (valid == 0x0) {
                //no valid link found => possible spoofing
#ifdef  DEBUG
                cout << debug_ip_src << " ---> " << debug_ip_dst << endl;
                cout << "Flow goes through " << (long long) record->linkbitfield << " while stored is " << (long long) src[record->src_addr.ui64[0]].link  << endl;
                cout << "Possible spoofing found: tested route is asymetric." << endl;
#endif
                return SPOOF_POSITIVE;
            } else {
                return SPOOF_NEGATIVE;
            }
        } else { // no bit record found
            return SPOOF_NEGATIVE;
        }
    }
    return SPOOF_NEGATIVE;
}

int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec; // interface specification for TRAP

    ur_basic_flow_t *record; // pointer on flow record

    pref_list_t bogon_list; // list of bogon prefixes

    ipv4_mask_map_t v4_masks; // all possible IPv4 masks
    ipv6_mask_map_t v6_masks; // all possible IPv6 masks

    v4_sym_sources_t v4_route_sym; // map of sources for symetric routes (IPv4)
    v6_sym_sources_t v6_route_sym; // map of sources for symetric routes (IPv6)

    // Initialize TRAP library (create and init all interfaces)
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        if (retval == TRAP_E_HELP) {
            trap_print_help(&module_info);
            return EXIT_SUCCESS;
        }
        cerr << "ERROR: TRAP initialization failed: ";
        cerr <<  trap_last_error_msg << endl;
        return retval;
    }

    if (argc != 2) {
        cerr << "ERROR: Bogon file missing. Unable to continue" << endl;
        return EXIT_FAILURE;
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

    // fill the netmask masks
    create_v4_mask_map(v4_masks);    
    create_v6_mask_map(v6_masks);

    int v4 = 0;
    int v6 = 0;
    int spoof_count = 0;
    int bogons = 0;
    int syms = 0;

    // ***** Main processing loop *****
    while (!stop) {
        const void *data;
        uint16_t data_size;
                
        // we don't have list of bogon prefixes loaded (usually first run)
        if (bogon_list.empty()) {
            retval = load_pref(bogon_list, argv[1]);
            if (retval == BOGON_FILE_ERROR) {
                return retval;
            }
        }
        
        // retrieve data from server
        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_E_TERMINATED) { // trap is terminated
                break;
            } else { // recieve error
                cerr << "ERROR: Unable to get data. Return value ";
                cerr << dec << retval;
                cerr << " (" << trap_last_error_msg << ")." <<  endl;
                break;
            }
        }

        // check the data size 
        if (data_size != sizeof(ur_basic_flow_t)) {
            if (data_size <= 1) { // end of data
                break;
            } else { // data corrupted
                cerr << "ERROR: Wrong data size.";
                cerr << "Expected: " << sizeof(ur_basic_flow_t);
                cerr << "Recieved: " << data_size << endl;
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
        
        // we caught a spoofed address by bogon prefix
        if (retval == SPOOF_POSITIVE) {
            ++spoof_count;
            ++bogons;
            retval = ALL_OK; // reset return value
            continue;
        }
        // ***** 2. symetric routing filter *****
        if (ip_is4(&(record->src_addr))) {
            retval = check_symetry_v4(record, v4_route_sym);
        } else {
            retval = check_symetry_v6(record, v6_route_sym);
        }
        
        // we caught a spoofed address by not keeping to symteric routing
        if (retval == SPOOF_POSITIVE) {
            ++spoof_count;
            ++syms;
            retval = ALL_OK;
            continue;
        }
        
        //3. asymetric routing filter (will be implemented later)
        //4. new flow count check (TBA)


        //return spoofed or not
    }

#ifdef DEBUG
    cout << "IPv4: ";
    cout << dec << v4 << endl;

    cout << "IPv6: ";
    cout << dec << v6 << endl;
    cout << "No. of possibly spoofed addresses: ";
    cout << dec << spoof_count << endl;
    cout << "Caught by bogon filter: " << bogons << endl;
    cout << "Caught by symetric routing filter: " << syms << endl;
#endif

    // clean up before termination
    clear_bogon_filter(bogon_list);
    trap_finalize();

    return EXIT_SUCCESS;
}
