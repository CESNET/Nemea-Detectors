/**
 * \file spoofing.cpp
 * \brief IP spoofing detector for Nemea
 * \author Roman Vrana, xvrana20@stud.fit.vutbr.cz
 * \date 2013
 */

#include <iostream>
#include <cstdlib>
#include <stdint.h>
#include "../unirec.h"
#include "../ipaddr.h"

using namespace std;

/**
 * Filter for checking ip for bogon prefixes
 * @param analyzed Record that's being analyzed
 * @return SPOOF_POSITIVE if address fits the bogon prefix else SPOOF_NEGATIVE
 */

int bogon_filter(ur_basic_flow_t *analyzed)
{
    //load file with bogon prefixes
    //check source address of the record with each prefix
//    if  fits the bogon prefix
        return SPOOF_POSTIVE;
//    else
        return SPOOF_NEGATIVE;
}
int main (int argc, char** argv)
{

    int retval = 0; // return value

    trap_ifc_spec_t ifc_spec;

    ur_basic_flow_t *record;

    // Initialize TRAP library (create and init all interfaces)
    retval = trap_parse_params(&argc, argv, &ifc_spec);
    if (retval != TRAP_E_OK) {
        cerr << "ERROR: TRAP initialization failed: "+ trap_last_eror_msg << endl;
    }
    trap_free_ifc_spec(ifc_spec);

    while (!stop) {
        const void *data;
        uint16_t data_size;

        retval = trap_get_data(TRAP_MASK_ALL, &data, &data_size, TRAP_WAIT);
        if (retval != TRAP_E_OK) {
            if (retval == TRAP_TERMINATED) {
                break;
            } else {
                cerr << "ERROR: Unable to get data. Return value " + retval + " ("trap_last_error_msg")" << endl;
                break;
            }
        }

    // Interpret data as unirec flow record
    record = (ur_basic_flow_t *) data;

    //go through all filters
    //1. bogon prefix filter
    //2. symetric routing filter
    //3. asymetric routing filter (will be implemented later)
    //4. new flow count check


    //return spoofed or not
}
