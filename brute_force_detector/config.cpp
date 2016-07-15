/**
 * \file config.cpp
 * \brief Class Config used for loading configuration, singleton implementation
 * \author Vaclav Pacholik <xpacho03@stud.fit.vutbr.cz || vaclavpacholik@gmail.com>
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

#include "config.h"

using namespace std;

Config::Config()
{
    //init default config variables
    GENERAL_CHECK_FOR_REPORT_TIMEOUT = ur_time_from_sec_msec(60, 0);
    GENERAL_CHECK_FOR_DELETE_TIMEOUT = ur_time_from_sec_msec(60, 0);
    GENERAL_ATTACK_MIN_EVENTS_TO_REPORT = 10;
    GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST = 10.0;
    GENERAL_IGNORE_FIRST_SEND = 0; 

    //SSH
    SSH_LIST_SIZE = 1000;
    SSH_LIST_SIZE_BOTTOM_TRESHOLD = 50; // There are two types of tresholds, first means how many records are in list [50/1000] and based on this value is set up TRESHOLD which detects if host is attacker or not
    SSH_LIST_THRESHOLD = 30;
    SSH_RECORD_TIMEOUT = ur_time_from_sec_msec(1800, 0);
    SSH_HOST_TIMEOUT   = ur_time_from_sec_msec(4200, 0);

    SSH_BRUTEFORCE_INC_MIN_PACKETS = 11;
    SSH_BRUTEFORCE_INC_MAX_PACKETS = 30;
    SSH_BRUTEFORCE_INC_MIN_BYTES = 1000;
    SSH_BRUTEFORCE_INC_MAX_BYTES = 5000;
    
    SSH_BRUTEFORCE_OUT_MIN_PACKETS = 11;
    SSH_BRUTEFORCE_OUT_MAX_PACKETS = 50;
    SSH_BRUTEFORCE_OUT_MIN_BYTES = 1000;
    SSH_BRUTEFORCE_OUT_MAX_BYTES = 11000;

    SSH_REPORT_TIMEOUT = ur_time_from_sec_msec(300, 0);
    SSH_ATTACK_TIMEOUT = ur_time_from_sec_msec(600, 0);

    //RDP
    RDP_LIST_SIZE = 1000;
    RDP_LIST_SIZE_BOTTOM_TRESHOLD = 50;
    RDP_LIST_THRESHOLD = 30;
    RDP_RECORD_TIMEOUT = ur_time_from_sec_msec(1800, 0);
    RDP_HOST_TIMEOUT   = ur_time_from_sec_msec(4200, 0);

    RDP_BRUTEFORCE_INC_MIN_PACKETS = 20;
    RDP_BRUTEFORCE_INC_MAX_PACKETS = 100;
    RDP_BRUTEFORCE_INC_MIN_BYTES = 2200;
    RDP_BRUTEFORCE_INC_MAX_BYTES = 8001;
    
    //based on Flow-based detection of RDP brute-force attacks by Vykopal
    RDP_BRUTEFORCE_OUT_MIN_PACKETS = 30;
    RDP_BRUTEFORCE_OUT_MAX_PACKETS = 190;
    RDP_BRUTEFORCE_OUT_MIN_BYTES = 3000;
    RDP_BRUTEFORCE_OUT_MAX_BYTES = 180000;

    RDP_REPORT_TIMEOUT = ur_time_from_sec_msec(300, 0);
    RDP_ATTACK_TIMEOUT = ur_time_from_sec_msec(600, 0);

    //TELNET
    TELNET_LIST_SIZE = 1000;
    TELNET_LIST_SIZE_BOTTOM_TRESHOLD = 50;
    TELNET_LIST_THRESHOLD = 30;
    TELNET_RECORD_TIMEOUT = ur_time_from_sec_msec(1800, 0);
    TELNET_HOST_TIMEOUT   = ur_time_from_sec_msec(4200, 0);

    TELNET_BRUTEFORCE_INC_MIN_PACKETS = 9;
    TELNET_BRUTEFORCE_INC_MAX_PACKETS = 50;
    TELNET_BRUTEFORCE_INC_MIN_BYTES = 450;
    TELNET_BRUTEFORCE_INC_MAX_BYTES = 3000;

    TELNET_REPORT_TIMEOUT = ur_time_from_sec_msec(300, 0);
    TELNET_ATTACK_TIMEOUT = ur_time_from_sec_msec(600, 0);


	//init keywords
    kw_GENERAL_CHECK_FOR_REPORT_TIMEOUT = "GENERAL_CHECK_FOR_REPORT_TIMEOUT";
    kw_GENERAL_CHECK_FOR_DELETE_TIMEOUT = "GENERAL_CHECK_FOR_DELETE_TIMEOUT";
    kw_GENERAL_ATTACK_MIN_EVENTS_TO_REPORT = "GENERAL_ATTACK_MIN_EVENTS_TO_REPORT";
    kw_GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST = "GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST";
    kw_GENERAL_IGNORE_FIRST_SEND = "GENERAL_IGNORE_FIRST_SEND";

    //SSH
    kw_SSH_LIST_SIZE      = "SSH_LIST_SIZE";
    kw_SSH_LIST_THRESHOLD = "SSH_LIST_THRESHOLD";
    kw_SSH_RECORD_TIMEOUT = "SSH_RECORD_TIMEOUT";
    kw_SSH_HOST_TIMEOUT   = "SSH_HOST_TIMEOUT";
    kw_SSH_REPORT_TIMEOUT = "SSH_REPORT_TIMEOUT";
    kw_SSH_ATTACK_TIMEOUT = "SSH_ATTACK_TIMEOUT";

    kw_SSH_BRUTEFORCE_INC_MIN_PACKETS = "SSH_BRUTEFORCE_INC_MIN_PACKETS";
    kw_SSH_BRUTEFORCE_INC_MAX_PACKETS = "SSH_BRUTEFORCE_INC_MAX_PACKETS";
    kw_SSH_BRUTEFORCE_INC_MIN_BYTES   = "SSH_BRUTEFORCE_INC_MIN_BYTES";
    kw_SSH_BRUTEFORCE_INC_MAX_BYTES   = "SSH_BRUTEFORCE_INC_MAX_BYTES";
    
    kw_SSH_BRUTEFORCE_OUT_MIN_PACKETS = "SSH_BRUTEFORCE_OUT_MIN_PACKETS";
    kw_SSH_BRUTEFORCE_OUT_MAX_PACKETS = "SSH_BRUTEFORCE_OUT_MAX_PACKETS";
    kw_SSH_BRUTEFORCE_OUT_MIN_BYTES   = "SSH_BRUTEFORCE_OUT_MIN_BYTES";
    kw_SSH_BRUTEFORCE_OUT_MAX_BYTES   = "SSH_BRUTEFORCE_OUT_MAX_BYTES";

    //RDP
    kw_RDP_LIST_SIZE      = "RDP_LIST_SIZE";
    kw_RDP_LIST_THRESHOLD = "RDP_LIST_THRESHOLD";
    kw_RDP_RECORD_TIMEOUT = "RDP_RECORD_TIMEOUT";
    kw_RDP_HOST_TIMEOUT   = "RDP_HOST_TIMEOUT";
    kw_RDP_REPORT_TIMEOUT = "RDP_REPORT_TIMEOUT";
    kw_RDP_ATTACK_TIMEOUT = "RDP_ATTACK_TIMEOUT";

    kw_RDP_BRUTEFORCE_INC_MIN_PACKETS = "RDP_BRUTEFORCE_INC_MIN_PACKETS";
    kw_RDP_BRUTEFORCE_INC_MAX_PACKETS = "RDP_BRUTEFORCE_INC_MAX_PACKETS";
    kw_RDP_BRUTEFORCE_INC_MIN_BYTES   = "RDP_BRUTEFORCE_INC_MIN_BYTES";
    kw_RDP_BRUTEFORCE_INC_MAX_BYTES   = "RDP_BRUTEFORCE_INC_MAX_BYTES";
    
    kw_RDP_BRUTEFORCE_OUT_MIN_PACKETS = "RDP_BRUTEFORCE_OUT_MIN_PACKETS";
    kw_RDP_BRUTEFORCE_OUT_MAX_PACKETS = "RDP_BRUTEFORCE_OUT_MAX_PACKETS";
    kw_RDP_BRUTEFORCE_OUT_MIN_BYTES   = "RDP_BRUTEFORCE_OUT_MIN_BYTES";
    kw_RDP_BRUTEFORCE_OUT_MAX_BYTES   = "RDP_BRUTEFORCE_OUT_MAX_BYTES";

    //TELNET
    kw_TELNET_LIST_SIZE      = "TELNET_LIST_SIZE";
    kw_TELNET_LIST_THRESHOLD = "TELNET_LIST_THRESHOLD";
    kw_TELNET_RECORD_TIMEOUT = "TELNET_RECORD_TIMEOUT";
    kw_TELNET_HOST_TIMEOUT   = "TELNET_HOST_TIMEOUT";
    kw_TELNET_REPORT_TIMEOUT = "TELNET_REPORT_TIMEOUT";
    kw_TELNET_ATTACK_TIMEOUT = "TELNET_ATTACK_TIMEOUT";

    kw_TELNET_BRUTEFORCE_INC_MIN_PACKETS = "TELNET_BRUTEFORCE_INC_MIN_PACKETS";
    kw_TELNET_BRUTEFORCE_INC_MAX_PACKETS = "TELNET_BRUTEFORCE_INC_MAX_PACKETS";
    kw_TELNET_BRUTEFORCE_INC_MIN_BYTES   = "TELNET_BRUTEFORCE_INC_MIN_BYTES";
    kw_TELNET_BRUTEFORCE_INC_MAX_BYTES   = "TELNET_BRUTEFORCE_INC_MAX_BYTES";

}

void Config::reloadConfig()
{
    if(!configPath.empty())
    {
        if(!initFromFile(configPath))
        {
            cerr << "Error Config: Configuration reload failed!\n";
        }
        else
        {
            cout << "Config: Configuration reloaded successfully.\n";
        }
    }
    else
    {
        cerr << "Error Config: Configuration path is not set!\n";
    }
}

bool Config::initFromFile(string path)
{
    configPath = path;

    ifstream configFile;
    configFile.open(path.c_str());
    if(!configFile.is_open())
        return false;

    //Parse file
    string line;
    string keyword, value;
    while(configFile.good())
    {
        getline(configFile, line);

        if(line.empty())
            continue; //skip empty line

        if(line[0] == '#')
            continue; //skip comment line

        size_t pos = line.find("="); // = delimiter
        if(pos == std::string::npos)
        {
            cerr << "Error Config: Invalid line \"" << line << "\"" << endl;
            cerr.flush();
            continue; //skip invalid line
        }

        keyword = line.substr(0, pos);
        value = line.substr(pos + 1); //skip = char

        //erase whitespace
        keyword.erase(remove_if(keyword.begin(), keyword.end(), ::isspace), keyword.end());
        value.erase(remove_if(value.begin(), value.end(), ::isspace), value.end());

		// GENERAL
        if(keyword.compare(kw_GENERAL_CHECK_FOR_REPORT_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            GENERAL_CHECK_FOR_REPORT_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_GENERAL_CHECK_FOR_DELETE_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            GENERAL_CHECK_FOR_DELETE_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_GENERAL_ATTACK_MIN_EVENTS_TO_REPORT) == 0)
        {
            GENERAL_ATTACK_MIN_EVENTS_TO_REPORT = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST) == 0)
        {
            GENERAL_ATTACK_MIN_RATIO_TO_KEEP_TRACKING_HOST = atof(value.c_str());
        }
        else if(keyword.compare(kw_GENERAL_IGNORE_FIRST_SEND) == 0)
        {
            GENERAL_IGNORE_FIRST_SEND = strtoul(value.c_str(), NULL, 10);
        }        
        // *********************
        // ******* SSH *********
        // *********************
        else if(keyword.compare(kw_SSH_LIST_SIZE) == 0)
        {
            SSH_LIST_SIZE = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_LIST_THRESHOLD) == 0)
        {
            SSH_LIST_THRESHOLD = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_ATTACK_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            SSH_ATTACK_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_SSH_RECORD_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            SSH_RECORD_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_SSH_HOST_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            SSH_HOST_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_SSH_REPORT_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            SSH_REPORT_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        // SSH INCOMING DIRECTION (ATTACKER -> VICTIM)
        else if(keyword.compare(kw_SSH_BRUTEFORCE_INC_MIN_PACKETS) == 0)
        {
            SSH_BRUTEFORCE_INC_MIN_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_BRUTEFORCE_INC_MAX_PACKETS) == 0)
        {
            SSH_BRUTEFORCE_INC_MAX_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_BRUTEFORCE_INC_MIN_BYTES) == 0)
        {
            SSH_BRUTEFORCE_INC_MIN_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_BRUTEFORCE_INC_MAX_BYTES) == 0)
        {
            SSH_BRUTEFORCE_INC_MAX_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        // SSH OUTGOING DIRECTION (VICTIM -> ATTACKER)
        else if(keyword.compare(kw_SSH_BRUTEFORCE_OUT_MIN_PACKETS) == 0)
        {
            SSH_BRUTEFORCE_OUT_MIN_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_BRUTEFORCE_OUT_MAX_PACKETS) == 0)
        {
            SSH_BRUTEFORCE_OUT_MAX_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_BRUTEFORCE_OUT_MIN_BYTES) == 0)
        {
            SSH_BRUTEFORCE_OUT_MIN_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_SSH_BRUTEFORCE_OUT_MAX_BYTES) == 0)
        {
            SSH_BRUTEFORCE_OUT_MAX_BYTES = strtoul(value.c_str(), NULL, 10);
        }        
        // *********************
        // ******* RDP *********
        // *********************
        else if(keyword.compare(kw_RDP_LIST_SIZE) == 0)
        {
            RDP_LIST_SIZE = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_LIST_THRESHOLD) == 0)
        {
            RDP_LIST_THRESHOLD = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_ATTACK_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            RDP_ATTACK_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_RDP_RECORD_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            RDP_RECORD_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_RDP_HOST_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            RDP_HOST_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_RDP_REPORT_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            RDP_REPORT_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        // RDP INCOMING DIRECTION (ATTACKER -> VICTIM)
        else if(keyword.compare(kw_RDP_BRUTEFORCE_INC_MIN_PACKETS) == 0)
        {
            RDP_BRUTEFORCE_INC_MIN_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_BRUTEFORCE_INC_MAX_PACKETS) == 0)
        {
            RDP_BRUTEFORCE_INC_MAX_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_BRUTEFORCE_INC_MIN_BYTES) == 0)
        {
            RDP_BRUTEFORCE_INC_MIN_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_BRUTEFORCE_INC_MAX_BYTES) == 0)
        {
            RDP_BRUTEFORCE_INC_MAX_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        // RDP OUTGOING DIRECTION (VICTIM -> ATTACKER)
        else if(keyword.compare(kw_RDP_BRUTEFORCE_OUT_MIN_PACKETS) == 0)
        {
            RDP_BRUTEFORCE_OUT_MIN_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_BRUTEFORCE_OUT_MAX_PACKETS) == 0)
        {
            RDP_BRUTEFORCE_OUT_MAX_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_BRUTEFORCE_OUT_MIN_BYTES) == 0)
        {
            RDP_BRUTEFORCE_OUT_MIN_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_RDP_BRUTEFORCE_OUT_MAX_BYTES) == 0)
        {
            RDP_BRUTEFORCE_OUT_MAX_BYTES = strtoul(value.c_str(), NULL, 10);
        }        
        // *********************
        // ****** TELNET *******
        // *********************
        else if(keyword.compare(kw_TELNET_LIST_SIZE) == 0)
        {
            TELNET_LIST_SIZE = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_TELNET_LIST_THRESHOLD) == 0)
        {
            TELNET_LIST_THRESHOLD = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_TELNET_ATTACK_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            TELNET_ATTACK_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_TELNET_RECORD_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            TELNET_RECORD_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_TELNET_HOST_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            TELNET_HOST_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_TELNET_REPORT_TIMEOUT) == 0)
        {
            uint32_t sec = strtoul(value.c_str(), NULL, 10);
            TELNET_REPORT_TIMEOUT = ur_time_from_sec_msec(sec, 0);
        }
        else if(keyword.compare(kw_TELNET_BRUTEFORCE_INC_MIN_PACKETS) == 0)
        {
            TELNET_BRUTEFORCE_INC_MIN_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_TELNET_BRUTEFORCE_INC_MAX_PACKETS) == 0)
        {
            TELNET_BRUTEFORCE_INC_MAX_PACKETS = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_TELNET_BRUTEFORCE_INC_MIN_BYTES) == 0)
        {
            TELNET_BRUTEFORCE_INC_MIN_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        else if(keyword.compare(kw_TELNET_BRUTEFORCE_INC_MAX_BYTES) == 0)
        {
            TELNET_BRUTEFORCE_INC_MAX_BYTES = strtoul(value.c_str(), NULL, 10);
        }
        // *********************
        // ******* UNKNOWN *****
        // *********************
        else
        {
            cerr << "Error Config: Unknown keyword " << keyword << endl;
            cerr.flush();
        }
    }

    configFile.close();

    return true;
}
