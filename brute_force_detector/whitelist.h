/**
 * \file whitelist.h
 * \brief Whitelist and whitelist parser
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

#ifndef WHITELIST_H
#define WHITELIST_H

#include <fstream>
#include <cstdlib>
#include <set>  
#include <iostream>
#include <string>
#include <unirec/unirec.h>
#include <csignal> 


//WHITELIST PARSER VARIABLES
const static std::string WHITELIST_PARSER_IP_DIRECTION_KEYWORD_SRC = "src";
const static std::string WHITELIST_PARSER_IP_DIRECTION_KEYWORD_DST = "dst";

const static uint8_t WHITELIST_PARSER_IP_DIRECTION_ALL = 0;
const static uint8_t WHITELIST_PARSER_IP_DIRECTION_SRC = 1;
const static uint8_t WHITELIST_PARSER_IP_DIRECTION_DST = 2;

const static uint8_t WHITELIST_PARSER_COMMENT_DELIM    = '#';
const static uint8_t WHITELIST_PARSER_PREFIX_DELIM     = '/';
const static uint8_t WHITELIST_PARSER_PORTS_DELIM      = '/';
const static uint8_t WHITELIST_PARSER_NEXT_PORT_DELIM  = ',';
const static uint8_t WHITELIST_PARSER_PORT_RANGE_DELIM = '-';


// ************************************************************/
// ******************** WHITELISTEDPORTS  *********************/
// ************************************************************/

/**
 * @desc Class storage of white listed ports. Single port or portRange can be added
 */
class WhitelistedPorts
{

public:
    WhitelistedPorts();
    /**
     * @desc Add port range to whitelisted ports
     * @param from Port from (start of range)
     * @param to   Port to   (end of range)
     */
    void addPortRange(uint16_t from, uint16_t to);
    /**
     * @desc Add single port to whitelisted ports
     * @param port Port to add
     */
    void addSinglePort(uint16_t port);
    /**
     * @desc Find port if is whitelisted
     * @param port Port to find
     */
    bool findPort(uint16_t port);

private:
    typedef std::pair<uint16_t, uint16_t> Range;
    struct RangeCompare
    {
        bool operator()(const Range& r1, const Range& r2) const
        {
            return r1.second < r2.first;
        }
    };
    std::set<Range, RangeCompare> portRangeList;

    bool inRange(const std::set<Range, RangeCompare>& ranges, uint16_t port)
    {
        return ranges.find(Range(port, port)) != ranges.end();
    }

};

// ************************************************************/
// ************************ IP TRIE  **************************/
// ************************************************************/

class IPTrie {
public:
    IPTrie();
    ~IPTrie();

    IPTrie *left;
    IPTrie *right;

    bool allPorts;
    bool set;

    WhitelistedPorts *whitelistedPorts;
};

// ************************************************************/
// ******************** WHITELISTPARSER  **********************/
// ************************************************************/
/**
 * @desc Class for parsing input whitelist file stream
 */
class WhitelistParser {
public:
    WhitelistParser()
    {
        rulesCounter = 0;
        verbose = false;
    }

    /**
     * @desc Init parser with two IP tries, first for IPv4, second for IPv6
     */
    void init(IPTrie *ipv4Src, IPTrie *ipv4Dst, IPTrie *ipv6Src, IPTrie *ipv6Dst);
    /**
     * @desc Parse input filestream and add rules into IP Tries, detection mode must be set
     */
    void parse(std::ifstream *ifs, bool verboseMode);

    /**
     * \brief Only for unit testing!
     *
     * Only for unit testing!
     */
    bool addSelectedPortRule(ip_addr_t ip, uint8_t direction, uint8_t prefix, std::string ports) 
    {
        return checkPrefixAndPortsAndAdd(ip, direction, prefix, ports);
    }

    /**
     * \brief Only for unit testing!
     *
     * Only for unit testing!
     */
    bool addAllPortRule(ip_addr_t ip, uint8_t direction, uint8_t prefix)
    {
        return checkPrefixAndAddAllPorts(ip, direction, prefix);
    }

private:
    IPTrie *ipv4Src;
    IPTrie *ipv4Dst;
    IPTrie *ipv6Src;
    IPTrie *ipv6Dst;
    bool verbose;
    uint32_t rulesCounter;

    /**
     * @desc Add ip into whitelist
     */
    void prepareAddIP(ip_addr_t addr, uint8_t direction, uint8_t prefix, uint8_t iptype);
    /**
     * @desc Add ip and ports into whitelist
     */
    void prepareAddIPAndPorts(ip_addr_t addr, uint8_t direction, uint8_t prefix, uint8_t iptype, std::string ports);

    /**
     * @desc Add ip and all ports into whitelist
     */
    void addIPAllPorts(uint8_t *ip, uint8_t prefix, IPTrie *trie);
    /**
     * @desc Add ip and selected ports into whitelist
     */
    void addIPAndSelectedPorts(uint8_t *ip, uint8_t prefix, IPTrie *trie, std::string ports);

    /**
     * @desc Add ports into IP trie
     */
    void addPorts(IPTrie *currentNode, std::string ports);

    /**
     * @desc Check ip prefix, then add ip and all ports into whitelist
     */
    bool checkPrefixAndAddAllPorts(ip_addr_t ip, uint8_t direction, uint8_t prefix);
    /**
     * @desc Check ip prefix, then add ip and ports into whitelist
     */
    bool checkPrefixAndPortsAndAdd(ip_addr_t ip, uint8_t direction, uint8_t prefix, std::string ports);

};

// ************************************************************/
// ************************ WHITELIST  ************************/
// ************************************************************/

/**
 * @desc Whitelist filter for whitelisting IP address and ports
 */
class Whitelist {
public:
    Whitelist();
    ~Whitelist();

    /**
     * @desc init whitelist
     * @param fileName name of whitelist file
     * @param detectionMode detection mode
     */
    bool init(char *fileName, bool verbose);

    /**
     * @desc check given record and host source ip if is whitelisted
     * @param Record record
     * @param srcip source ip address
     */
    bool isWhitelisted(const ip_addr_t *srcIp, const ip_addr_t *dstIp, uint16_t srcPort, uint16_t dstPort);

    /**
     * @desc get status for configuration reload
     */
    sig_atomic_t isLockedForConfigurationReload()
    {
        return locked;
    }

    /**
     * @desc reaload whitelist, all previous configuration will be erased
     */
    void reloadWhitelist();

    /**
     * \brief Only for unit testing!
     *
     * Only for unit testing!
     */
    WhitelistParser *getPointerToParser()
    {
        return &parser;
    }
private:
    /**
     * @desc  Find given ip address and port inside IP trie structure
     * @param ipTrie IP trie
     * @param ip IP address as array
     * @param ipType Type of IP address 4 or 6
     * @param port Searched port
     * @return true if port or ip is filtered, false otherwise
     */
    bool trieSearch(IPTrie *ipTrie, uint8_t *ip, uint8_t ipType, uint16_t port);

    WhitelistParser parser;
    IPTrie *ipv4Src;
    IPTrie *ipv4Dst;
    IPTrie *ipv6Src;
    IPTrie *ipv6Dst;
    sig_atomic_t locked;
    char *wlFileName;
};

#endif