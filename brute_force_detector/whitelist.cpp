/**
 * \file whitelist.cpp
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

#include "whitelist.h"

using namespace std;


// ************************************************************/
// ********************* WHITELISTEDPORTS  ********************/
// ************************************************************/

WhitelistedPorts::WhitelistedPorts()
{

}

bool WhitelistedPorts::findPort(uint16_t port)
{
    return inRange(portRangeList, port);
}

void WhitelistedPorts::addPortRange(uint16_t from, uint16_t to)
{
    portRangeList.insert(Range(from, to));
}


void WhitelistedPorts::addSinglePort(uint16_t port)
{
    addPortRange(port, port);
}

// ************************************************************/
// ************************ IPTRIE  ***************************/
// ************************************************************/
IPTrie::IPTrie()
{
    left = NULL;
    right = NULL;
    allPorts = false;
    set = false;
    whitelistedPorts = NULL;
}

IPTrie::~IPTrie()
{
    if(left != NULL)
        delete left;

    if(right != NULL)
        delete right;

    if(whitelistedPorts != NULL)
        delete whitelistedPorts;
}

// ************************************************************/
// ******************** WHITELISTPARSER  **********************/
// ************************************************************/

void WhitelistParser::init(IPTrie *ipv4Src, IPTrie *ipv4Dst, IPTrie *ipv6Src, IPTrie *ipv6Dst)
{
    this->ipv4Src = ipv4Src;
    this->ipv4Dst = ipv4Dst;
    this->ipv6Src = ipv6Src;
    this->ipv6Dst = ipv6Dst;

    rulesCounter = 0;
}


// ************************************************************/
// ************************ WHITELIST  ************************/
// ************************************************************/


Whitelist::Whitelist()
{
    locked = false;
    wlFileName = NULL;

    ipv4Src = new IPTrie();
    ipv4Dst = new IPTrie();
    ipv6Src = new IPTrie();
    ipv6Dst = new IPTrie();

    parser.init(ipv4Src, ipv4Dst, ipv6Src, ipv6Dst);
}

Whitelist::~Whitelist()
{
    delete ipv4Src;
    delete ipv4Dst;
    delete ipv6Src;
    delete ipv6Dst;
}

bool Whitelist::init(char *fileName, bool verbose)
{
    wlFileName = fileName;
    ifstream ifs;
    ifs.open(fileName, ifstream::in);
    if(!ifs.is_open())
        return false;

    parser.parse(&ifs, verbose);

    ifs.close();

    return true;
}

bool Whitelist::isWhitelisted(const ip_addr_t *srcIp, const ip_addr_t *dstIp, uint16_t srcPort, uint16_t dstPort)
{
    locked = true;
    bool found = false;
	
	if(ip_is4(srcIp))
    {
        //ipv4
        //check src addr first
        found = trieSearch(ipv4Src, (uint8_t*) srcIp + 8, 4, srcPort);
        if(found)
        {
            locked = false;
            return true;
        }

        found = trieSearch(ipv4Dst, (uint8_t*) dstIp + 8, 4, dstPort);
        if(found)
        {
            locked = false;
            return true;
        }
    }
    else
    {        //ipv6

        //check src addr first
        found = trieSearch(ipv6Src, (uint8_t*) srcIp, 6, srcPort);
        if(found)
        {
            locked = false;
            return true;
        }

        //check dst addr
        found = trieSearch(ipv6Dst, (uint8_t*) dstIp, 6, dstPort);
        if(found)
        {
            locked = false;
            return true;
        }
    }
    locked = false;
    return false;
}

bool Whitelist::trieSearch(IPTrie *ipTrie, uint8_t *ip, uint8_t ipType, uint16_t port)
{
    IPTrie *currentNode = ipTrie;

    int iRange = -1;
    if(ipType == 4)
        iRange = 8 * 4;
    else if(ipType == 6)
        iRange = 8 * 16;

    for(int i = 0; i < iRange; i++)
    {
        for(int u = 7; u >= 0; u--)
        {
            //change last known node
            if(currentNode->set)
            {
                //vsechny porty
                if(currentNode->allPorts)
                {
                    return true;
                }
                if(currentNode->whitelistedPorts != NULL)
                {
                    if((currentNode->whitelistedPorts->findPort(port)) == true)
                    {
                        return true;
                    }

                }
            }

            //search right
            if(((ip[i] >> u) & 1) > 0)
            {
                currentNode = currentNode->right;
            }
            else
            { //search left
                currentNode = currentNode->left;
            }

            if(currentNode == NULL)
            {
                return false;
            }
        }
    }

    return false;
}

void Whitelist::reloadWhitelist()
{
    if(wlFileName != NULL)
    {
        ifstream ifs;
        ifs.open(wlFileName, ifstream::in);
        if(!ifs.is_open())
        {
            cerr << "Error Whitelist: Cannot open whitelist file!\n";
            return;
        }

        delete ipv4Src;
        delete ipv4Dst;
        delete ipv6Src;
        delete ipv6Dst;

        ipv4Src = new IPTrie();
        ipv4Dst = new IPTrie();
        ipv6Src = new IPTrie();
        ipv6Dst = new IPTrie();

        parser.init(ipv4Src, ipv4Dst, ipv6Src, ipv6Dst);
        parser.parse(&ifs, false);

        ifs.close();

        cout << "Whitelist: Whitelist reloaded successfully.\n";
    }
    else
    {
        cerr << "Error Whitelist: Whitelist path is not set!\n";
    }
}

// ************************************************************/
// ********************* WHITELIST PARSER *********************/
// ************************************************************/
void WhitelistParser::parse(ifstream *ifs, bool verboseMode)
{
    static bool verbose = verboseMode;
    this->verbose = verbose;
    if(verbose)
        cout << "Parsing whitelist file...\n";
    string line;
    uint8_t direction;

    while(std::getline((*ifs), line).good()) //get single line
    {
        //skip empty line
        if(line.empty())
            continue;

        //skip comment line
        if(line[0] == WHITELIST_PARSER_COMMENT_DELIM)
            continue;

        //substring before comment delim if exists
        size_t pos = line.find_first_of(WHITELIST_PARSER_COMMENT_DELIM);
        if(pos != string::npos)
        {
            line = line.substr(0, pos);
        }

        //now check for src or dst direction
        if(line.size() < 4)
        {
            if(verbose)
                cout << "Invalid line: " << line << endl;
            continue;
        }

        string sDirection = line.substr(0, 3);

        if(sDirection == WHITELIST_PARSER_IP_DIRECTION_KEYWORD_SRC)
        {
            direction = WHITELIST_PARSER_IP_DIRECTION_SRC;
            line = line.substr(4);
        }
        else if(sDirection == WHITELIST_PARSER_IP_DIRECTION_KEYWORD_DST)
        {
            direction = WHITELIST_PARSER_IP_DIRECTION_DST;
            line = line.substr(4);
        }
        else
            direction = WHITELIST_PARSER_IP_DIRECTION_ALL;


		//now ip check parse
        pos = line.find_first_of(WHITELIST_PARSER_PREFIX_DELIM);
        if(pos != string::npos)
        {
            string ipstring = line.substr(0, pos);
            ip_addr_t ip;
            if(ip_from_str(ipstring.c_str(), &ip))
            {
                //ip ok, now parse prefix and ports
                string prefixAndPorts = line.substr(pos + 1);
                if(!prefixAndPorts.empty())
                {
                    if(verbose)
                        cout << "IP: " << ipstring << endl;

                    pos = prefixAndPorts.find_first_of(WHITELIST_PARSER_PORTS_DELIM);
                    if(pos != string::npos)
                    {
                        string prefixStr = prefixAndPorts.substr(0, pos);
                        int prefix = atoi(prefixStr.c_str());
                        //get ports now
                        string ports = prefixAndPorts.substr(pos + 1);
                        if(ports.empty())
                        {
                            if(verbose)
                            {
                                cout << "Invalid line: " << line << endl;
                            }
                        }
                        else
                        {
                            if(!checkPrefixAndPortsAndAdd(ip, direction, prefix, ports))
                            {
                                if(verbose)
                                    cout << "Invalid line: " << line << endl;
                            }
                        }
                    }
					else
                    { //??? mtva vezev?
                        int prefix = atoi(prefixAndPorts.c_str());
                        if(!checkPrefixAndAddAllPorts(ip, direction, prefix))
                            if(verbose)
                                cout << "Invalid line: " << line << endl;
                    }
				}
                else if(verbose)
                    cout << "Invalid line: " << line << endl;
            }
            else if(verbose) //invalid ip
                cout << "Invalid line: " << line << endl;
        }
        else if(verbose)
            cout << "Invalid line: " << line << endl;
	}

    if(verbose)
    {
        cout << "Total rules added: " << rulesCounter << endl;
        cout << "Parsing whitelist file done" << endl;
    }

}

bool WhitelistParser::checkPrefixAndAddAllPorts(ip_addr_t ip, uint8_t direction, uint8_t prefix)
{
    if(ip_is4(&ip))
    {
        if(prefix > 32 || prefix < 0)
            return false;
        else
            prepareAddIP(ip, direction, prefix, 4);
    }
    else
    {
        if(prefix > 128 || prefix < 0)
            return false;
        else
            prepareAddIP(ip, direction, prefix, 6);
    }

    return true;
}

bool WhitelistParser::checkPrefixAndPortsAndAdd(ip_addr_t ip, uint8_t direction, uint8_t prefix, string ports)
{
    if(ip_is4(&ip))
    {
        if(prefix > 32 || prefix < 0)
            return false;
        else
            prepareAddIPAndPorts(ip, direction, prefix, 4, ports);
    }
    else
    {
        if(prefix > 128 || prefix < 0)
            return false;
        else
            prepareAddIPAndPorts(ip, direction, prefix, 6, ports);
    }
    return true;
}

void WhitelistParser::prepareAddIP(ip_addr_t addr, uint8_t direction, uint8_t prefix, uint8_t iptype)
{
    if(iptype == 4)
    {
        if(direction == WHITELIST_PARSER_IP_DIRECTION_ALL)
        {
            addIPAllPorts((uint8_t*) &addr + 8, prefix, ipv4Src);
            addIPAllPorts((uint8_t*) &addr + 8, prefix, ipv4Dst);

        }
        else if(direction == WHITELIST_PARSER_IP_DIRECTION_SRC)
        {
            addIPAllPorts((uint8_t*) &addr + 8, prefix, ipv4Src);
        }
        else
        { //direction == WHITELIST_PARSER_IP_DIRECTION_DST
            addIPAllPorts((uint8_t*) &addr + 8, prefix, ipv4Dst);

        }
    }
    else
    { //ipv6
        if(direction == WHITELIST_PARSER_IP_DIRECTION_ALL)
        {
            addIPAllPorts((uint8_t*) &addr, prefix, ipv6Src);
            addIPAllPorts((uint8_t*) &addr, prefix, ipv6Dst);

        }
        else if(direction == WHITELIST_PARSER_IP_DIRECTION_SRC)
        {
            addIPAllPorts((uint8_t*) &addr, prefix, ipv6Src);
        }
        else
        { //direction == WHITELIST_PARSER_IP_DIRECTION_DST
            addIPAllPorts((uint8_t*) &addr, prefix, ipv6Dst);
        }
    }
}

void WhitelistParser::prepareAddIPAndPorts(ip_addr_t addr, uint8_t direction, uint8_t prefix, uint8_t iptype, string ports)
{
    if(iptype == 4)
    {
        if(direction == WHITELIST_PARSER_IP_DIRECTION_ALL)
        {
            addIPAndSelectedPorts((uint8_t*) &addr + 8, prefix, ipv4Src, ports);
            addIPAndSelectedPorts((uint8_t*) &addr + 8, prefix, ipv4Dst, ports);
        }
        else if(direction == WHITELIST_PARSER_IP_DIRECTION_SRC)
        {
            addIPAndSelectedPorts((uint8_t*) &addr + 8, prefix, ipv4Src, ports);
        }
        else
        { //direction == WHITELIST_PARSER_IP_DIRECTION_DST
            addIPAndSelectedPorts((uint8_t*) &addr + 8, prefix, ipv4Dst, ports);
        }
    }
    else
    { //ipv6
        if(direction == WHITELIST_PARSER_IP_DIRECTION_ALL)
        {
            addIPAndSelectedPorts((uint8_t*) &addr, prefix, ipv6Src, ports);
            addIPAndSelectedPorts((uint8_t*) &addr, prefix, ipv6Dst, ports);
        }
        else if(direction == WHITELIST_PARSER_IP_DIRECTION_SRC)
        {
            addIPAndSelectedPorts((uint8_t*) &addr, prefix, ipv6Src, ports);
        }
        else
        { //direction == WHITELIST_PARSER_IP_DIRECTION_DST
            addIPAndSelectedPorts((uint8_t*) &addr, prefix, ipv6Dst, ports);
        }
    }
}

void WhitelistParser::addPorts(IPTrie *currentNode, string ports)
{
    WhitelistedPorts *whitelistedPorts = currentNode->whitelistedPorts;

    if(ports.empty())
        return;

    size_t pos;
    pos = ports.find_first_of(WHITELIST_PARSER_NEXT_PORT_DELIM);
    if(pos != string::npos)
    {
        string portString = ports.substr(0, pos);
        ports = ports.substr(pos + 1);

        pos = portString.find_first_of(WHITELIST_PARSER_PORT_RANGE_DELIM);
        if(pos != string::npos)
        { //range
            string firstStringPort = portString.substr(0, pos);
            string secondStringPort = portString.substr(pos + 1);
            if(secondStringPort.empty())
            {
                if(verbose)
                    cout << "Invalid ports range: " << portString << endl;
                return;
            }

            uint16_t port = atoi(firstStringPort.c_str());
            uint16_t port2 = atoi(secondStringPort.c_str());

            whitelistedPorts->addPortRange(port, port2);
            rulesCounter++;
            if(verbose)
            {
                cout << "Adding port range " << portString << endl;
            }
        }
        else
        { //single port
            uint16_t port = atoi(portString.c_str());
            whitelistedPorts->addSinglePort(port);
            if(verbose)
            {
                cout << "Adding single port " << port << endl;
            }
        }
        addPorts(currentNode, ports);
    }
    else
    {
        pos = ports.find_first_of(WHITELIST_PARSER_PORT_RANGE_DELIM);
        if(pos != string::npos)
        { //range
            string firstStringPort = ports.substr(0, pos);
            string secondStringPort = ports.substr(pos + 1);
            if(secondStringPort.empty())
            {
                if(verbose)
                    cout << "Invalid ports range: " << ports << endl;
                addPorts(currentNode, ports);
                return;
            }

            uint16_t port = atoi(firstStringPort.c_str());
            uint16_t port2 = atoi(secondStringPort.c_str());

            whitelistedPorts->addPortRange(port, port2);
            rulesCounter++;
            if(verbose)
                cout << "Adding port range " << ports << endl;
        }
        else
        { //single port
            uint16_t port = atoi(ports.c_str());
            whitelistedPorts->addSinglePort(port);
            if(verbose)
                cout << "Adding single port " << port << endl;
        }
    }
}

void WhitelistParser::addIPAllPorts(uint8_t *ip, uint8_t prefix, IPTrie *trie)
{
    IPTrie *currentNode = trie;
    for(int i = 0; i < prefix; i++)
    {
        //bitset go right
        if(((ip[i / 8] >> (7 - i % 8)) & 1) > 0)
        {
            if(currentNode->right == NULL)
            {
                currentNode->right = new IPTrie();
            }
            //next
            currentNode = currentNode->right;
        }
        else
        { //go left
            if(currentNode->left == NULL)
            {
                currentNode->left = new IPTrie();
            }
            //next
            currentNode = currentNode->left;
        }

        if((i + 1) == prefix)
        { //last pos
            currentNode->allPorts = true;
            currentNode->set = true;
            rulesCounter++;

            if(currentNode->whitelistedPorts == NULL)
                currentNode->whitelistedPorts = new WhitelistedPorts;
        }
    }
    //prefix 0 useless with all whitelisted ports but still
    if(prefix == 0)
    {
        if(currentNode->whitelistedPorts == NULL)
            currentNode->whitelistedPorts = new WhitelistedPorts;

        currentNode->set = true;
        currentNode->allPorts = true;
        rulesCounter++;
    }
}

void WhitelistParser::addIPAndSelectedPorts(uint8_t *ip, uint8_t prefix, IPTrie *trie, string ports)
{
    IPTrie *currentNode = trie;
    for(int i = 0; i < prefix; i++)
    {
        //bitset go right
        if(((ip[i / 8] >> (7 - i % 8)) & 1) > 0)
        {
            if(currentNode->right == NULL)
            {
                currentNode->right = new IPTrie();
            }
            //next
            currentNode = currentNode->right;
        }
        else
        { //go left
            if(currentNode->left == NULL)
            {
                currentNode->left = new IPTrie();
            }
            //next
            currentNode = currentNode->left;
        }

        if((i + 1) == prefix)
        { //last pos
            if(currentNode->whitelistedPorts == NULL)
                currentNode->whitelistedPorts = new WhitelistedPorts;

            addPorts(currentNode, ports);
            currentNode->set = true;
            rulesCounter++;
        }
    }
    //prefix 0
    if(prefix == 0)
    {
        if(currentNode->whitelistedPorts == NULL)
            currentNode->whitelistedPorts = new WhitelistedPorts;

        addPorts(currentNode, ports);
        currentNode->set = true;
        rulesCounter++;
    }
}
