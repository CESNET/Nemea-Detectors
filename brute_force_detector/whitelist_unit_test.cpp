/**
 * \file whitelist_unit_test.cpp
 * \brief Unit test for whitelist
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
#include <cstdlib>

using namespace std;

//init and delete WL for new test instance
#define WL() {								\
    if(wl!=NULL)							\
    {										\
	    delete wl;							\
		wl = NULL;							\
    }										\
    if(wl == NULL)							\
        wl = new Whitelist();				\
    parser = wl->getPointerToParser();		\
}
//parser->setVerbose();

//print test number
#define TEST(x) { WL(); cout<<"Test "<<x<<":"<<endl; }

uint16_t getRandomPort(){return rand() % 65536;}

int failCounter = 0;

void subTestRes(int testNum, string state) {cout<<"Subtest "<<testNum<<": "<<state<<endl; if(state == "fail") failCounter++;}


int main()
{
    Whitelist *wl = NULL;
    WhitelistParser *parser;

    srand(0);

    //add rules using:
    //parser->addSelectedPortRule(ip_addr_t, direction, prefix, string ports);
    //parser->addAllPortRule(ip_addr_t, direction, prefix);
    //for search use
    //wl->isWhitelisted(srcip, dstip, srcPort, dstPort);
    //WHITELIST_PARSER_IP_DIRECTION_ALL
    //WHITELIST_PARSER_IP_DIRECTION_SRC
    //WHITELIST_PARSER_IP_DIRECTION_DST

    ip_addr_t zeroIp;
    ip_from_str("0.0.0.0", &zeroIp);
    uint16_t zeroPort = 0;

    ip_addr_t ip1, ip2, ip3, ip4, ip5;

    ip_from_str("1.1.1.1", &ip1);
    ip_from_str("1.1.1.2", &ip2);
    ip_from_str("3.3.3.3", &ip3);
    ip_from_str("3.3.3.4", &ip4);
    ip_from_str("255.255.255.255", &ip5);


	/*******************************************
	 ***************** TEST 1 ******************
	 ****** TEST FOR ALL PORTS, ALL DIR ********
	 *******************************************/
    TEST(1);

    parser->addAllPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_ALL, 32);

    //ip should be whitelisted
    if(wl->isWhitelisted(&ip1, &zeroIp, getRandomPort(), getRandomPort()))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&ip2, &zeroIp, getRandomPort(), getRandomPort()))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //ip should be whitelisted
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), getRandomPort()))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), getRandomPort()))
        subTestRes(4, "passed");
    else
        subTestRes(4, "fail");

    /*******************************************
     ***************** TEST 2 ******************
     ****** TEST FOR ALL PORTS, SRC DIR ********
     *******************************************/
    TEST(2);
    parser->addAllPortRule(ip2, WHITELIST_PARSER_IP_DIRECTION_SRC, 32);
    //ip should be whitelisted
    if(wl->isWhitelisted(&ip2, &zeroIp, getRandomPort(), getRandomPort()))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&ip1, &zeroIp, getRandomPort(), getRandomPort()))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&ip3, &zeroIp, getRandomPort(), getRandomPort()))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    /*******************************************
     ***************** TEST 3 ******************
     ****** TEST FOR ALL PORTS, DST DIR ********
     *******************************************/
    TEST(3);
    parser->addAllPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_DST, 32);
    //ip should be whitelisted
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), getRandomPort()))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), getRandomPort()))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip3, getRandomPort(), getRandomPort()))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    /*******************************************
     ***************** TEST 4 ******************
     ****** TEST FOR SINGLE PORT, ALL DIR ******
     *******************************************/
    TEST(4);
    parser->addSelectedPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_ALL, 32, "80");

    //ip port should be whitelisted
    if(wl->isWhitelisted(&ip1, &zeroIp, 80, zeroPort))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&ip2, &zeroIp, 80, 80))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //ip port should be whitelisted
    if(wl->isWhitelisted(&zeroIp, &ip1, zeroPort, 80))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip2, 80, 80))
        subTestRes(4, "passed");
    else
        subTestRes(4, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip1, 79, 79))
        subTestRes(5, "passed");
    else
        subTestRes(5, "fail");

    /*******************************************
     ***************** TEST 5 ******************
     ****** TEST FOR SINGLE PORT, SRC DIR ******
     *******************************************/
    TEST(5);
    parser->addSelectedPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_SRC, 32, "80");
    //ip should be whitelisted
    if(wl->isWhitelisted(&ip1, &zeroIp, 80, getRandomPort()))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&ip1, &zeroIp, 79, 80))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&ip3, &zeroIp, 80, 80))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    /*******************************************
     ***************** TEST 6 ******************
     ****** TEST FOR SINGLE PORT, DST DIR ******
     *******************************************/
    TEST(6);
    parser->addSelectedPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_DST, 32, "80");
    //ip should be whitelisted
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 80))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 80))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 79))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    /*******************************************
     ***************** TEST 7 ******************
     ****** TEST FOR RANGE PORTS, DST DIR ******
     *******************************************/
    TEST(7);
    parser->addSelectedPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_DST, 32, "80-100");
    //inside 80-100 range
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 95))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //inside 80-100 range
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 80))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //inside 80-100 range
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 100))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    //outside 80-100 range
    if(!wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 79))
        subTestRes(4, "passed");
    else
        subTestRes(4, "fail");

    //outside 80-100 range
    if(!wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 101))
        subTestRes(5, "passed");
    else
        subTestRes(5, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 80))
        subTestRes(6, "passed");
    else
        subTestRes(6, "fail");

    /*******************************************
     ***************** TEST 8 ******************
     ********* TEST FOR SINGLE PORT ************
     ******** & RANGE PORTS, DST DIR ***********
     *******************************************/
    TEST(8);
    parser->addSelectedPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_DST, 32, "50,10-20,1000");
    //1000 whitelisted
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 1000))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    //inside 80-100 range
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 10))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    //inside 80-100 range
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 18))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    //50 whitelisted
    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 50))
        subTestRes(4, "passed");
    else
        subTestRes(4, "fail");

    //ip should not be whitelisted
    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 50))
        subTestRes(5, "passed");
    else
        subTestRes(5, "fail");

    /*******************************************
     ***************** TEST 9 ******************
     ***** SHORT PREFIX SINGLE PORT DST DIR ****
     *******************************************/
    TEST(9);
    parser->addSelectedPortRule(ip1, WHITELIST_PARSER_IP_DIRECTION_DST, 16, "10-20");
    parser->addAllPortRule(ip3, WHITELIST_PARSER_IP_DIRECTION_DST, 16);

    if(wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 15))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    if(wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 15))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    if(!wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 21))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 9))
        subTestRes(4, "passed");
    else
        subTestRes(4, "fail");

    if(wl->isWhitelisted(&zeroIp, &ip3, getRandomPort(), getRandomPort()))
        subTestRes(5, "passed");
    else
        subTestRes(5, "fail");

    if(wl->isWhitelisted(&zeroIp, &ip4, getRandomPort(), getRandomPort()))
        subTestRes(6, "passed");
    else
        subTestRes(6, "fail");

    /*******************************************
     ***************** TEST 10 ******************
     ***** ZERO PREFIX SINGLE PORT DST DIR ****
     *******************************************/
    TEST(10);
    parser->addSelectedPortRule(ip5, WHITELIST_PARSER_IP_DIRECTION_DST, 0, "10-20");

    if(wl->isWhitelisted(&zeroIp, &ip4, getRandomPort(), 10))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    if(!wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 9))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    parser->addAllPortRule(ip3, WHITELIST_PARSER_IP_DIRECTION_DST, 0);
    if(wl->isWhitelisted(&zeroIp, &ip2, getRandomPort(), 9))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    /*******************************************
     ***************** TEST 11 *****************
     ********  PREFIX SINGLE PORT DST DIR ******
     *******************************************/
    TEST(11);
    parser->addSelectedPortRule(ip5, WHITELIST_PARSER_IP_DIRECTION_DST, 8, "25");

    if(wl->isWhitelisted(&zeroIp, &ip5, getRandomPort(), 25))
        subTestRes(1, "passed");
    else
        subTestRes(1, "fail");

    if(!wl->isWhitelisted(&zeroIp, &ip5, 25, 0))
        subTestRes(2, "passed");
    else
        subTestRes(2, "fail");

    if(!wl->isWhitelisted(&zeroIp, &ip1, getRandomPort(), 25))
        subTestRes(3, "passed");
    else
        subTestRes(3, "fail");

    if(failCounter == 0)
        cout << "=====================" << "OK" << "=====================" << endl;
    else
        cout << "====================" << "FAIL" << "====================" << endl;

    return 0;
}
