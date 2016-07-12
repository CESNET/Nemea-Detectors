/**
 * \file utils.cpp
 * \brief Nemea module for detecting bitcoin miners.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2016
 */

// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <nemea-common.h>
#include "fields.h"
#include "miner_detector.h"
#include "utils.h"

#include <iostream>
#include <fstream>
#include <map>
#include <string>


//#define DEBUG

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, "DEBUG: "  __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif


using namespace std;


const char *MINER_POOL_SUBSCRIBE_STR = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"cpuminer/2.4.3\"]}\x0a";


/**
 * \brief Create structure from specified parameters.
 * \param suspect IP address of suspect.
 * \param pool    IP address of mining pool.
 * \param port    Port on the mining pool server.
 * \return Structure containg specified parameters.
 */
suspect_item_key_t create_suspect_key(ip_addr_t& suspect, ip_addr_t& pool, uint16_t port)
{
    suspect_item_key_t key;
    memset(&key, 0, sizeof(suspect_item_key_t));

    memcpy(&key.suspect_ip, &suspect, sizeof(ip_addr_t));
    memcpy(&key.pool_ip, &pool, sizeof(ip_addr_t));
    key.port = port;

    return key;
}


/**
 * \brief Send data to server and wait for reply.
 * \param ip       String containg IP address of the server.
 * \param port     Port on the remote server.
 * \param data_out Data to be sent to server.
 * \param data_in  Data server sent back as reply. BEWARE: Only valid on success!
 * \return 1 on success, 0 otherwise.
 */
int get_data(string &ip, int port, const char *data_out, char **data_in)
{
    int flags;
    int ret;
    int sockfd, n;
    fd_set rset, wset;
    struct sockaddr_in serv_addr;
    char buffer[256];

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return 0;
    }

    // Clear out descriptor sets for select
    // add socket to the descriptor sets
    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    wset = rset;

    // Set socket nonblocking flag
    if((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        return 0;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return 0;
    }

    // Set timeout for socket
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = STRATUM_RECV_TIMEOUT;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

    // Clear and copy IP and port to server structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip.c_str());
    serv_addr.sin_port = htons(port);

    // Try to connect
    DEBUG_PRINT("Trying to connect to server...\n");
    if ((ret = connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr))) < 0) {
        if (errno != EINPROGRESS) {
            DEBUG_PRINT("Connect error...\n");
            return 0;
        }
    }

    if (ret != 0) {
        // We need to wait for connect
        if ((ret = select(sockfd + 1, &rset, &wset, NULL, &tv)) < 0) {
            return 0;
            DEBUG_PRINT("Select error!\n");
        }
        if (ret == 0) {
            // Timeout
            DEBUG_PRINT("Connection timed out!\n");
            return 0;
        }
    }


    // Send data to server
    DEBUG_PRINT("Sending data to server...\n");
    n = write(sockfd, data_out, strlen(data_out));
    if (n < 0) {
         return 0;
    }

    // Recieve data from server
    DEBUG_PRINT("Reading data from server...\n");
    memset(buffer, 0, 256);
    n = read(sockfd,buffer,255);
    if (n < 0) {
         return 0;
    }
    close(sockfd);

    // Allocate memory for recieved data and copy it from temporary buffer
    *data_in = (char*)malloc(sizeof(char) * strlen(buffer));
    if (*data_in == NULL) {
        return 0;
    }
    memcpy(*data_in, buffer, strlen(buffer));

    return 1;
}


/**
 * \brief Check using regex for stratum protocol in specified data.
 * \param data Data to be checked for stratum protocol.
 * \return 1 on successfull match, 0 otherwise.
 */
int find_stratum_in_data(char *data)
{
    const char *regex_str = "mining.notify";
    regex_t preg;
    int res;

    // Compile regular expression
    if ((res = regcomp(&preg, regex_str, REG_NOSUB)) != 0) {
        char reg_err_buf[100];
        regerror(res, &preg, reg_err_buf, 99);
        fprintf(stderr, "Error: %s\n", reg_err_buf);
        return 0;
    }

    // Check regex
    if (regexec(&preg, data, 0, NULL, 0) != REG_NOMATCH) {
        // Pattern was found
        return 1;
    } else {
        // Pattern was not found
        return 0;
    }
}



/**
 * \brief Chech given IP address and port for stratum protocol
 * \param ip   IP adddress of remote server.
 * \param port Port on the remote server.
 * \return True on success, false otherwise.
 */
bool check_for_stratum_protocol(std::string ip, uint16_t port)
{
    char *data_in = NULL;

    if (get_data(ip, port, MINER_POOL_SUBSCRIBE_STR, &data_in)) {
        if (find_stratum_in_data(data_in)) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}
