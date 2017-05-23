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
#include <regex.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

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

/**
 * Message sent to server to check if it supports stratum protocol.
 */
const char *MINER_POOL_BITCOIN_STR = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"cpuminer/2.4.3\"]}\x0a";
const char *MINER_POOL_ETHEREUM_STR = "{\"worker\": \"eth1.0\", \"jsonrpc\": \"2.0\", \"params\": [\"0x42/k.work1/email@mail\", \"x\"], \"id\": 2, \"method\": \"eth_submitLogin\"}\x0a";
const char *MINER_POOL_MONERO_STR = "{\"method\": \"login\", \"params\": {\"login\": \"42\", \"pass\": \"x\", \"agent\": \"xmr/1.0\"}, \"id\": 1}\x0a";
const char *MINER_POOL_ZCASH_STR = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"equihashminer\", null, \"zec\", \"6666\"]}\x0a";
/*
const char *MINER_POOL_ZCASH_STR2 = "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"equihashminer\", null, \"zec\", \"6666\"]}\x0a"
                                    "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"t.k\",\"pass\"]}\x0a"
                                    "{\"id\": 5, \"method\": \"mining.extranonce.subscribe\", \"params\": []}\x0a";
*/


/*
 * Default values for timeouts in seconds
 */
static int CONNECTION_TIMEOUT = 10;
static int READ_TIMEOUT = 10;


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
int get_data(char *ip, int port, const char *data_out, char **data_in)
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
        DEBUG_PRINT("Could not create socket\n");
        return ERR_SOCKET_CREATE;
    }

    // Clear out descriptor sets for select
    // add socket to the descriptor sets
    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);
    wset = rset;

    // Set socket nonblocking flag
    if((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
        DEBUG_PRINT("Could not socket flags\n");
        close(sockfd);
        return ERR_SOCKET_FGET;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        DEBUG_PRINT("Could not set nonblocking flags for socket\n");
        close(sockfd);
        return ERR_SOCKET_FSET;
    }

    // Set timeout for socket
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = CONNECTION_TIMEOUT;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));

    // Clear and copy IP and port to server structure
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(ip);
    serv_addr.sin_port = htons(port);

    // Try to connect
    DEBUG_PRINT("Trying to connect to server...\n");
    if ((ret = connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr))) < 0) {
        if (errno != EINPROGRESS) {
            DEBUG_PRINT("Connect error...\n");
            close(sockfd);
            return ERR_CONNECT;
        }
    }

    if (ret != 0) {
        // We need to wait for connect
        if ((ret = select(sockfd + 1, &rset, &wset, NULL, &tv)) < 0) {
            DEBUG_PRINT("Select error!\n");
            close(sockfd);
            return ERR_SELECT;
        }
        if (ret == 0) {
            // Timeout
            DEBUG_PRINT("Connection timed out!\n");
            close(sockfd);
            return ERR_CONNECT_TIMEOUT;
        }
    }


    // Send data to server
    DEBUG_PRINT("Sending data to server: '%s'\n", data_out);
    n = write(sockfd, data_out, strlen(data_out));
    if (n < 0) {
        DEBUG_PRINT("No data was written\n");
        close(sockfd);
        return ERR_WRITE;
    }


    // Clear out descriptor sets for select
    // add socket to the descriptor sets
    FD_ZERO(&rset);
    FD_SET(sockfd, &rset);

    // Recieve data from server
    DEBUG_PRINT("Reading data from server...\n");
    memset(buffer, 0, 256);

    // We need to wait for data
    tv.tv_sec = READ_TIMEOUT;
    if ((ret = select(sockfd + 1, &rset, NULL, NULL, &tv)) < 0) {
        DEBUG_PRINT("Select error!\n");
        close(sockfd);
        return ERR_SELECT;
    }
    if (ret == 0) {
        // Timeout
        DEBUG_PRINT("Read timed out!\n");
        close(sockfd);
        return ERR_READ_TIMEOUT;
    }
    // Data is ready to be read
    n = read(sockfd, buffer, 255);
    if (n < 0) {
        DEBUG_PRINT("Read error: %s(%d)\n", strerror(errno), n);
        close(sockfd);
        return ERR_READ;
    }
    close(sockfd);

    // Allocate memory for recieved data and copy it from temporary buffer
    *data_in = (char*)malloc(sizeof(char) * (strlen(buffer) + 1)); // + 1 for terminating byte
    if (*data_in == NULL) {
        DEBUG_PRINT("Could not allocate data\n");
        return ERR_MEMORY;
    }
    memcpy(*data_in, buffer, strlen(buffer));
    (*data_in)[strlen(buffer)] = 0; // terminate

    DEBUG_PRINT("%s\n", *data_in);

    DEBUG_PRINT("Successfully received data\n");
    return DATA_OK;
}


/**
 * \brief Check using regex for stratum protocol in specified data.
 * \param re_str Regular expression to find in data.
 * \param data Data to be checked for stratum protocol.
 * \return 1 on successfull match, 0 otherwise.
 */
int find_stratum_in_data(const char *re_str, char *data)
{
    const char *regex_str = re_str;
    regex_t preg;
    int res;

    // Compile regular expression
    if ((res = regcomp(&preg, regex_str, REG_NOSUB)) != 0) {
        char reg_err_buf[100];
        regerror(res, &preg, reg_err_buf, 99);
        fprintf(stderr, "Error: %s\n", reg_err_buf);
        return ERR_REGEX;
    }

    // Check regex
    if (regexec(&preg, data, 0, NULL, 0) != REG_NOMATCH) {
        // Pattern was found
	DEBUG_PRINT("stratum detected\n");
        return STRATUM_MATCH;
    } else {
        // Pattern was not found
	DEBUG_PRINT("stratum NOT detected\n");
        return STRATUM_NO_MATCH;
    }
}



/**
 * \brief Chech given IP address and port for stratum protocol
 * \param ip   IP adddress of remote server.
 * \param port Port on the remote server.
 * \param pool_id ID of identified mining pool will be stored here.
 * \return True on success, false otherwise.
 */
int stratum_check_server(char *ip, uint16_t port, uint8_t *pool_id)
{
    char *data_in = NULL;
    int ret;

    // TEST FOR BITCOIN
    if ((ret = get_data(ip, port, MINER_POOL_BITCOIN_STR, &data_in)) == DATA_OK) {
        ret = find_stratum_in_data("mining.notify", data_in);
        free(data_in);

        if (ret == STRATUM_MATCH) {
            DEBUG_PRINT("BITCOIN\n");
            *pool_id = STRATUM_MPOOL_BITCOIN;
            return ret;
        }

        // TEST FOR MONERO
        if ((ret = get_data(ip, port, MINER_POOL_MONERO_STR, &data_in)) == DATA_OK) {
            ret = find_stratum_in_data(".*blob.*job_id.*target.*", data_in);
            free(data_in);

            if (ret == STRATUM_MATCH) {
                DEBUG_PRINT("MONERO\n");
                *pool_id = STRATUM_MPOOL_MONERO;
                return ret;
            }

            // TEST FOR ETHEREUM
            if ((ret = get_data(ip, port, MINER_POOL_ETHEREUM_STR, &data_in)) == DATA_OK) {
                ret = find_stratum_in_data("jsonrpc.*result\":[ \t]*true", data_in);
                free(data_in);

                if (ret == STRATUM_MATCH) {
                    DEBUG_PRINT("ETHEREUM\n");
                    *pool_id = STRATUM_MPOOL_ETHEREUM;
                    return ret;
                }

                // TEST FOR ZCASH
                if ((ret = get_data(ip, port, MINER_POOL_ZCASH_STR, &data_in)) == DATA_OK) {
                    ret = find_stratum_in_data("mining.set_target", data_in);
                    free(data_in);

                    if (ret == STRATUM_MATCH) {
                        DEBUG_PRINT("ZCASH\n");
                        *pool_id = STRATUM_MPOOL_ZCASH;
                        return ret;
                    }
                } else {
                    return ret;
                }
            } else {
                return ret;
            }
        } else {
            return ret;
        }
    } else {
        return ret;
    }

    return ret;
}


/**
 * \brief Set timeout for stratum protocol checker.
 * \param type Type of timeout to set.
 * \param timeout New value to set timeout to.
 */
void stratum_set_timeout(int type, int timeout)
{
    switch (type) {
        case STRATUM_CONN_TIMEOUT: CONNECTION_TIMEOUT = timeout;
                                   break;
        case STRATUM_READ_TIMEOUT: READ_TIMEOUT = timeout;
                                   break;
        default: fprintf(stderr, "Stratum checker: Unknown timeout type '%d'\n", type);
    }
}


/**
 * \brief USED ONLY FOR TESTING PURPOSES. Function convert error code
 *        to brief error message.
 * \param err_code Code to convert.
 * \return String with corresponding error message.
 */
const char *stratum_error_string(int err_code)
{
    switch (err_code) {
        case ERR_REGEX: return "Could not create regex";
        case DATA_OK: return "Data was received";
        case STRATUM_MATCH: return "Stratum was found";
        case STRATUM_NO_MATCH: return "Stratum was not found";
        case ERR_SOCKET_CREATE: return "Could not create socket";
        case ERR_SOCKET_FGET: return"Could not socket flags";
        case ERR_SOCKET_FSET: return "Could not set nonblocking flags for socket";
        case ERR_CONNECT: return "Connect error";
        case ERR_SELECT: return "Select error";
        case ERR_CONNECT_TIMEOUT: return "Connection timed out!";
        case ERR_WRITE: return "No data was writed";
        case ERR_READ: return "Read error";
        case ERR_READ_TIMEOUT: return "Read timeout";
        case ERR_MEMORY: return "Could not allocate memory";
        default: return "Unknown error";
    }
}

/**
 * \brief USED ONLY FOR TESTING PURPOSES. Function convert pool id
 *        to its name.
 * \param id ID to convert.
 * \return String with corresponding pool name.
 */
const char *stratum_mpool_string(uint8_t id)
{
    switch (id) {
        case STRATUM_MPOOL_BITCOIN: return "Bitcoin (BTC)";
        case STRATUM_MPOOL_MONERO: return "Monero (XMR)";
        case STRATUM_MPOOL_ETHEREUM: return "Ethereum (ETH)";
        case STRATUM_MPOOL_ZCASH: return "ZCash (ZEC)";
        default: return "Unknown pool";
    }
}
