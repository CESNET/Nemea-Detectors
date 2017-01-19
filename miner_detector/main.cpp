/**
 * \file main.cpp
 * \brief Nemea module for detecting bitcoin miners.
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2016
 */


// Information if sigaction is available for nemea signal macro registration
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <pthread.h>

#include <nemea-common.h>
#include <libtrap/trap.h>
#include <unirec/unirec.h>
#include <ctype.h>
#include "fields.h"

#include "miner_detector.h"
#include "sender.h"
#include "patternstrings.h"

UR_FIELDS(
    ipaddr SRC_IP,
    ipaddr DST_IP,
    uint16 SRC_PORT,
    uint16 DST_PORT,
    uint8 TCP_FLAGS,
    uint8 PROTOCOL,
    uint32 PACKETS,
    uint64 BYTES,
    time TIME_FIRST,
    time TIME_LAST,
    uint32 EVENT_SCALE,
)
// Struct with information about module
trap_module_info_t *module_info = NULL;

#define MODULE_BASIC_INFO(BASIC) \
  BASIC("miner_detector","Module for detecting bitcoin pool mining.",1,1)

#define MODULE_PARAMS(PARAM) \
  PARAM('u', "user-conf", "Specify user configuration file for miner detector. [Default: " SYSCONFDIR "/miner_detector/userConfigurationFile.xml]", required_argument, "string")



int STOP = 0;

Sender *SENDER;

extern pthread_t MINER_DETECTOR_CHECK_THREAD_ID;


// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(STOP = 1);


/**
 * *********************
 * \brief MAIN FUNCTION
 * *********************
 */
int main(int argc, char **argv)
{
    int ret;

    // Set defaukt file name
    char *userFile = (char*) SYSCONFDIR "/miner_detector/userConfigFile.xml";

    // ***** TRAP initialization *****
    INIT_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
    TRAP_DEFAULT_INITIALIZATION(argc, argv, *module_info);
    // Register signal handler.
    TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

    // Initialize sender
    bool senderState;
    SENDER = new Sender(&senderState);
    if(!senderState)
    {
        cerr << "Error: Could not initialize sender!\n";
        delete SENDER;
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return 4;
    }



    // ***** Parse arguments *****
    signed char opt;
    while((opt = TRAP_GETOPT(argc, argv, module_getopt_string, long_options)) != -1) {
        switch (opt) {
            case 'u': // Custom userConfig file
                userFile = optarg;
                break;
            default:
                fprintf(stderr, "Error: Invalid arguments.\n");
                delete SENDER;
                trap_finalize();
                FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
                return 3;
        }
    }

    // ***** Create cofig structure *****
    config_struct_t *config = (config_struct_t *) malloc(sizeof(config_struct_t));
    if (config == NULL) {
        cerr << "Error: Could not allocate memory for configuration structure." << endl;
        delete SENDER;
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }
    if (loadConfiguration((char*)MODULE_CONFIG_PATTERN_STRING, userFile, config, CONF_PATTERN_STRING)) {
        cerr << "Error: Could not parse XML configuration." << endl;
        delete SENDER;
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return EXIT_FAILURE;
    }




    // ***** Initialize miner detector *****
    if (!miner_detector_initialization(config)) {
        fprintf(stderr, "Miner detector initialization failed!\n");
        delete SENDER;
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return 1;
    }



    // ***** Create UniRec template *****
    const char *unirec_specifier = "SRC_IP,DST_IP,SRC_PORT,DST_PORT,TCP_FLAGS,PROTOCOL,PACKETS,BYTES,TIME_FIRST,TIME_LAST";
    char *ur_err_str = NULL;
    ur_template_t *tmplt = ur_create_input_template(0, unirec_specifier, &ur_err_str);
    if (tmplt == NULL) {
        fprintf(stderr, "Error: Invalid UniRec specifier.\n");
        if (ur_err_str) {
            fprintf(stderr, "%s\n", ur_err_str);
            free(ur_err_str);
        }
        delete SENDER;
        trap_finalize();
        FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)
        return 4;
    }



    // ***** Main processing loop *****
    while (!STOP) {
        // Receive data from any interface, wait until data are available
        const void *data;
        uint16_t data_size;
	    ret = trap_recv(0, &data, &data_size);

        // Handle format change messages
        if (ret == TRAP_E_FORMAT_CHANGED) {
            const char *spec = NULL;
            uint8_t data_fmt;
            if (trap_get_data_fmt(TRAPIFC_INPUT, 0, &data_fmt, &spec) != TRAP_E_OK) {
                fprintf(stderr, "Data format was not loaded.");
                break;
            }
            tmplt = ur_define_fields_and_update_template(spec, tmplt);
            if (tmplt == NULL) {
                fprintf(stderr, "Template could not be edited");
                break;
            }
            continue;
        }


        TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);


        // Check size of received data
        if (data_size < ur_rec_fixlen_size(tmplt)) {
            if (data_size <= 1) {
                break; // End of data (used for testing purposes)
            }
            fprintf(stderr, "Error: data with wrong size received (expected size: %i, received size: %i)\n",
            ur_rec_fixlen_size(tmplt), data_size);
            break;
        }

        // ***** Miner detector process data *****
        miner_detector_process_data(tmplt, data);
    }

    // Wait for miner detector to finish
    //printf("DEBUG_MAIN: Waiting for miner detector to finish...\n");
    STOP = 1;
    pthread_join(MINER_DETECTOR_CHECK_THREAD_ID, NULL);

    // Send 1 Byte sized data to both output interfaces to signalize end
    char dummy[1] = {0};
    trap_send(0, dummy, 1);


   // ***** Cleanup *****
   // Do all necessary cleanup before exiting
   // (close interfaces and free allocated memory)
    delete SENDER;
    trap_finalize();
    free(config);

   ur_free_template(tmplt);
   ur_finalize();
   FREE_MODULE_INFO_STRUCT(MODULE_BASIC_INFO, MODULE_PARAMS)

   return 0;
}
