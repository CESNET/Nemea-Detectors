#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <err.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <string>
#include <sstream>
#include "hoststats.h"
#include "../aux_func.h"
#include "processdata.h"
#include "../config.h"
#include "requesthandlers.h"
#include "profile.h"
//#include "sshdetection.h"

#include "../BloomFilter.hpp"
//TRAP
extern "C" {
   #include <libtrap/trap.h>
}


#define BUFFER    (1024)
#define QUEUE     (2)
#define SLEEP     (10)
#define LISTENFDS (16)

#define UNKNOWN "unknown"

#define HASHMAPSIZE 100000
#define SHMSZ    1000

/* define FG_MODE for skip daemon() mode */
// #define FG_MODE

using namespace std;

////////////////////////////
// Global variables

bool background = true;  // Run in background
int log_syslog = true;   // Log into syslog
int log_upto = LOG_ERR; // Log up to level 
static int terminated = 0;
ur_template_t *tmpl_in = NULL;
ur_template_t *tmpl_out = NULL;
extern pthread_mutex_t detector_start;

////////////////////////////
// Module global variables

static string server;
static string port;



///////////////////////////////////////////////////
// Flow filter functions for profile definitions

// SSH (TCP port 22)
bool ff_ssh(const flow_key_t& key, const flow_record_t& rec)
{
   return (key.proto == 6 && (key.sport == 22 || key.dport == 22));
}

// Telnet (TCP port 23)
bool ff_telnet(const flow_key_t& key, const flow_record_t& rec)
{
   return (key.proto == 6 && (key.sport == 23 || key.dport == 23));
}

// DNS (TCP and UDP ports 53)
bool ff_dns(const flow_key_t& key, const flow_record_t& rec)
{
   return ((key.proto == 6 || key.proto == 17) && (key.sport == 53 || key.dport == 53));
}

///////////////////////////////////////////////////
// Struct with information about Nemea module
trap_module_info_t module_info = {
   (char *) "HostStats module", // Module name
   // Module description
   (char *) "This module works as HostStats plugin for NfSen (Listens on network interface \n"
      "and process requests for host statistics), but adds extra input for TRAP.\n"
      "\n"
      "USAGE ./hoststatserv ARGUMENTS\n"
      "    -s IPADDRESS   IP address \n"
      "    -p NUMBER      Port number\n"
      "    -f             Stay in foreground (program runs in background by default)\n"
      "\n"
      "Note: All parameters are taken from hoststats.conf bydefault.\n"
      "\n" 
      "TRAP Interfaces:\n"
      "   Inputs: 1\n"
      "   Outputs: 1\n",
   1, // Number of input TRAP interfaces
   1, // Number of output TRAP interfaces
};

///////////////////////////////////////////////////////////////////////////////
/**
 * New request from frontend
 */
void *service(void * connectfd)
{
   ssize_t n, r;
   char buf[BUFFER];
   string params;
   int fd = * ((int *) connectfd);
   int action = -1;
   bool stop = false;
   
   // Read null-terminated message from socket
   while ( !stop && (n = read(fd, buf, BUFFER)) > 0) {
      r = 0;
      if (action == -1 && n > 0) {
         action = buf[0];
         r = 1;
         //log(LOG_INFO, "Trap action %i", action);
      }
      while (r < n && buf[r] != 0) {
         params += buf[r];
         r++;
      }
      stop = (buf[r] == 0);
   }
   
   // Message about new data available
   if (action == NEW_DATA) {
      log(LOG_WARNING, "NEW_DATA action is not supported in the HostStatsNemea module");
   }
   // Request from frontend
   else if (action > 0 && action < num_request_handlers && request_handlers[action] != 0) {
      log(LOG_INFO, "Request received (code: %i, params: \"%s\").", action, params.c_str());
      string ret = request_handlers[action](params);
      r = write(fd, ret.c_str(), ret.length());
      if (r == (ssize_t) -1)
         log(LOG_ERR, "Could not write reply, error status: %i", errno);
      if (r != (ssize_t) ret.length())
         log(LOG_ERR, "write(): Buffer written just partially");
      log(LOG_INFO, "Request %i replied.", action);
   }
   else {
      log(LOG_ERR, "Unknown request (code %i) received.", action);
   }
   close(fd);
   pthread_exit(NULL);
}

int arguments(int argc, char *argv[])
{
   char opt;
   
   while ((opt = getopt(argc, argv, "s:p:f")) != -1) {
      switch (opt) {
      case 's':  // Server
         server = string(optarg);
         break;
      case 'p':  // port
         port = string(optarg);
         break;
      case 'f':  // foreground
         background = false;
         break;
      default:  // invalid arguments
         errx(1,"invalid arguments");
      }
   }
   return 1;
}

void parse_logmask(string &mask);

void terminate_daemon(int signal)
{
   Configuration *cf;
   string logmask;

   switch (signal) {
   case SIGHUP:
      syslog(LOG_NOTICE, "Cought HUP signal -> reload configuration...");
      cf = Configuration::getInstance();
      cf->reload();
      logmask = cf->getValue("log-upto-level");
      parse_logmask(logmask);
      break;
   case SIGTERM:
      trap_terminate();
      terminated = 1;
      log(LOG_NOTICE, "Cought TERM signal...");
      break;
   case SIGINT:
      trap_terminate();
      terminated = 1;
      log(LOG_NOTICE, "Cought INT signal...");
      break;
   default:
      break;
   }
}

void parse_logmask(string &mask)
{
   if (mask.compare("LOG_EMERG") == 0) {
      log_upto = LOG_EMERG;
   } else if (mask.compare("LOG_ALERT") == 0) {
      log_upto = LOG_ALERT;
   } else if (mask.compare("LOG_CRIT") == 0) {
      log_upto = LOG_CRIT;
   } else if (mask.compare("LOG_ERR") == 0) {
      log_upto = LOG_ERR;
   } else if (mask.compare("LOG_WARNING") ==0) {
      log_upto = LOG_WARNING;
   } else if (mask.compare("LOG_NOTICE") == 0) {
      log_upto = LOG_NOTICE;
   } else if (mask.compare("LOG_INFO") == 0) {
      log_upto = LOG_INFO;
   } else if (mask.compare("LOG_DEBUG") == 0) {
      log_upto = LOG_DEBUG;
   }
   setlogmask(LOG_UPTO(log_upto));
}

int main(int argc, char *argv[])
{
   int rc = TRAP_E_OK;
   trap_ifc_spec_t ifc_spec;

   openlog(NULL, LOG_NDELAY, 0);
   log(LOG_INFO, "HostStats started");
   
   // TRAP parse params
   rc = trap_parse_params(&argc, argv, &ifc_spec);
   if (rc != TRAP_E_OK) {
      if (rc == TRAP_E_HELP) {
         trap_print_help(&module_info);
         return 0;
      }
      log(LOG_ERR, "ERROR in parsing of parameters for TRAP: %s\n", trap_last_error_msg);
      return 1;
   }

   // UniRec template
   tmpl_in = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL,TIME_FIRST,TIME_LAST,PACKETS,BYTES,TCP_FLAGS,LINK_BIT_FIELD,DIR_BIT_FIELD");
   tmpl_out = ur_create_template("SRC_IP,DST_IP,SRC_PORT,DST_PORT,PROTOCOL");
   if (tmpl_in == NULL || tmpl_out == NULL) {
      log(LOG_ERR, "Error when creating UniRec template.\n");
      trap_free_ifc_spec(ifc_spec);
      if (tmpl_in == NULL) ur_free_template(tmpl_in);
      if (tmpl_out == NULL) ur_free_template(tmpl_out);
      return 1;
   }


   int listenfd[LISTENFDS], connectfd[LISTENFDS];
   struct hostent *hostent;
   struct sigaction sa;
   int listenfds, gai_error, i, maxfd;
   struct addrinfo hints, *res, *res0;
   fd_set rset, allset;

   
   // Initialize Configuration singleton
   Configuration *config = Configuration::getInstance();
   
   // Load default configuration from config file
   config->lock();
   server = config->getValue("listen-interface");
   port = config->getValue("listen-port");
   
   // Default configuration may be overwritten by arguments
   arguments(argc, argv);

   /* Set logmask if used */
   string logmask = config->getValue("log-upto-level");
   if (!logmask.empty()) {
      parse_logmask(logmask);
   }
   
   // ***** Profiles *****
   // TODO: Read specifiaction of profiles from config
   vector<pair<string, flow_filter_func_ptr> > prof_spec;
   prof_spec.push_back(make_pair("all", (flow_filter_func_ptr)NULL));
   prof_spec.push_back(make_pair("ssh", ff_ssh));
   prof_spec.push_back(make_pair("telnet", ff_telnet));
   prof_spec.push_back(make_pair("dns", ff_dns));
   
   config->unlock();

   // BloomFilter
   bloom_parameters bp;
   bp.projected_element_count = 5000000;
   bp.false_positive_probability = 0.01;
   bp.compute_optimal_parameters();
   //log(LOG_INFO, "process_data: Creating Bloom Filter, table size: %d, hashes: %d",
   //    bp.optimal_parameters.table_size, bp.optimal_parameters.number_of_hashes);


   // Create profiles
   for (int i = 0; i < prof_spec.size(); i++) {
      profiles.push_back(new Profile(prof_spec[i].second, prof_spec[i].first));
      if (profiles.back()->database.connect() != 0) {
         log(LOG_ERR, "Error in initialization of database of profile \"%s\"", prof_spec[i].first.c_str());
         while (i >= 0)
            delete profiles[i--];
         return 1;
      }
      profiles.back()->bf_active = new bloom_filter(bp);
      profiles.back()->bf_learn = new bloom_filter(bp);
   }

   // ***** Initialization done, start server *****

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;
   
   const char *addr;
   if (server == "" || server == "any")
      addr = NULL;
   else
      addr = server.c_str();
   
   // Create a linked list of addrinfo structures, one for each address
   // corresponding to server.c_str() (e.g. IPv4 and IPv6)
   if ((gai_error = getaddrinfo(addr, port.c_str(), &hints, &res0)) != 0)
      errx(1, "getaddrinfo(): %s", gai_strerror(gai_error));
   
   // Create sockets, bind and losten on all addresses
   listenfds = 0;
   for (res = res0; res != NULL && listenfds < LISTENFDS; res = res->ai_next) {
      if ((listenfd[listenfds] = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) == -1)
         err(1, "socket()");
      
      log(LOG_DEBUG, "Bind socket");
      if (bind(listenfd[listenfds], res->ai_addr, res->ai_addrlen) == -1) {
         warn("bind()");
         listenfds++;
         continue;
      }
      
      if (listen(listenfd[listenfds], QUEUE) == -1)
         warn("listen()");
      listenfds++;
      
      // Print the address and port we are listening on
      char a[48] = "err";
      unsigned short port = 0;
      if (res->ai_family == AF_INET) {
         inet_ntop(res->ai_family, (void*)(&((struct sockaddr_in*)res->ai_addr)->sin_addr), a, 48);
         port = ntohs(((struct sockaddr_in*)res->ai_addr)->sin_port);
      }
      else if (res->ai_family == AF_INET6) {
         inet_ntop(res->ai_family, (void*)(&((struct sockaddr_in6*)res->ai_addr)->sin6_addr), a, 48);
         port = ntohs(((struct sockaddr_in6*)res->ai_addr)->sin6_port);
      }
      
      // if ANY address, break (otherwise next bind says "address already in use")
//       if (addr == NULL) {
//          log(LOG_INFO, "Listening on ANY port %hu", a, port);
//          break;
//       }
      log(LOG_INFO, "Listening on %s port %hu", a, port);
   }
   if (listenfds == 0)
      errx(1, "getaddrinfo(): Interface not found");
   freeaddrinfo(res0);

   // Switch to background (daemonize)
   if (background) {
      log(LOG_INFO, "Entering daemon mode");
      // Do not change current working directory, redirect std* to /dev/null
      daemon(1, 0);
   }

   // ***** Trap interface initialization *****
   rc = trap_init(&module_info, ifc_spec);
   if (rc != TRAP_E_OK) {
      log(LOG_ERR, "ERROR in TRAP initialization: %s\n", trap_last_error_msg);
      terminated = 1;
   }
   trap_free_ifc_spec(ifc_spec);

   signal(SIGTERM, terminate_daemon);
   signal(SIGINT, terminate_daemon);
   /* reload configuration signal: */
   signal(SIGHUP, terminate_daemon);

   // Create threads for data from TRAP
   thread_share_t share;

   if (!terminated) {
      rc = pthread_create(&share.data_reader_thread, NULL, &data_reader_trap, (void *) &share);
      if (rc) {
         trap_terminate();
         terminated = 1;
      }

      pthread_mutex_lock(&detector_start);
      rc = pthread_create(&share.data_process_thread, NULL, &data_process_trap, (void *) &share);
      if (rc) {
         trap_terminate();
         terminated = 1;
      }
   }

   // ***** Server *****
   // Block signal SIGALRM
   sigset_t signal_mask;
   sigemptyset(&signal_mask);
   sigaddset(&signal_mask, SIGALRM);

   rc = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
   if (rc != 0) {
      trap_terminate();
      terminated = 1;
   }

   // Create services for requests from frontend
   maxfd = 0;
   FD_ZERO(&allset);
   for (i = 0; i < listenfds; i++) {
      if (listenfd[i] > maxfd)
         maxfd = listenfd[i];
      FD_SET(listenfd[i], &allset);
   }
   rc = 0;
   while (1) {
      if (terminated == 1) {
         break;
      }
#ifdef USE_SLEEP
      log(LOG_INFO, "sleep(%d)", SLEEP);
      sleep(SLEEP);
#endif
      //log(LOG_INFO, "Listening on %s:%s ...\n", server.c_str(), port.c_str());
      rset = allset;
      if (select(maxfd + 1, &rset, NULL, NULL, NULL) == -1) {
         log(LOG_NOTICE, "Select() - %s", strerror(errno));
         continue;
      }
      for (i = 0; i < listenfds; i++) {
         pthread_t servicethread;
         if (FD_ISSET(listenfd[i], &rset)) {
            //log(LOG_INFO, "Waiting for a new client");
            if ((connectfd[i] = accept(listenfd[i], NULL, NULL)) == -1)
               err(1, "accept()");
            rc = pthread_create(&servicethread, NULL, &service, (void *) &connectfd[i]);
            pthread_detach(servicethread);
            if (rc) {
               log(LOG_ERR, "ERROR: return code from pthread_create() is %d", rc);
               close(listenfd[i]);
               break;
            }
         }
      }
   }
   
   // ***** Server part end, do cleanup and exit *****
   log(LOG_INFO, "Exiting...");
   for (i = 0; i < listenfds; i++) {
      close(listenfd[i]);
   }

   //Wait until end of TRAP threads
   pthread_join(share.data_process_thread, NULL);
   pthread_join(share.data_reader_thread, NULL);

   // Delete profiles
   for (int i = 0; i < profiles.size(); i++) {
      delete profiles[i]->bf_active;
      delete profiles[i]->bf_learn;
      delete profiles[i];
   }
   
   //Necessary cleanup before exiting
   trap_finalize();

   pthread_exit(NULL);
   return 0;
}
