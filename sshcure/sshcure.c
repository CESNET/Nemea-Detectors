/**
 * \file ssh_cure.h
 * \brief SSHCure module. 
 * \author Erik Sabik <xsabik02@stud.fit.vutbr.cz>
 * \date 2014
 */


#include "sshcure.h"

/* ****************************** Modify here ****************************** */
// Struct with information about module
trap_module_info_t module_info = {
   "Flow-counter module", // Module name
   // Module description
   "Example module for counting number of incoming flow records.\n"
   "Parameters:\n"
   "   -u TMPLT    Specify UniRec template expected on the input interface.\n"
   "   -p N        Show progess - print a dot every N flows.\n"
   "   -P CHAR     When showing progress, print CHAR instead of dot.\n"
   "Interfaces:\n"
   "   Inputs: 1 (flow records)\n"
   "   Outputs: 0\n",
   1, // Number of input interfaces
   0, // Number of output interfaces
};
/* ************************************************************************* */

static int stop = 0;
static int SEGFAULT_flag = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

int is_ip_uniq(ip_addr_t ip, vic_data_t *ar, int c)
{
   for (int i = 0; i < c; ++i) {
      if (ip.ui64[0] == ar[i].vic_ip.ui64[0] &&
          ip.ui64[1] == ar[i].vic_ip.ui64[1]) {
         return i;
      }
   }
   return -1;
}


float mean_stream(float old_mean, uint32_t elem_count, uint32_t new_elem)
{
   return (old_mean*(elem_count-1) + new_elem)/elem_count;
}

void print_tcp_flags(uint8_t flags)
{
   if (flags & SYN_FLAG) {
      printf("S");
   } else {
      printf("-");
   }

   if (flags & ACK_FLAG) {
      printf("A");
   } else {
      printf("-");
   }

   if (flags & PSH_FLAG) {
      printf("P");
   } else {
      printf("-");
   }

   if (flags & FIN_FLAG) {
      printf("F");
   } else {
      printf("-");
   }
   printf("\n");
}


uint32_t check_bruteforce(vic_data_t *data, uint32_t c, ip_addr_t **vic_ip_out)
{
   printf("MFD: ");
   uint32_t bf_count = 0;
   *vic_ip_out = malloc(sizeof(ip_addr_t) * 1024); // TODO: Lepsi algoritmus!!!
   for (int i = 0; i < c; ++i) {
        /* PRINT FLOW DUR
        uint64_t sec = data[i].mfd;
        uint64_t msec = ur_time_get_msec(sec);
	sec = sec >> 32;
	printf ("%15llu", sec * 1000 + msec);   
        */

      // Check if SRC IP is BRUTEFORCING DST IP
      if (
          (data[i].con_total >= BF_TOTAL_CON_THRESHOLD &&
           data[i].ppf >= BF_TOTAL_MEAN_PPF_THRESHOLD_MIN && data[i].ppf <= BF_TOTAL_MEAN_PPF_THRESHOLD_MAX &&
           data[i].con_sap >= BF_TOTAL_CON_SAP_THRESHOLD)
         ) {
         (*vic_ip_out)[bf_count++] = data[i].vic_ip;
         if (bf_count >= 1000) { printf("bf_count over 1000\n"); exit(1);}
      }
   }
   if (bf_count == 0) {
      free(*vic_ip_out);
      *vic_ip_out = NULL;
   }

   // PRINT FLOW DUR
   //printf("\n"); 

   return bf_count;
}

int main(int argc, char **argv)
{
   int ret;
   char buf[128] = {0};
   unsigned long abs_cnt_flows = 0;
   unsigned long ssh_cnt_flows = 0;
   unsigned long atk_cnt_flows = 0;
   cc_hash_table_v2_t *ht = malloc(sizeof(cc_hash_table_v2_t));
   ht_data_t *ht_data = malloc(sizeof(ht_data_t));
   uint8_t print_low_con_count = 0;
   uint8_t print_legitimate    = 0;
   uint8_t print_debug         = 0;
   uint8_t use_unk_scan        = 0;

   // ***** TRAP initialization *****   
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   
   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec template *****   
   char *unirec_specifier = "<COLLECTOR_FLOW>";
   char opt;
   while ((opt = getopt(argc, argv, "u:cdls")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'c':
            print_low_con_count = 1;
            break;
         case 'd':
            print_debug = 1;
            break;
         case 'l':
            print_legitimate = 1;
            break;
         case 's':
            use_unk_scan = 1;
            break;
         default:
            fprintf(stderr, "Invalid arguments.\n");
            return 3;
      }
   }
   
   ur_template_t *tmplt = ur_create_template(unirec_specifier);
   if (tmplt == NULL) {
      fprintf(stderr, "Error: Invalid UniRec specifier.\n");
      trap_finalize();
      return 4;
   }
 

   // ***** Hash table initialization *****
   ret = ht_init_v2(ht, HT_TABLE_SIZE, sizeof(ht_data_t), sizeof(uint32_t));
   if (ret != 0) {
      // Error initializing hash table
      free(ht);
      trap_finalize();
      return 5;
   }
  
   
   // ***** Main processing loop *****
   while (!stop) {
      // Receive data from input interface (block until data are available)
      const void *data;
      uint16_t data_size;
      ret = trap_recv(0, &data, &data_size);
      TRAP_DEFAULT_RECV_ERROR_HANDLING(ret, continue, break);
      
      // Check size of received data
      if (data_size < ur_rec_static_size(tmplt)) {
         if (data_size <= 1) {
            break; // End of data (used for testing purposes)
         }
         else {
            fprintf(stderr, "Error: data with wrong size received (expected size: >= %hu, received size: %hu)\n",
                    ur_rec_static_size(tmplt), data_size);
            break;
         }
      }  
     
      // Update counters for all flows
      abs_cnt_flows   += 1;

      // *************** SSHCure ***************
      // Filter non TCP SSH traffic
      if ((ur_get(tmplt, data, UR_PROTOCOL) != TCP) ||
          (ur_get(tmplt, data, UR_SRC_PORT) != SSH_PORT &&
           ur_get(tmplt, data, UR_DST_PORT) != SSH_PORT))  {
         continue;
      }

      // Update counters for SSH flows
      ssh_cnt_flows   += 1;

      if (ur_get(tmplt, data, UR_DST_PORT) == SSH_PORT) {
         atk_cnt_flows++;
         uint32_t hash = SuperFastHash((char*)ur_get_ptr(tmplt, data, UR_SRC_IP), 16);
         ht_data_t *old_data;
         if ((old_data = ht_get_v2(ht, (char*)&hash)) == NULL) {
            // New possible attacker
            // TODO: Spravit funkciu
            ht_data->atk_ip   = ur_get(tmplt, data, UR_SRC_IP);
            ht_data->vic_data = malloc(sizeof(vic_data_t) * 32000);
            ht_data->vic_data[0].vic_ip = ur_get(tmplt, data, UR_DST_IP);
            ht_data->vic_ip_count = 1;
            ht_data->uniq_con  = 1;
            ht_data->total_con = 1;
            ht_data->vic_data[0].con_total = 1;
            ht_data->uniq_ppf  = ur_get(tmplt, data, UR_PACKETS);
            ht_data->total_ppf = ur_get(tmplt, data, UR_PACKETS);
            ht_data->vic_data[0].ppf = ur_get(tmplt, data, UR_PACKETS);
            ht_data->vic_data[0].mfd = ur_get(tmplt, data, UR_TIME_LAST) - ur_get(tmplt, data, UR_TIME_FIRST);

            ht_data->total_con_sap = 0; // TODO: REALLY??

            // Check TCP flags for SYN flag (SYN SCAN or legitimate connection)
            if(ur_get(tmplt, data, UR_TCP_FLAGS) == SYN_FLAG) {
               ht_data->uniq_syn_only  = 1;
            } else {
               ht_data->uniq_syn_only  = 0;
            }

            // Check TCP flags for SYN & ACK flag (CONNECT SCAN)
            if(ur_get(tmplt, data, UR_TCP_FLAGS) == (ACK_FLAG | SYN_FLAG)) {
               ht_data->uniq_syn_ack_only  = 1;
            } else {
               ht_data->uniq_syn_ack_only  = 0;
            }


            old_data = ht_insert_v2(ht, (char *)&hash, ht_data);
            if (old_data != NULL) {
               printf(" |- WARNING: Kicking out data from hash table!\n");
            }
         } else {
            // Check if this is new connection for this attacker
            uint32_t vic_index;
            if ((vic_index = is_ip_uniq(ur_get(tmplt, data, UR_DST_IP), old_data->vic_data, old_data->vic_ip_count)) == -1) {
               // First time connection
               // TODO: Spravit funkciu
               old_data->uniq_con++;
               vic_data_t vic_data;
               vic_data.vic_ip = ur_get(tmplt, data, UR_DST_IP);
               vic_data.ppf    = ur_get(tmplt, data, UR_PACKETS);
               vic_data.con_total = 1;
               vic_data.con_sap   = 0; //TODO: REALLY?
               ht_data->vic_data[0].mfd = ur_get(tmplt, data, UR_TIME_LAST) - ur_get(tmplt, data, UR_TIME_FIRST);

               old_data->uniq_ppf = mean_stream(old_data->uniq_ppf, old_data->uniq_con, ur_get(tmplt, data, UR_PACKETS));
               // Check TCP flags for SYN flag (SYN SCAN or legitimate connection)
               if (ur_get(tmplt, data, UR_TCP_FLAGS) == SYN_FLAG) { 
                  old_data->uniq_syn_only++;
               }
               // Check TCP flags for SYN & ACK flag (CONNECT SCAN)
               if (ur_get(tmplt, data, UR_TCP_FLAGS) == (ACK_FLAG | SYN_FLAG)) { 
                  old_data->uniq_syn_ack_only++;
               }
               // Save new vic_data to attacker's array
               old_data->vic_data[old_data->vic_ip_count++] = vic_data;
            } else {
               // Attacker was already connected to this host (vic_index is set)
               // TODO: Spravit funkciu
               // Update PPF for this victim
               old_data->vic_data[vic_index].con_total++;
               old_data->vic_data[vic_index].ppf = mean_stream(old_data->vic_data[vic_index].ppf, old_data->vic_data[vic_index].con_total, ur_get(tmplt, data, UR_PACKETS));

               // Check TCP flags for at least SYN & ACK & PSH  flag (whole connection with PSH without FIN (some attackers do not close connection with FIN)
               // TODO: PSH tam musi byt??
               if ((ur_get(tmplt, data, UR_TCP_FLAGS) & (SYN_FLAG | ACK_FLAG | PSH_FLAG)) == (SYN_FLAG | ACK_FLAG | PSH_FLAG)) { 
                  old_data->total_con_sap++;
                  old_data->vic_data[vic_index].con_sap++;
                  ht_data->vic_data[vic_index].mfd = mean_stream(old_data->vic_data[vic_index].mfd, old_data->vic_data[vic_index].con_sap,
                                                                 ur_get(tmplt, data, UR_TIME_LAST) - ur_get(tmplt, data, UR_TIME_FIRST));
               }
            }

            old_data->total_con++;
            old_data->total_ppf = mean_stream(old_data->total_ppf, old_data->total_con, ur_get(tmplt, data, UR_PACKETS));
         }
       
      }


      // ***************************************
   }
   
   // ***** Print results *****
   printf("Flows:   %20lu of %20lu of %20lu (%.5f, %.5f)\n", atk_cnt_flows, ssh_cnt_flows, abs_cnt_flows,
                                                            (float)atk_cnt_flows/ssh_cnt_flows, (float)ssh_cnt_flows/abs_cnt_flows);
   printf("-----------------------------\n");
   int uniq_ip_count = 0;
   int attk_ip_count = 0;
   int attk_scan_count = 0;
   int attk_bf_ucount = 0;
   int attk_bf_tcount = 0;
   // Print possible attackers
   for (uint32_t i = 0; i < ht->table_size; ++i) {
      // Print only valid records from hash table
      if (!ht->ind[i].valid) {
         continue;
      }
      uniq_ip_count++;

      uint32_t index = ht->ind[i].index;
      ip_to_str(&(((ht_data_t*)(ht->data[index]))->atk_ip), buf);
      // Print only records that have more than 1 connection
      if (((ht_data_t*)ht->data[index])->uniq_con <= 4 && print_low_con_count == 0) {
         continue;
      }
      
      vic_data_t *vic_data = ((ht_data_t*)ht->data[index])->vic_data;
      uint32_t vic_ip_count = ((ht_data_t*)ht->data[index])->vic_ip_count;
      uint32_t uniq_con  = ((ht_data_t*)ht->data[index])->uniq_con;
      uint32_t total_con = ((ht_data_t*)ht->data[index])->total_con;
      uint32_t total_con_sap = ((ht_data_t*)ht->data[index])->total_con_sap;
      float    uniq_ppf  = ((ht_data_t*)ht->data[index])->uniq_ppf;
      float    total_ppf = ((ht_data_t*)ht->data[index])->total_ppf;
      uint32_t uniq_syn_only   = ((ht_data_t*)ht->data[index])->uniq_syn_only;
      uint32_t uniq_syn_ack_only   = ((ht_data_t*)ht->data[index])->uniq_syn_ack_only;
      

      // ******************** FLAG ATTACKERS ******************
      uint8_t flag = 0;
      // Flag attackers (Unknown SCAN)
      if (
          use_unk_scan &&
          (uniq_con >= SCAN_UNIQ_CON_THRESHOLD && uniq_ppf <= SCAN_UNIQ_MEAN_PPF_THRESHOLD)
         ) {
         printf("%s", RED_S);
         flag |= AT_SCAN_UNK;
         attk_scan_count++;
      }
      // Flag attackers (SYN SCAN)
      if (
          (uniq_con >= SCAN_UNIQ_CON_THRESHOLD && uniq_syn_only >= SCAN_UNIQ_SYN_ONLY_THRESHOLD)
         ) {
         printf("%s", RED_S);
         flag |= AT_SCAN_SYN;
         attk_scan_count++;
      }

      // Flag attackers (CONNECT SCAN)
      if (
          (uniq_con >= SCAN_UNIQ_CON_THRESHOLD && uniq_syn_ack_only >= SCAN_UNIQ_SYN_ONLY_THRESHOLD)
         ) {
         printf("%s", RED_S);
         flag |= AT_SCAN_CON;
         attk_scan_count++;
      }

      // Flag attackers (BRUTEFORCE_ALL)
      if (
          (total_con >= BF_TOTAL_CON_THRESHOLD &&
           total_ppf >= BF_TOTAL_MEAN_PPF_THRESHOLD_MIN && total_ppf <= BF_TOTAL_MEAN_PPF_THRESHOLD_MAX &&
           total_con_sap >= BF_TOTAL_CON_SAP_THRESHOLD)
         ) {
         printf("%s", RED_S);
         flag |= AT_BRUTEFORCE_ALL;

      }

      // Flag attacker (BRUTEFORCE_IP)
      ip_addr_t *tmp_vic_ip;
      uint32_t  tmp_vic_ip_c;
      tmp_vic_ip_c = check_bruteforce(vic_data, vic_ip_count, &tmp_vic_ip);
      if (tmp_vic_ip_c) {
         printf("%s", RED_S);
         flag |= AT_BRUTEFORCE_IP;
         attk_bf_ucount++;
         attk_bf_tcount += tmp_vic_ip_c;
         fprintf(stderr, "%s\n", buf);
      }
      // *****************************************************
      if (flag || print_legitimate) {
         // Print record (DEBUG MODE)
         if (print_debug) {
            printf("IP: %16s | CON(U/T): %5u / %5u | SAPCON: %5u | MPPF(U/T): %7.2f / %7.2f | UNIQCON(SYN/SYNACK): %5u / %5u)",
                    buf, uniq_con, total_con, total_con_sap, uniq_ppf, total_ppf, uniq_syn_only, uniq_syn_ack_only);
         } else {
             printf("IP: %16s | ", buf);
         }
         // If src ip is flagged
         if (flag) {
           attk_ip_count++;
           if (print_debug) {
              printf ("\n		|->");
           }
	   if (flag & AT_SCAN_UNK) {
               printf(" SCAN(U)");
            }
            if (flag & AT_SCAN_SYN) {
               printf(" SCAN(S)");
            }
            if (flag & AT_SCAN_CON) {
               printf(" SCAN(C)");
            }
            if (flag & AT_BRUTEFORCE_ALL) {
               printf(" BRUTEFORCE_ALL");
            }
            if (flag & AT_BRUTEFORCE_IP) {
               printf(" BRUTEFORCE_IP(");
               char buf[128];
               for (int j = 0; j < tmp_vic_ip_c; ++j) {
                  ip_to_str(&tmp_vic_ip[j], buf);
                  printf(" %s", buf);
               }
               free(tmp_vic_ip);
               printf(")");
            }
            printf("%s", RED_E);
         }
         printf("\n");
      }
   }
   printf("Uniq total IP count:       %6u\n", uniq_ip_count);
   printf("Uniq attacker IP count:    %6u\n", attk_ip_count);
   printf("Uniq scan IP count:        %6u\n", attk_scan_count);
   printf("Uniq bruteforce IP count:  %6u\n", attk_bf_ucount);
   printf("Total bruteforce IP count: %6u\n", attk_bf_tcount);

   // ***** Cleanup *****   
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(tmplt);
   

   return 0;
}

