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

void signal_handler(int signal)
{
   if (signal == SIGTERM || signal == SIGINT) {
      printf("Signal detected, terminating.\n");
      stop = 1;
      trap_terminate();
   }
}

int is_ip_uniq(ip_addr_t ip, ip_addr_t *ar, int c)
{
   for (int i = 0; i < c; ++i) {
      if (ip.ui64[0] == ar[i].ui64[0] &&
          ip.ui64[1] == ar[i].ui64[1]) {
         return 0;
      }
   }
   return 1;
}


float mean_stream(float old_mean, uint32_t elem_count, uint32_t new_elem)
{
   return (old_mean*(elem_count-1) + new_elem)/elem_count;
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
   int display_valid_ssh_con = 0;

   // ***** TRAP initialization *****   
   TRAP_DEFAULT_INITIALIZATION(argc, argv, module_info);
   signal(SIGTERM, signal_handler);
   signal(SIGINT, signal_handler);

   // ***** Create UniRec template *****   
   char *unirec_specifier = "<COLLECTOR_FLOW>";
   char opt;
   while ((opt = getopt(argc, argv, "u:d")) != -1) {
      switch (opt) {
         case 'u':
            unirec_specifier = optarg;
            break;
         case 'd':
            display_valid_ssh_con = 1;
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
      // Filter non SSH traffic
      if (ur_get(tmplt, data, UR_SRC_PORT) != SSH_PORT &&
          ur_get(tmplt, data, UR_DST_PORT) != SSH_PORT) {
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
            ht_data->atk_ip   = ur_get(tmplt, data, UR_SRC_IP);
            ht_data->vic_ip_ar = malloc(sizeof(ip_addr_t) * 10000);
            ht_data->vic_ip_ar[0] = ur_get(tmplt, data, UR_DST_IP);
            ht_data->vic_ip_count = 1;
            ht_data->uniq_con  = 1;
            ht_data->total_con = 1;
            ht_data->uniq_ppf  = ur_get(tmplt, data, UR_PACKETS);
            ht_data->total_ppf = ur_get(tmplt, data, UR_PACKETS);
            // Check TCP flags for SYN flag (1. phase of 3 way handshake)
            if (ur_get(tmplt, data, UR_TCP_FLAGS) == SYN_FLAG) { 
               ht_data->uniq_syn_only  = 1;
               ht_data->total_syn_only = 1;
            }
            old_data = ht_insert_v2(ht, (char *)&hash, ht_data);
            if (old_data != NULL) {
               printf(" |- WARNING: Kicking out data from hash table!\n");
            }
         } else {
            // Check if this is new connection for this attacker
            if (is_ip_uniq(ur_get(tmplt, data, UR_DST_IP), old_data->vic_ip_ar, old_data->vic_ip_count)) {
               old_data->uniq_con++;
               old_data->vic_ip_ar[old_data->vic_ip_count++] = ur_get(tmplt, data, UR_DST_IP);
               old_data->uniq_ppf = mean_stream(old_data->uniq_ppf, old_data->uniq_con, ur_get(tmplt, data, UR_PACKETS));
               // Check TCP flags for SYN flag (1. phase of 3 way handshake)
               if (ur_get(tmplt, data, UR_TCP_FLAGS) == SYN_FLAG) { 
                  old_data->uniq_syn_only++;
               }
            }
            // Check TCP flags for SYN flag (1. phase of 3 way handshake)
            if (ur_get(tmplt, data, UR_TCP_FLAGS) == SYN_FLAG) { 
               old_data->total_syn_only++;
            }
            // Check TCP flags for at least SYN & ACK & PSH & FIN flag (whole connection with PSH)
            if (ur_get(tmplt, data, UR_TCP_FLAGS) & (SYN_FLAG | ACK_FLAG | PSH_FLAG | FIN_FLAG) >= (SYN_FLAG | ACK_FLAG | PSH_FLAG | FIN_FLAG)) { 
               old_data->total_wcon++;
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
      if (((ht_data_t*)ht->data[index])->uniq_con <= 4 && display_valid_ssh_con == 0) {
         continue;
      }
      
      uint32_t uniq_con  = ((ht_data_t*)ht->data[index])->uniq_con;
      uint32_t total_con = ((ht_data_t*)ht->data[index])->total_con;
      float    con_ratio = (float)uniq_con / total_con;
      uint32_t total_wcon= ((ht_data_t*)ht->data[index])->total_wcon;
      float    uniq_ppf  = ((ht_data_t*)ht->data[index])->uniq_ppf;
      float    total_ppf = ((ht_data_t*)ht->data[index])->total_ppf;
      uint32_t uniq_syn_only   = ((ht_data_t*)ht->data[index])->uniq_syn_only;
      uint32_t total_syn_only  = ((ht_data_t*)ht->data[index])->total_syn_only;
      float    uniq_syn_ratio  = (float)uniq_syn_only / uniq_con;
      float    total_syn_ratio = (float)total_syn_only / total_con;
      float    total_wcon_ratio;

      if (total_con - total_syn_only == 0) {
         total_wcon_ratio = 0;
      } else {
         total_wcon_ratio = (float)total_wcon / (total_con - total_syn_only);
      }

      uint8_t flag = 0;

      // Flag attackers (scanner)
      if (
          (uniq_con >= SCAN_UNIQ_CON_THRESHOLD && (uniq_ppf <= SCAN_UNIQ_MEAN_PPF_THRESHOLD || uniq_syn_ratio >= SCAN_UNIQ_SYN_ONLY_RATIO_THRESHOLD))
         ) {
         printf("%s", RED_S);
         flag |= 1;
      }

      // Flag attackers (bruteforce)
      if (
          (total_con >= BF_TOTAL_CON_THRESHOLD && total_syn_ratio <= BF_TOTAL_SYN_ONLY_RATIO_THRESHOLD &&
           total_ppf >= BF_TOTAL_MEAN_PPF_THRESHOLD_MIN && total_ppf <= BF_TOTAL_MEAN_PPF_THRESHOLD_MAX &&
           total_wcon_ratio >= BF_TOTAL_WCON_RATIO_THRESHOLD)
         ) {
         printf("%s", RED_S);
         flag |= 2;
      }


      // Print record
      printf("IP: %16s | CON: %5u, %5u (%.2f) | WCON: %5u (%.2f) | PPF: %7.2f, %7.2f | SYN: %5u, %5u (%.2f, %.2f)",
              buf, uniq_con, total_con, con_ratio, total_wcon, total_wcon_ratio, uniq_ppf, total_ppf, uniq_syn_only, total_syn_only, uniq_syn_ratio, total_syn_ratio);

      if (flag) {
         if (flag & 1) {
            printf(" | SCAN");
         }
         if (flag & 2) {
            printf(" | BRUTEFORCE ");
         }
         printf("%s", RED_E);
      }
      printf("\n");
   }
   printf("Count: %u\n", uniq_ip_count);

   // ***** Cleanup *****   
   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   ur_free_template(tmplt);
   

   return 0;
}

