#include "subprofiles.h"

/******************************* DNS subprofile *******************************/
/* 
 * flow_filter()
 * Check if the flow data belongs to subprofile.
 * 
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @return True when data belongs to subprofile, false otherwise
 */
bool DNSHostProfile::flow_filter(const void *data, const ur_template_t *tmplt)
{
   return ((ur_get(tmplt, data, UR_PROTOCOL) == 6  || 
            ur_get(tmplt, data, UR_PROTOCOL) == 17) 
            &&
           (ur_get(tmplt, data, UR_SRC_PORT) == 53 || 
            ur_get(tmplt, data, UR_DST_PORT) == 53));
}

/*
 * update()
 * Update record with new data from TRAP
 *
 * If the new flow data belongs to subprofile update it. If the profile 
 * does not exist create a new one.
 * 
 * @param record Record to update
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @param dir_flag Direction of flow (DIR_OUT - source, DIR_IN - destination)
 * @return True when data belongs to subprofile, false otherwise
 */
bool DNSHostProfile::update(hosts_record_t &record, const void *data, 
                            const ur_template_t *tmplt, char dir_flag)
{
   // DNS flow filter
   if (!flow_filter(data, tmplt)) {
      return 0;
   }

   // create new DNS record
   if (record.dnshostprofile == NULL) {
      record.dnshostprofile = new DNSHostProfile;
   }

   // update items
   dns_record_t &dns = record.dnshostprofile->record;

   if (dir_flag & DIR_OUT) dns.out_dns_flows++;
   if (dir_flag & DIR_IN)  dns.in_dns_flows++;

   return 1;
}

/*
 * check_record()
 * Check detection rules only if subprofile exists
 *
 * @param key HostProfile key of a record
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool DNSHostProfile::check_record(const hosts_key_t &key, const hosts_record_t &record)
{
   if (record.dnshostprofile == NULL)
      return 0;

   // TODO: call detector here!!! 

   return 1;
}

/*
 * delete_record()
 * Delete a DNS record from a main record.
 *
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool DNSHostProfile::delete_record(hosts_record_t &record)
{
   if (record.dnshostprofile == NULL) {
      return 0;
   }
   else {
      delete record.dnshostprofile;
      return 1;
   }
}


/******************************* SSH subprofile *******************************/
/* 
 * flow_filter()
 * Check if the flow data belongs to subprofile.
 * 
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @return True when data belongs to subprofile, false otherwise
 */
bool SSHHostProfile::flow_filter(const void *data, const ur_template_t *tmplt)
{
   return 
      (ur_get(tmplt, data, UR_PROTOCOL) == 6 
      &&
      (
         ur_get(tmplt, data, UR_SRC_PORT) == 22 || 
         ur_get(tmplt, data, UR_DST_PORT) == 22
      ));
}

/*
 * update()
 * Update record with new data from TRAP
 *
 * If the new flow data belongs to subprofile update it. If the profile 
 * does not exist create a new one.
 * 
 * @param record Record to update
 * @param data New data from TRAP
 * @param tmplt Pointer to input interface template
 * @param dir_flag Direction of flow (DIR_OUT - source, DIR_IN - destination)
 * @return True when data belongs to subprofile, false otherwise
 */
bool SSHHostProfile::update(hosts_record_t &record, const void *data, 
                            const ur_template_t *tmplt, char dir_flag)
{
   // SSH flow filter
   if (!flow_filter(data, tmplt)) {
      return 0;
   }

   // create new SSH record
   if (record.sshhostprofile == NULL) {
      record.sshhostprofile = new SSHHostProfile;
   }

   // update items
   ssh_record_t &ssh = record.sshhostprofile->record;

   if (dir_flag & DIR_OUT) ssh.out_ssh_flows++;
   if (dir_flag & DIR_IN)  ssh.in_ssh_flows++;

   return 1;
}

/*
 * check_record()
 * Check detection rules only if subprofile exists
 *
 * @param key HostProfile key of a record
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool SSHHostProfile::check_record(const hosts_key_t &key, const hosts_record_t &record)
{
   if (record.sshhostprofile == NULL)
      return 0;

   // TODO: call detector here!!! 

   return 1;
}

/*
 * delete_record()
 * Delete a SSH record from a main record.
 *
 * @param record HostProfile record
 * @return True if there was a subprofile, false otherwise.
 */
bool SSHHostProfile::delete_record(hosts_record_t &record)
{
   if (record.sshhostprofile == NULL) {
      return 0;
   }
   else {
      delete record.sshhostprofile;
      return 1;
   }
}