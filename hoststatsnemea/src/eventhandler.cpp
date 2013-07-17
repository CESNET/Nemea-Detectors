#include "eventhandler.h"
#include "wardenreport.h"
#include "config.h"
#include "aux_func.h"

#include <fstream>
extern "C" {
   #include <libtrap/trap.h>
}
//#include "../../../unirec/ipaddr.h"
#include "../../../unirec/ipaddr_cpp.h"

using namespace std;

extern ur_template_t *tmpl_out;

string getProtoString(uint8_t proto);
string getTypeString(EventType type);

void reportEvent(const Event& event)
{
   // Print info about event into a string 
   stringstream line;
   line << event.timeslot << ';';
   line << getTypeString(event.type) << ';';
   for (vector<uint8_t>::const_iterator it = event.proto.begin(); it != event.proto.end(); ++it) {
      if (it != event.proto.begin())
         line << ',';
      line << (int)*it;
   }
   line << ';';
   for (vector<ip_addr_t>::const_iterator it = event.src_addr.begin(); it != event.src_addr.end(); ++it) {
      if (it != event.src_addr.begin())
         line << ',';
      line << IPaddr_cpp(&(*it));
   }
   line << ';';
   for (vector<ip_addr_t>::const_iterator it = event.dst_addr.begin(); it != event.dst_addr.end(); ++it) {
      if (it != event.dst_addr.begin())
         line << ',';
      line << IPaddr_cpp(&(*it));
   }
   line << ';';
   for (vector<uint16_t>::const_iterator it = event.src_port.begin(); it != event.src_port.end(); ++it) {
      if (it != event.src_port.begin())
         line << ',';
      line << *it;
   }
   line << ';';
   for (vector<uint16_t>::const_iterator it = event.dst_port.begin(); it != event.dst_port.end(); ++it) {
      if (it != event.dst_port.begin())
         line << ',';
      line << *it;
   }
   line << ';';
   line << event.scale << ';';
   line << event.note << '\n';
   
   // Write the line to a log file
   Configuration *config = Configuration::getInstance();
   config->lock();
   string path = config->getValue("detection-log");
   string warden_script = config->getValue("warden-send-script");
   config->unlock();
   
   string y = event.timeslot.substr(0,4);
   string m = event.timeslot.substr(4,2);
   string d = event.timeslot.substr(6,2);
   string h = event.timeslot.substr(8,2);
   string n = event.timeslot.substr(10,2);
   
   if (!path.empty()) {
      // Fill in year, month, day, hour and minute
//       replace(path, "%y", event.timeslot.substr(0,4));
//       replace(path, "%m", event.timeslot.substr(4,2));
//       replace(path, "%d", event.timeslot.substr(6,2));
//       replace(path, "%H", event.timeslot.substr(8,2));
//       replace(path, "%M", event.timeslot.substr(10,2));
      
      if (path[path.size()-1] != '/')
         path += '/';
      path += y + m + d + ".log";
      
      // Open file and append the line
      ofstream logfile(path.c_str(), ios_base::app);
      if (logfile.good()) {
         logfile << line.str();
         logfile.close();
      }
      else {
         log(LOG_ERR, "Can't open log file \"%s\".", path.c_str());
      }
   }
   
   // Send event report to Warden (if appropriate type and if source is known)
   //                               TODO: what to do when there are more sources/ports/protocols?
   if (!warden_script.empty() && event.src_addr.size() == 1) {
      WardenReport wr;
      wr.time = y+"-"+m+"-"+d+"T"+h+":"+n+":00";
      wr.source = IPaddr_cpp(&event.src_addr[0]).toString();
      if (event.proto.size() == 1)
         wr.target_proto = getProtoString(event.proto[0]);
      if (event.dst_port.size() == 1)
         wr.target_port = event.dst_port[0];
      wr.attack_scale = event.scale;
      wr.note = event.note;   
      
      if (event.type == PORTSCAN || event.type == PORTSCAN_H || event.type == PORTSCAN_V) {
         wr.type = "portscan";
         wr.send(warden_script);
      }
      else if (event.type == DOS || event.type == DDOS) {
         wr.type = "dos";
         wr.send(warden_script);
      }
      else if (event.type == BRUTEFORCE) {
         wr.type = "bruteforce";
         wr.send(warden_script);
      }
   }
/*
   // Send event report to TRAP output interface (HALF_WAIT)
   int note_size = 0;
   if (!event.note.size()) {
      note_size = strlen(event.note.c_str());
   }

   void *rec = ur_create(tmpl_out, note_size);

   if (event.src_addr.size()) {
      if (event.src_addr.front().isIPv4()) {
         char b[4] = {
            event.src_addr[0].ad[0] >> 24,
            event.src_addr[0].ad[0] >> 16,
            event.src_addr[0].ad[0] >> 8, 
            event.src_addr[0].ad[0] };
         ur_set(tmpl_out, rec, UR_SRC_IP, ip_from_4_bytes_le(b));
      }
      else {
         char b[16];  
         for (int i = 0; i < 8; i++) {
            b[i] = event.src_addr[0].ad[1] >> ((7-i) * 8);
            b[8+i] = event.src_addr[0].ad[0] >> ((7-i) * 8);
         }
         ur_set(tmpl_out, rec, UR_SRC_IP, ip_from_16_bytes_le(b));
      }
   }

   if (event.dst_addr.size()) {
      if (event.dst_addr.front().isIPv4()) {
         char b[4] = {
            event.dst_addr[0].ad[0] >> 24,
            event.dst_addr[0].ad[0] >> 16,
            event.dst_addr[0].ad[0] >> 8, 
            event.dst_addr[0].ad[0] };
         ur_set(tmpl_out, rec, UR_DST_IP, ip_from_4_bytes_le(b));
      }
      else {
         char b[16];  
         for (int i = 0; i < 8; i++) {
            b[i] = event.dst_addr[0].ad[1] >> ((7-i) * 8);
            b[8+i] = event.dst_addr[0].ad[0] >> ((7-i) * 8);
         }
         ur_set(tmpl_out, rec, UR_DST_IP, ip_from_16_bytes_le(b));
      }
   }

   if (event.src_port.size()) ur_set(tmpl_out, rec, UR_SRC_PORT, event.src_port.front());
   if (event.dst_port.size()) ur_set(tmpl_out, rec, UR_DST_PORT, event.dst_port.front());
   if (event.proto.size()) ur_set(tmpl_out, rec, UR_PROTOCOL, event.proto.front());

   //NOTE
   //memcpy(ur_get_dyn(tmpl_out, rec, UR_NOTE), event.note.c_str(), note_size);
   //*(uint16_t*)ur_get_ptr(tmpl_out, rec, UR_NOTE) = note_size;

   //ADD EVENT TYPE, TIMESLOT, SCALE,  
   
   // TODO: change to halfwait
   printf(">>>>>>>>>ODESILAM DATA NA TRAPU\n");
   int ret = trap_send_data(0, rec, ur_rec_size(tmpl_out, rec), TRAP_WAIT);
   if (ret != TRAP_E_OK) printf("TRAP_SEND_DATA: %d\n", ret);
   printf(">>>>>>>>>ODESLANO\n");
   */
}


string getTypeString(EventType type)
{
   switch (type)
   {
      case PORTSCAN:   return "portscan";
      case PORTSCAN_H: return "portscan_h";
      case PORTSCAN_V: return "portscan_v";
      case BRUTEFORCE: return "bruteforce";
      case DOS:        return "dos";
      case OTHER:      return "other";
      default: return string("type_")+int2str((int)type);
   }
}


string getProtoString(uint8_t proto)
{
   switch (proto)
   {
      case TCP:  return "TCP";
      case UDP:  return "UDP";
      case ICMP: return "ICMP";
      default:   return int2str((int)proto);
   }
}


/*
int main()
{
   IPAddr ip1,ip2,ip3,ip4;
//    str2ip("0.1.2.3", ip1);
//    str2ip("1.2.3.4", ip2);
//    str2ip("100.0.0.3", ip3);
//    str2ip("100.0.0.4", ip4);
   
   Event evt("201303271000", PORTSCAN);
   evt.addSrcAddr(ip1).addProto(6);
   evt.addDstPort(21).addDstPort(22).addDstPort(23).addDstPort(24).addDstPort(25);
   evt.setScale(1000);
   reportEvent(evt);
   
   evt = Event("201303271005", DOS);
   evt.addDstAddr(ip4).addProto(6).addDstPort(80);
   evt.setScale(50000);
   reportEvent(evt);
   
   return 0;
}
*/
