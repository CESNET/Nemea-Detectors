#!/usr/bin/python
# Full imports *****************************************************************
import pytrap
import sys
import time
# Partial imports **************************************************************
from difflib import SequenceMatcher

# print current version of python
print (sys.version)

# ******************************************************************************
# ******************************  GLOBAL DEFINITIONS ***************************
# ******************************************************************************
# SMTP COMMANDS
# =============
SMTP_CMD_EHLO = 0x0001
SMTP_CMD_HELO = 0x0002
SMTP_CMD_MAIL = 0x0004
SMTP_CMD_RCPT = 0x0008
SMTP_CMD_DATA = 0x0010
SMTP_CMD_RSET = 0x0020
SMTP_CMD_VRFY = 0x0040
SMTP_CMD_EXPN = 0x0080
SMTP_CMD_HELP = 0x0100
SMTP_CMD_NOOP = 0x0200
SMTP_CMD_QUIT = 0x0400
CMD_UNKNOWN   = 0x8000
# SMTP status codes
# =================
SMTP_SC_211 =   0x00000001
SMTP_SC_214 =   0x00000002
SMTP_SC_220 =   0x00000004
SMTP_SC_221 =   0x00000008
SMTP_SC_250 =   0x00000010
SMTP_SC_251 =   0x00000020
SMTP_SC_252 =   0x00000040
SMTP_SC_354 =   0x00000080
SMTP_SC_421 =   0x00000100
SMTP_SC_450 =   0x00000200
SMTP_SC_451 =   0x00000400
SMTP_SC_452 =   0x00000800
SMTP_SC_455 =   0x00001000
SMTP_SC_500 =   0x00002000
SMTP_SC_501 =   0x00004000
SMTP_SC_502 =   0x00008000
SMTP_SC_503 =   0x00010000
SMTP_SC_504 =   0x00020000
SMTP_SC_550 =   0x00040000
SMTP_SC_551 =   0x00080000
SMTP_SC_552 =   0x00100000
SMTP_SC_553 =   0x00200000
SMTP_SC_554 =   0x00400000
SMTP_SC_555 =   0x00800000
SC_SPAM     =   0x40000000        # indicates that answer contains SPAM keyword
SC_UNKNOWN  =   0x80000000
# ******************************************************************************
# Global variables
# ================
# path to temp data
POTENTIAL_SPAMMERS_REPORT = "/tmp/potencial_spam.csv"
SIMILARITY_INDEX = 0.8
CLUST_INTERVAL = 30*60         # How often should datepool get clustered
CLEAN_INTERVAL = 20*60         # How often should datapool get cleaned
MAX_ALLOWED_SERVERS = 10       # Number of maximum allowded server that mail
                               # server is able to communicate
CDF_PATH = "/tmp/smtp_cdf.csv"
# ******************************************************************************

# Class for SMTP flow handling
class SMTP_Flow:
    def __init__(self, rec):
        self.DST_IP = rec.DST_IP
        self.SRC_IP = rec.SRC_IP
        self.BYTES = rec.BYTES
        self.TIME_FIRST = rec.TIME_FIRST
        self.TIME_LAST = rec.TIME_LAST
        self.PACKETS = rec.PACKETS
        self.SMTP_2XX_STAT_CODE_COUNT = rec.SMTP_2XX_STAT_CODE_COUNT
        self.SMTP_3XX_STAT_CODE_COUNT = rec.SMTP_3XX_STAT_CODE_COUNT
        self.SMTP_4XX_STAT_CODE_COUNT = rec.SMTP_4XX_STAT_CODE_COUNT
        self.SMTP_5XX_STAT_CODE_COUNT = rec.SMTP_5XX_STAT_CODE_COUNT
        self.SMTP_COMMAND_FLAGS = rec.SMTP_COMMAND_FLAGS
        self.SMTP_MAIL_CMD_COUNT = rec.SMTP_MAIL_CMD_COUNT
        self.SMTP_RCPT_CMD_COUNT = rec.SMTP_RCPT_CMD_COUNT
        self.SMTP_STAT_CODE_FLAGS = rec.SMTP_STAT_CODE_FLAGS
        self.SMTP_DOMAIN = rec.SMTP_DOMAIN
        self.SMTP_FIRST_RECIPIENT = rec.SMTP_FIRST_RECIPIENT
        self.SMTP_FIRST_SENDER = rec.SMTP_FIRST_SENDER

    def __repr__(self):
        return "FLOW:\nSRC:" + self.SRC_IP + "\nDST:" + self.DST_IP + "\nCMD_FLAGS:" + self.SMTP_COMMAND_FLAGS + "\n"
    def __str__(self):
        return "FLOW:\nSRC:" + self.SRC_IP + "\nDST:" + self.DST_IP + "\nCMD_FLAGS:" + self.SMTP_COMMAND_FLAGS + "\n"

    # function that detecs whether current flow could be a spam
    # based on SMTP FLAGS, it returns positive value on suspicion
    # flow otherwise negative one
    def BCP_Filter(self):
        spam_flag = 0
        if int(self.SMTP_STAT_CODE_FLAGS) & int(SC_SPAM) > 0:
        # It contains a spam key word
            spam_flag += 50
            print("Alert(SPAM flag present) [{0},{1}]".format(self.SRC_IP,
                                                   str(self.SMTP_FIRST_SENDER)))
        if self.SMTP_FIRST_SENDER == "" or self.SMTP_FIRST_RECIPIENT == "":
            spam_flag += 20
            print("Alert(Address not filled) [{0},{1}]".format(self.SRC_IP, str(self.SMTP_FIRST_SENDER)))
        # todo more filters
        return spam_flag

    def get_name(self):
        return self.SMTP_FIRST_SENDER.partition("@")[0][1:]

# A class for storing information about sender with time window that record
# a first occourence of sender in traffic and his last interaction on
# the network
class SMTP_Server:
    def __init__(self, arg):
        self.sent_history = []
        self.last_seen = 0
        self.incoming = 0
        self.id = ""
        # got whole template
        if isinstance(arg, pytrap.UnirecTemplate):
            self.id = flow.SRC_IP
            self.sent_history.append(flow)
            self.last_seen = flow.TIME_LAST
        # got only ip address
        elif isinstance(arg, pytrap.UnirecIPAddr):
            self.id = arg
            self.incoming += 1

    def __str__(self):
        return ("{0},{1},{2},{3}").format(self.id, len(self.sent_history),
                                          self.incoming, self.last_seen)
    # Getter for number of sent mails from this server
    def count_sent(self):
        return len(self.sent_history)

    # Updates last_seen parametr of server
    def update_time(self, flow):
        if flow.TIME_LAST > self.last_seen:
            self.last_seen = flow.TIME_LAST
        else:
            return None

    # Function that adds flows for this server history
    def add_new_flow(self, flow):
        self.sent_history.append(flow)

    # Function writes current statistics for this server such as how many flows
    # were send and recieved, and last time seen this server in traffic.
    def report_statistics(self, data_report_path):
        # Open file and write new statistics
        with open(data_report_path, 'a') as f:
            try:
                f.write(str(self))
                f.write('\n')
                f.close()
                return True
            except:
                sys.stderr.write("Error writing to file.\n")
                return None

    # Function that checks whether a machine with IP as self.id is a legit
    # smtp mail server or not. It looks at incoming and outgoing traffic
    # and compares the ratio between these two parameters, if the outgoing
    # traffic ratio is X then function returns positive value, otherwise
    # negative one, also it checks for unqie DST_IP's in sent history
    def is_mail_server(self):
        # Calculate traffic ratio
        sent = len(self.sent_history)
        traffic_ratio = self.incoming / sent

        # Check for unique DST_IPs
        unique_ips = set()

        for flow in self.sent_history:
            unique_ips.add(flow.DST_IP)

        if len(unique_ips) > MAX_ALLOWED_SERVERS or traffic_ratio < 1.2:
            return True
        else:
            return False

class ClusterNode:
    def __init__(self):
        self.common_index = ""
        self.cluster_data = list()

    # Setter for the most common index
    def setCommonIndex(self):
        return None

class Cluster:
    def __init__(self):
        self.cluster_nodes = []

    def clustering(self, data_pool):
        """data_pool dict(SRC_IP)"""
        print("Started clustering.\n")

        # iteration through all recorded servers
        for ip in data_pool:
            server = data_pool[ip]
            added = False

            for cluster in self.cluster_nodes:
                if (is_similar(server, cluster)):
                    cluster.append(server)
                    added = True
                    break

            if not added:
                # add new group/cluster with only one server
                self.cluster_nodes.append([server])

    def __str__(self):
        cnt = 0
        ret = "************************************************************\n"
        ret += "Clustering report:\n"
        ret += "Number of clusters: " + str(len(self.cluster_nodes)) + "\n"

        for i in self.cluster_nodes:
            ret += "Node: " + str(cnt) + "\n"
            for q in i:
                ret += "\tServer IP: " + str(q.id) + "\n"
                for j in q.sent_history:
                    ret += "\t\t" + j.SMTP_FIRST_SENDER + "\n"

            cnt += 1
        return ret

# Functions that compares two strings and decide they similarity according to
# SIMILARITY_INDEX, return true if they are similar otherwise false
def is_similar(server, cluster):
    #Server, list(Server)
    for s_flow in server.sent_history:
        for cluster_server in cluster:
            for c_flow in cluster_server.sent_history:
                if SequenceMatcher(None, s_flow.get_name(),
                                  c_flow.get_name()).ratio() > SIMILARITY_INDEX:
                    return True
    return False

# Takes list() of SMTP_Servers and writes them to file.
def write_report(potencial_spammers):
    # Open file and start writing
    with open(POTENTIAL_SPAMMERS_REPORT, 'w') as f:
        for ps in potencial_spammers:
            try:
                f.write(str(ps))
                f.write("\n")
            except:
                sys.stderr.write("Could not write to file!\n")
                return None
        f.close()
    print("Potencial spam servers saved to: {0}").format(POTENTIAL_SPAMMERS_REPORT)
    return 0

# data_pool is dictionary of servers with flow history as a list
def CDF(data_pool):
    CDF_dict = {}
    for server in data_pool:
        CDF_dict[data_pool[server].id] = set()
        for flow in data_pool[server].sent_history:
            CDF_dict[data_pool[server].id].add(flow)

    CDF_vals = []
    for i in CDF_dict:
        ln = len(CDF_dict[i])
        CDF_vals.append(ln)

    with open(CDF_PATH, 'w') as f:
        for val in CDF_vals:
            try:
                f.write(str(val))
                f.write(",")
            except:
                sys.stderr.write("Error while writing CDF report.!\n")
                return None
        f.close()

    return True

def main():
# Main loop ********************************************************************
# =========
    # Stores data about previous flows and saves them
    # to dictionary with SRC_IP as a key
    flow_data_pool = {}
    potencial_spammers = []
    cleanup_interval    = CLEAN_INTERVAL
    clustering_interval = CLUST_INTERVAL
    checked = 0
    alerts = 0

    # Timestamp flag
    TS_SET = 0

    # Inerval timestamps
    flow_first_ts = 0
    flow_curr_ts = 0

    analysis_ts = time.time()
    last_clustering = time.time()


    # Cluster for similiarity analysis
    cluster = Cluster()

    # Traplib init
    trap = pytrap.TrapCtx()
    trap.init(sys.argv, 1, 1)

    # Set the list of required fields in received messages.
    # This list is an output of e.g. flow_meter - basic flow.
    inputspec = ("ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD," +
                "time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint32 SMTP_2XX_STAT_CODE_COUNT," +
                "uint32 SMTP_3XX_STAT_CODE_COUNT,uint32 SMTP_4XX_STAT_CODE_COUNT," +
                "uint32 SMTP_5XX_STAT_CODE_COUNT,uint32 SMTP_COMMAND_FLAGS," +
                "uint32 SMTP_MAIL_CMD_COUNT,uint32 SMTP_RCPT_CMD_COUNT," +
                "uint32 SMTP_STAT_CODE_FLAGS,uint16 DST_PORT,uint16 SRC_PORT," +
                "uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS," +
                "uint8 TTL,string SMTP_DOMAIN,string SMTP_FIRST_RECIPIENT,string SMTP_FIRST_SENDER")
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
    rec = pytrap.UnirecTemplate(inputspec)

    # Define a template of alert (can be extended by any other field)
    alertspec = "ipaddr SRC_IP,time TIME_FIRST,time TIME_LAST,string SMTP_DOMAIN,string SMTP_FIRST_SENDER"
    alert = pytrap.UnirecTemplate(alertspec)
    # Set the data format to the output IFC
    trap.setDataFmt(0, pytrap.FMT_UNIREC, alertspec)

    # Allocate memory for the alert, we do not have any variable fields
    # so no argument is needed.
    #TODO:alert.createMessage()

    # Automat for smtp spam detection
    while (True):
        # Start analysis timer
        curr_time = time.time()

        flow_ts = 0 # A flow timestamp

        if flow_curr_ts + CLEAN_INTERVAL < flow_first_ts:
            # BASIC Analysis - no SMTP header is needed
            # Create timestamp of current statistics and create path for log
            data_report_time = time.time()
            data_report_path = '/tmp/smtp_stats'+str(data_report_time)

            for server in flow_data_pool:
                flow_data_pool[server].report_statistics(data_report_path)
                # Add alert record to potencial spam pool for further analysis
                if (flow_data_pool[server].is_mail_server() is False):
                    potencial_spammers.append(server)

            print("Analysis runtime: {0}").format(data_report_time - analysis_ts)

            # Clear history
            flow_data_pool.clear()
            analysis_ts = curr_time

        else:
            # Recieve data from libtrap
            try:
                data = trap.recv()
            except pytrap.FormatChanged as e:
                fmttype, inputspec = trap.getDataFmt(0)
                rec = pytrap.UnirecTemplate(inputspec)
                adata = e.data

            if len(data) <= 1:
                break

            rec.setData(data)

            # Create a new flow record
            flow = SMTP_Flow(rec)

            if flow.BCP_Filter():
                alerts += 1

            # Update time timestamps
            if not TS_SET:
                flow_first_ts = flow.TIME_FIRST
                TS_SET = 1

            if flow.TIME_LAST > flow_curr_ts:
                flow_curr_ts = flow.TIME_LAST

            # Add it to the history flow datapool
            if flow.SRC_IP in flow_data_pool.keys():
                if flow.DST_IP in flow_data_pool.keys():
                    flow_data_pool[flow.DST_IP].incoming += 1
                else:
                    flow_data_pool[flow.DST_IP] = SMTP_Server(flow.DST_IP)

                flow_data_pool[flow.SRC_IP].add_new_flow(flow)
                flow_data_pool[flow.SRC_IP].update_time(flow)

            else:
                flow_data_pool[flow.SRC_IP] = SMTP_Server(flow)

            # Increment flow checked counter
            checked += 1

            # Print every 10k flows in pool
            if checked % 10000 == 0:
                print('Flows in pool [{0}]').format(len(flow_data_pool))

            # Similarity clustering
            #if last_clustering + clustering_interval < curr_time:
            #    cluster.clustering(flow_data_pool)
            #    last_clustering = time.time()

    # Free allocated TRAP IFCs
    trap.finalize()
    print("Flow scan report:")
    print("{0} suspicious in {1} flows").format(alerts, checked)
    print("Potencial spammers: {0}.\n").format(len(potencial_spammers))
    print(cluster)

    CDF(flow_data_pool)

    write_report(potencial_spammers)

if __name__ == "__main__":
    main()

