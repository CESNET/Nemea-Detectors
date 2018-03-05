#!/usr/bin/env python3
import pytrap
from flow import *
from global_def import *
""" ************************ CLASS SMTP_ENTITY ***************************** """
# A class for storing information about sender or reciever with time window
# that record a first occourence of sender in traffic and his last interaction
# on the network
class SMTP_ENTITY:
    # SMTP_ENTITY constructor from whole unirec record or just ip from traffic
    def __init__(self, *args):
        self.id = None              # an unique entity identification (it's IP)
        self.sent_history = []      # history of sent msgs from this entity
        self.time_start = args[0].TIME_FIRST
        self.time_end = args[0].TIME_LAST

        self.time_window = self.time_end.getTimeAsFloat() - self.time_start.getTimeAsFloat()

        self.smtp_pool = []         # SMTP communication database
        self.basic_pool = []        # POP3/IMAP communication database

        # traffic counters
        self.incoming = 0           # counter for incoming messages from others
        self.outgoing = 0           # currently using len(sent_history) #TODO

        # entity parameters
        self.traffic_ratio = 0.0    # ratio of incoming/outgoing traffic
        self.rep =  0.0             # reputation score

        # Set up params based on input data
        # got whole template
        if isinstance(args[0], Flow):
            # Separate basic/smtp flows
            if isinstance(args[0], SMTP_Flow):
                self.smtp_pool.append(args[0])
            else:
                self.basic_pool.append(args[0])

            self.id = args[0].SRC_IP
            self.sent_history.append(args[0])

        # got only ip address (args[0] is ip and args[1] is time)
        elif isinstance(args[0], pytrap.UnirecIPAddr):
            self.id = args[0].DST_IP
            self.incoming += 1


    def __str__(self):
        return ("{0},{1},{2},{3},{4},{5}").format(self.id, len(self.sent_history),
                                                    self.incoming, self.time_start,
                                                    self.time_end, self.time_window)
    # Getter for number of sent mails from this server
    def count_sent(self):
        return len(self.sent_history)

    # Updates time_end parametr of this entity
    def update_time(self, flow):
        if flow.TIME_LAST > self.time_end:
            self.time_end = flow.TIME_LAST
            self.time_window = self.time_end.getTimeAsFloat() - self.time_start.getTimeAsFloat()
        else:
            return None

    # Function that adds flows for server history
    def add_new_flow(self, flow):
        self.sent_history.append(flow)
        self.outgoing += 1

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
    """
    Function that checks whether a machine with IP as self.id is a legit
    smtp mail server or not. It looks at incoming and outgoing traffic
    and compares the ratio between these two parameters, if the outgoing
    traffic ratio is X then function returns positive value, otherwise
    negative one, also it checks for unqie DST_IP's in sent history
    """
    def is_legit(self):
        # Calculate traffic ratio
        sent = len(self.sent_history)
        if sent is not 0:
            traffic_ratio = self.incoming / sent
        else:
            traffic_ratio = 0

        # Check for unique DST_IPs
        unique_ips = set()

        for flow in self.sent_history:
            unique_ips.add(flow.DST_IP)

        if len(unique_ips) > MAX_ALLOWED_SERVERS or traffic_ratio < 1.2:
            return True
        else:
            return False

    # Setter for current ratio of traffic on this smtp server
    def set_up_traffic_ratio(self):
        outgoing = len(self.sent_history)
        incoming = self.incoming
        if outgoing is not 0:
            tr = float(incoming) / float(outgoing)
            self.traffic_ratio = tr
            return True
        else:
            self.traffic_ratio = 0
            return None


