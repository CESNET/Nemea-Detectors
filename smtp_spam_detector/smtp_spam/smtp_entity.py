#!/usr/bin/env python3
""" ************************ CLASS SMTP_ENTITY ***************************** """
# A class for storing information about sender or reciever with time window
# that record a first occourence of sender in traffic and his last interaction
# on the network
class SMTP_ENTITY:
    # SMTP_ENTITY constructor from whole unirec record or just ip from traffic
    def __init__(self, arg):
        self.id = None              # an unique entity identification (it's IP)
        self.sent_history = []      # history of sent msgs from this entity
        self.last_seen = 0          # time of last occurrence in traffic

        # traffic counters
        self.incoming = 0           # counter for incoming messages from others
        self.outgoing = 0           # currently using len(sent_history) #TODO

        # entity parameters
        self.traffic_ratio = 0.0
        self.rep =  0.0             # reputation score

        # Set up params based on input data
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

    # Updates last_seen parametr of this entity
    def update_time(self, flow):
        if flow.TIME_LAST > self.last_seen:
            self.last_seen = flow.TIME_LAST
        else:
            return None

    # Function that adds flows for server history
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

        #TODO Rep score
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


