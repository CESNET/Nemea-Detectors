#!/usr/bin/env python
""" Module imports """
import cluster
import flow
import smtp_entity

""" Partial imports """
from difflib import SequenceMatcher
from pytrap import TrapCtx

""" Full imports """
import pytrap
import sys
import time

""" Interfaces definition """
BASIC_IF = 0
SMTP_IF = 1

class SpamDetection:
    """ Data is dict of flows from multirecievers """
    def __init__(data):
        # Storage for both flow types
        self.flow_data = data
        
        # Separated data pools
        self.smtp_flows = {}
        self.basic_flows = {}

        # Blacklisted entites that are probably spammers
        self.potencial_spammers = []
        
        # Timers and timestamps
        self.t_clean = 0                # last cleaning time
        self.t_detect = 0               # last detection time
        self.t_cluster = 0              # last clustering time
    
        """ Counters for how many flows has been checked,
            and how many alerts has been generated. 
        """
        self.checked = 0
        self.alerts = 0

        # Cluster for clustering spammers, further analysis
        self.cluster = Cluster() 

    """ Functions that compares two strings and decide their similarity 
        according to SIMILARITY_INDEX, return true if they are similar otherwise
        false 
    """
    def is_similar(server, cluster):
        #Server, list(Server)
        for s_flow in server.sent_history:
            for cluster_server in cluster:
                for c_flow in cluster_server.sent_history:
                    if SequenceMatcher(None, s_flow.get_name(),
                                      c_flow.get_name()).ratio() > SIMILARITY_INDEX:
                        return True
        return False

    # Class for basic flow without SMTP Headers 
    def get_ctx_data(trap, interface, queue): 
        while (True): 
            try: 
                data = trap.recv(interface) 
            except pytrap.FormatChanged as e: 
                fmttype, inputspec = trap.getDataFmt(interface) 
                rec = pytrap.UnirecTemplate(inputspec) 
                data = e.data 
     
            if len(data) <= 1: 
                break 
     
            rec.setData(data) 
            queue.put(rec) 
        return True 
     
    def data_handling(data, q): 
        # Load flow from queue 
        while (True): 
            try: 
                rec = q.get() 
                flow = Flow(rec) 
                if flow.SRC_IP in data.keys(): 
                    data[flow.SRC_IP].history.append(flow) 
                else: 
                    data[flow.SRC_IP] = SMTP_ENTITY(flow.SRC_IP) 
                print("DEBUG: Flow recieved from queue.\n") 
                print(flow) 
            except: 
                sys.stderr.write("No data in queue.\n") 
        return True 

    def flow_reciever():
        # Create a new trap context
        trap = pytrap.TrapCtx()
        """
            Trap initialization for two input interfaces, and no output interface
        """
        trap.init(["-i", "u:flow_data_source,u:smtp_data_source"], 2, 0)
        # Set up requried format to accept any unirec format.
        trap.setRequiredFmt(BASIC_IF)   # Refers to flows without SMTP headers
        trap.setRequiredFmt(SMTP_IF)    # Refers to flows with SMTP headers
        """
            *** Multireciever Implementation ***
            Splits unirec input from libtrap into multiple interfaces
            this enables recieving unirec flows with different format.
        """
        # Data queue
        flow_queue = Queue.Queue()
        # Create workers for each reciever
        basic_rcv = threading.Thread(target=get_ctx_data,
                                     args=(trap, BASIC_IF, flow_queue))
        smtp_rcv = threading.Thread(target=get_ctx_data,
                                    args=(trap, SMTP_IF, flow_queue))
        # Handle the recieved data from recivers
        data_handler = threading.Thread(target=data_handling,
                                        args=(data, flow_queue))
        basic_rcv.start()
        smtp_rcv.start()
        data_handler.start()

        # Finilize multireciver
        flow_queue.put(0)
        basic_rcv.join()
        smtp_rcv.join()
        data_handler.join()

        # Free allocated memory
        trap.finalize()


    def frequency_analysis(): 
        """ Do frequencual analysis here """
        return None

    def clustering():
        """ Do clustering analysis here """
        return None
        
    def clean_up():
        """ Do clean up here, get rid off old data """
        return None
