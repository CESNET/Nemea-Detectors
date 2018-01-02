#!/usr/bin/env python
""" Module imports """
import cluster
import flow
import smtp_entity
""" Partial imports """
from difflib import SequenceMatcher
from pytrap import TrapCtx
from threading import *
""" Full imports """
import pytrap
import sys
import time
""" Interfaces definition """
BASIC_IF = 0
SMTP_IF = 1

class MultiReciver(threading.Thread):
    def __init__(self, shared_data):
        threading.Thread.__init__(self)
        self.flow_pool = shared_data
    
    def run(self, cond):
        sys.stderr.write("Starting MultiReciever at {0}".
                format(time.ctime(time.time())))

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
        threads = []
        with cond:
            # Create workers for each reciever
            basic_rcv = threading.Thread(target=get_ctx_data,
                                         args=(trap, BASIC_IF, flow_queue))
            smtp_rcv = threading.Thread(target=get_ctx_data,
                                        args=(trap, SMTP_IF, flow_queue))
            # Handle the recieved data from recivers
            data_handler = threading.Thread(target=data_handling,
                                            args=(flow_queue))
            # Add threads to tread list
            threads.append(basic_rcv)
            threads.append(smtp_rcv)
            threads.append(data_handler)
            # Try to start the threads
            try:
                basic_rcv.start()
                smtp_rcv.start()
                data_handler.start()
            except:
                sys.stderr.write("Unable to start one of the threads.\n")
                sys.stderr.write(threading.currentThread())
                sys.stderr.write(threading.enumerate())

            # Finilize multireciver
            flow_queue.put(0)
            for t in threads:
                t.join()

            # Free allocated memory
            trap.finalize()
            cond.notifyAll()

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
     
    def data_handling(q): 
        # Load flow from queue 
        while (True): 
            try: 
                rec = q.get() 
                flow = Flow(rec) 
                if flow.SRC_IP in data.keys(): 
                    data[flow.SRC_IP].history.append(flow) 
                else: 
                    self.flow_pool[flow.SRC_IP] = SMTP_ENTITY(flow.SRC_IP) 
                print("DEBUG: Flow recieved from queue.\n") 
                print(flow) 
            except: 
                sys.stderr.write("No data in queue.\n") 
        return True 

class SpamDetection:
    """ Data is dict of flows from multirecievers """
    def __init__(self,data):
        # Storage for both flow types
        self.data = data
        
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

    def analysis(cond): 
        """ Do frequencual analysis here """
        t = threading.currentThread()
        with cond:
            cond.wait()
            for entity in data:
                print("[detection] Reading: {0}".format(entity))
        return None

    def clustering():
        """ Do clustering analysis here """
        return None
        
    def clean_up():
        """ Do clean up here, get rid off old data """
        return None

def main():
    condition = threading.Condition()
    flows = {}
    treads = []
    condition = Condition()
    reciver = MultiReciver(flows)
    detector = SpamDetection(flows)

    # Create threads
    fetch_flows = Thread(name="Reciver", target=reciver.run, args="cond")
    analysis = Thread(name="Analysis", target=detector.analysis,args="cond")
    clustering = Thread(name="Clustering", target=detector.clustering, args="")
    cleaning = Thread(name="Cleaning", target=detector.clean_up ,args="")
    
    # Add threads to thread list
    threads.append(fetch_flows, analysis, clustering, cleaning)
   
    # Timestamps
    curr_time = 0
    last_cluster = 0
    last_clean = 0
    clust_interval = 1000
    clean_interval = 500

    # Detection loop
    while true:
        try:
            fetch_flows.start()
            analysis.start()

            if last_cluster - curr_time > clust_interval:
                clustering.start()

            if last_clean - curr_time > clean_interval:
                cleaning.start()
        except:
            sys.stderr.write("Could not start one of the threads.\n")

        for t in threads:
            t.join()
    return 0
