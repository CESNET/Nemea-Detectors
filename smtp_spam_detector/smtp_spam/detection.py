#!/usr/bin/env python
from smtp_spam import cluster
from smtp_spam import smtp_flow
from smtp_spam import flow
from smtp_spam import smtp_entity

class SpamDetection 
    """ data is dict of flows from multirecievers """
    def __init__(data)
        # Storage for both flow types
        self.flow_data = data
        
        # Separated data pools
        self.smtp_flows = {}
        self.basic_flows = {}

        # Blacklisted entites that are probably spammers
        self.potencial_spammers = []
        
        # Timers and timestamps
        self.t_clean = 0
        self.t_detect = 0
        self.t_cluster = 0
    
        """ Counters for how many flows has been checked,
            and how many alerts has been generated. 
        """
        self.checked = 0
        self.alerts = 0

        # Cluster for clustering spammers, further analysis
        self.cluster = Cluster() 

    def frequency_analysis() 
        """ Do frequencual analysis here """
        return None

    def clustering()
        """ Do clustering analysis here """
        return None
        
    def clean_up()
        """ Do clean up here, get rid off old data """
        return None
