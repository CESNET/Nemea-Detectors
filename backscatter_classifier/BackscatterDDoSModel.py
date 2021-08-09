#!/usr/bin/env python3

class DDoSModel:

    def __init__(self, ddos_class: int, tcp_model, tcp_scaler, icmp_model, icmp_scaler, tcp_features:list, icmp_features:list, primary:int,
                 derived: int):
        # Class value for DDoS
        self.DDOS_CLASS = ddos_class
        # TCP Backscatter model
        self.tcp_model = tcp_model
        # TCP Scaler
        self.tcp_scaler = tcp_scaler
        # ICMP Backscatter model
        self.icmp_model = icmp_model
        # ICMP Scaler
        self.icmp_scaler = icmp_scaler
        # List of TCP features
        self.tcp_features = tcp_features
        # List of ICMP features
        self.icmp_features = icmp_features
        # Primary flag value
        self.PRIMARY = primary
        # Derived flag value
        self.DERIVED = derived