# NEMEA Detectors

Detection modules of the [Nemea system](https://github.com/CESNET/Nemea) provide mechanisms for automatic detection of malicious network traffic.
This repository contains modules with the following detection capabilities:

* [amplification_detection](amplification_detection): universal detector of DNS/NTP/... amplification attacks
* [blacklistfilter](blacklistfilter): module that checks whether observed IP addresses are listed in any of given public-available blacklists
* [hoststatsnemea](hoststatsnemea): universal detection module based on computation of statistics about hosts, it can detect some types of DoS, DDoS, scanning
* [tunnel_detection](tunnel_detection): detector of communication tunnels over DNS (e.g. using iodine or tcp2dns)
* [voip_fraud_detection](voip_fraud_detection): detector of guessing dial scheme of Session Initiation Protocol (SIP)
* [vportscan_detector](vportscan_detector): detector of vertical scans based on TCP SYN
