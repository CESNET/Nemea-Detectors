# NEMEA Detectors

Detection modules of the [NEMEA system](https://github.com/CESNET/Nemea) provide mechanisms for automatic detection of malicious network traffic.
This repository contains modules with the following detection capabilities:

* [amplification_detection](amplification_detection): universal detector of DNS/NTP/... amplification attacks
* [blacklistfilter](blacklistfilter): module that checks whether observed IP addresses are listed in any of given public-available blacklists
* [brute_force_detector](brute_force_detector): detector of brute-force attacks over SSH, RDP and TELNET.
* [ddos_detector](ddos_detector): detector of DDoS attacks
* [haddrscan_detector](haddrscan_detector): detector of horizontal scans
* [hoststatsnemea](hoststatsnemea): universal detection module based on computation of statistics about hosts, it can detect some types of DoS, DDoS, scanning
* [miner_detector](miner_detector): detector of crypto mining hosts.
* [sip_bf_detector](sip_bf_detector): detector of brute-force attacks attempting to breach passwords of users on SIP (Session Initiation Protocol) devices
* [smtp_spam_detector](smtp_spam_detector): detector of spam sources
* [tunnel_detection](tunnel_detection): detector of communication tunnels over DNS (e.g. using iodine or tcp2dns)
* [voip_fraud_detection](voip_fraud_detection): detector of guessing dial scheme of Session Initiation Protocol (SIP)
* [vportscan_detector](vportscan_detector): detector of vertical scans based on TCP SYN
* [waintrusion_detector](waintrusion_detector): detector of attacks on web applications
