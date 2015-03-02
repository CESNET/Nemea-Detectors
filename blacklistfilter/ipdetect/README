IP blacklist README

Goal:	Module recieves the UniRec and checks if the stored source
	address or destination address is not present in any 
	blacklist that are available. If any of the addresses is 
	blacklisted the record is changed by adding a number of 
	the list which blacklisted the address. UniRec with this 
	flag is then sent to the next module.

Input Interface: UniRec format (<COLLECTOR_FLOW>)
Output Interface: UniRec format (<COLLECTOR_FLOW>,SRC_BLACKLIST,
		  DST_BLACKLIST)

Usage:	./ipblacklistfilter -i <trap_interface> <blacklist_folder>

Note:	This module should be controlled by python script "detector.py"	
