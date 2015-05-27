ARP poison with python
======================
A simple python script to perform ARP cache poisoning between two targets, preferably gateway and target to allow for MITM attacks and monitoring of traffic between the targets.

Uses scapy to create and send packets, also enables IP forwarding and will restore targets original data when exiting.

Requirements
------------
Needs to be run as root.

	Python 2.7
	Scapy 2.2.0

Usage
-----
python arp-poison.py -g 192.168.1.1 -t 192.168.1.109 -i eth0

Required:  
-g gateway for the target to perform MITM  
-t target IP

Optional:  
-i specify the interface to use (scapy will use default if not set)