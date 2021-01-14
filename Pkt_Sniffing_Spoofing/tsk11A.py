#!/usr/bin/python3
from scapy.all import *

def print_pkt(pkt): 
	pkt.show()

pkt = sniff(filter='icmp',prn=print_pkt)