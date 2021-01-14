#!/usr/bin/python3
from scapy.all import *

def spoof_pkt(pkt):
#if this is a ping pkt
	if 'ICMP' in pkt and pkt['ICMP'].type == 8:
        	print("ping pkt from " + str(pkt['IP'].src) + " to " + str(pkt['IP'].dst))
		#make a fake echo pkt
        	ip = IP(src=pkt['IP'].dst, dst=pkt['IP'].src, ihl=pkt['IP'].ihl)
        	icmp = ICMP(type=0, id=pkt['ICMP'].id, seq=pkt['ICMP'].seq)
        	data = pkt['Raw'].load
        	fakepkt = ip / icmp / data

        	print("spoof pkt from " + str(fakepkt['IP'].src) + " to " + str(fakepkt['IP'].dst))
        	send(fakepkt, verbose=0)


pkt=sniff(filter='icmp', prn=spoof_pkt)
