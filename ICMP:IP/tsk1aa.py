#!/usr/bin/python3

from scapy.all import *
ip=IP(src="172.16.133.129", dst="172.16.133.130")
ip.id=1000

udp=UDP(sport=7070,dport=9090)
udp.len=96

payload='A'*32
ip.frag=0
ip.flags=1
pkt=ip/udp/payload
pkt[UDP].chksum=0
send(pkt,verbose=0)


payload='B'*32
ip.frag=4
pkt=ip/udp/payload
pkt[UDP].chksum=0
send(pkt,verbose=0)

payload='C'*32
ip.frag=8
ip.flags=0
pkt=ip/udp/payload
pkt[UDP].chksum=0
send(pkt,verbose=0)

