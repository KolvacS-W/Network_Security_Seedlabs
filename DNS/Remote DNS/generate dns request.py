#!/usr/bin/python
from scapy.all import *
Qdsec = DNSQR(qname='twysw.example.com')
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)
ip = IP(dst='172.16.133.128', src='172.16.133.130')
udp = UDP(dport=53, sport=33333, chksum=0)
pkt = ip/udp/dns

# Save the packet to a file 
with open("ip_req.bin", 'wb') as f:
	f.write(bytes(pkt))