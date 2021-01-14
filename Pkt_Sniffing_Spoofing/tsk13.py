#!/usr/bin/python3
from scapy.all import *

a=IP()
a.dst='10.0.2.4'

for i in range(1,10):
	a.ttl=i
	b=ICMP()
	p=a/b
	send(p)