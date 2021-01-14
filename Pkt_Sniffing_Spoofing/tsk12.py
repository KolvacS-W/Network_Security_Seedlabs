#!/usr/bin/python3
from scapy.all import *

a=IP()
a.dst='10.0.2.3'
a.src='127.1.1.1'
b=ICMP()
p=a/b
send (p)