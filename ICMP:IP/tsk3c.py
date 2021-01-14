#!/usr/bin/python3
from scapy.all import *
# Construct IP header
ip1 = IP(src="172.16.133.129", dst="192.168.22.129",id=1000,frag=0,flags=1,)

# Construct UDP header
udp = UDP(sport=7070, dport=9090)
udp.len = 32 # This should be the combined length of all fragments
# Construct payload
payload1 = 'A' * 32 # Put 80 bytes in the first fragment

# Construct the entire packet and send it out
pkt1 = ip1/udp/payload1 # For other fragments, we should use ip/payload
pkt1[UDP].checksum = 0

send(pkt1, verbose=0)