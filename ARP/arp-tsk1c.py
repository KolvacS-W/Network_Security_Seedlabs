 #!/usr/bin/python3
from scapy.all import *
 
E = Ether(
	src='00:0c:29:70:30:23',#本机MAC
    dst='FF:FF:FF:FF:FF:FF'#广播发送
    ) 
A = ARP(
	op=1,#发送arp请求
    hwsrc='00:0c:29:70:30:23',#发送端以太网地址
    psrc='172.16.133.130',#发送端ip
    hwdst='ff:ff:ff:ff:ff:ff',#目的以太网地址
    pdst='172.16.133.130'#目的ip地址
    )
pkt = E/A 

sendp(pkt)