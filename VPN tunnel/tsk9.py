#!/usr/bin/python3
import fcntl
import struct
import os
import time
from scapy.all import *
from select import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001 
IFF_TAP = 0x0002 
IFF_NO_PI = 0x1000
# Create the tun interface
tap = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'wut%d', IFF_TAP | IFF_NO_PI) 
ifname_bytes = fcntl.ioctl(tap, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00") 

#configure
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname)) 
os.system("ip link set dev {} up".format(ifname))

print("Interface Name: {}".format(ifname))



while True:
	packet = os.read(tap, 2048) 
	'''
	if True:
		ether = Ether(packet)
		print(ether.summary())
	'''


	if True:
		print("--------------------------------") 
		ether = Ether(packet)
		print(ether.summary())
# Send a spoofed ARP response
		if ARP in ether and ether[ARP].op == 1 :
			arp = ether[ARP] 
			newether = Ether(src='00:0c:29:70:30:23',#伪造Mac为 Host V 的MAC地址
							dst='FF:FF:FF:FF:FF:FF'
						)#广播发送

			newarp = ARP(op=2,hwsrc='00:0c:29:70:30:23',#发送端以太网地址
							psrc=arp.pdst,#发送端ip
							hwdst=arp.hwsrc,#目的以太网地址
							pdst=arp.psrc#目的ip地址
						) 

			newpkt = newether/newarp
			print("***** Fake response: {}".format(newpkt.summary())) 
			os.write(tap, bytes(newpkt))


