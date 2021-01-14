#!/usr/bin/python3
from scapy.all import *
import fcntl
import struct
import os
import time
from select import *

#Create a TUN interface and configure it.
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001 
IFF_TAP = 0x0002 
IFF_NO_PI = 0x1000
# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'Jq%d', IFF_TUN | IFF_NO_PI) 
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00") 

#configure
os.system("ip addr add 192.168.53.11/24 dev {}".format(ifname)) 
os.system("ip link set dev {} up".format(ifname))

print("Interface Name: {}".format(ifname))


#Get the data from the socket interface; treat the received data as an IP packet. 
#Write the packet to the TUN interface.
IP_A = "0.0.0.0" 
PORT = 9090

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
sock.bind((IP_A, PORT))

while True:

	# this will block until at least one interface is ready 
	ready, _, _ = select([sock, tun], [], [])
	for fd in ready:
		if fd is sock:
			data, (ip, port) = sock.recvfrom(2048)
			pkt = IP(data)
			print("From socket <==: {} --> {}".format(pkt.src, pkt.dst)) 
			#... (code needs to be added by students) ...
			if pkt.dst == '192.168.22.129':
				os.write(tun, bytes(pkt))
				print('request go ')


		if fd is tun:
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst)) 
			#... (code needs to be added by students) ...
			if pkt.src == '192.168.22.129':
			# Send the packet via the tunnel 
				sock.sendto(packet, ('172.16.133.129', 9090))
				print('reply go')

'''
while True:
	data, (ip, port) = sock.recvfrom(2048)
	print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT)) 
	pkt = IP(data)
	print(" Inside: {} --> {}".format(pkt.src, pkt.dst))

	os.write(tun, bytes(pkt))
	print('sent')

'''