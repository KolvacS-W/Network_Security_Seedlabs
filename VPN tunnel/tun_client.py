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
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'wu%d', IFF_TUN | IFF_NO_PI) 
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00") 

#configure
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname)) 
os.system("ip link set dev {} up".format(ifname))

print("Interface Name: {}".format(ifname))

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
IP_A = "0.0.0.0" 
PORT = 9090

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
			if pkt.dst == '192.168.53.99':
				print('reply back')
				os.write(tun, bytes(pkt))


		if fd is tun:
			packet = os.read(tun, 2048)
			pkt = IP(packet)
			print("From tun ==>: {} --> {}".format(pkt.src, pkt.dst)) 
			#... (code needs to be added by students) ...
			if pkt.dst == '192.168.22.129':
			# Send the packet via the tunnel 
				sock.sendto(packet, ('172.16.133.131', 9090))
				print('request go')




'''
while True:

# Get a packet from the tun interface 
	packet = os.read(tun, 2048)
	#print('here 1')
	if True:
		#print('here 2')
		ip = IP(packet) 
		
		#print('here 3')
		print('go in:')
		print(ip.summary())
		
		#print(icmp)
		#print(icmp.type)

		if ICMP in ip and ip[ICMP].type is 8:
			print('this is request')
			
			icmp=ip[ICMP]
			print(icmp.type)
			newip = IP(src=ip.dst, dst=ip.src)
			newicmp=ICMP(type=0,id=icmp.id,seq=icmp.seq)
			data=ip[Raw].load
			newpkt = newip/newicmp/data

			print('go out')
			print(newip.summary)
			os.write(tun, bytes(newpkt))

		#Send out a spoof packet using the tun 

		# newip = IP(src=ip.dst, dst=ip.src)
		# newpkt = newip/ip.payload
		# print('go out:')
		# print(newpkt.summary())
		# os.write(tun, bytes(newpkt))
'''		
