#!/usr/bin/env python3

"""interfaceoperations.py: File containing several interface related operations (mostly w.r.t. retrieving addresses of an interface).""" 

import netifaces #Used to get list of interfaces. Also for IP address, MAC address and subnet mask of given interface

#Gets available interfaces
def getAvailableInterfaceList():
	return netifaces.interfaces()

#Gets IP address corresponding to given interface
def getIP(iface):
	return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']

#Gets MAC corresponding to given interface
def getMAC(iface):
	return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']

#Gets subnet mask of given interface's subnet
def getSubnetMask(iface):
	return netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']