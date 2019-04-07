#!/usr/bin/env python3

"""arphandlers.py: File containing the handlers (e.g., for input) used in Schoolbook_RSA.py."""

from networkreconnaissance import *

#Input handler. Obtains and processes (as in, checks for validity) input from user. Returns given input in desired format.
class InputHandler:
    
    def interfaceChoice(self, allIDs, ifaceList):
        while True:
            ifaceID = input('\nChoose the desired interface (from above table) to use for the ARP cache poisoning by specifying its corresponding ID:\n')

            if ifaceID in allIDs:
                return ifaceList[int(ifaceID)]
            else:
                print('Specified ID does not correspond to an interface in the table. Try again.')

    def attackChoice(self):
        return eval(input('\nDo you solely want to perform ARP Cache Poisoning (0), or DNS Spoofing as well (1)?:\n'))

    def arpMethodChoice(self):
        return eval(input('\nConcerning the ARP Cache Poisoning attack, '
            'do you want to select the victim(s) from a list of active hosts (0) or manually provide the victims\' IPv4 addresses (1)?:\n'))

    def arpTuplesChoice(self, iface, activeHosts):
        arpTuples = []
        allIDs = list(map(str, range(len(activeHosts)))) #List of all IDs given to active host in activeHosts
        remainingIDs = list(map(str, range(len(activeHosts)))) #List of IDs of hosts that are available for selection (as a victim). A host cannot be picked twice.

        #Ask user for victims to poison and IPv4 addresses to spoof
        #While there are still remainingIDs, there are still hosts that are available to be selected as a victim
        while len(remainingIDs):
            victimChoice = input('\nChoose an(other) ARP Cache Poisoning victim from the list of active hosts '
                'above by specifying the corresponding ID, or quit the selection process by inputting Q:\n')

            #Process input of the user
            if victimChoice != 'Q' and victimChoice != 'q':
                    
                #Check if the choice is included in the remainingIDs array
                if not victimChoice in remainingIDs:
                    print('Either the host was already selected in previous iteration or the specified ID does not correspond to any active host. Try again.')
                    continue
                else:
                    spoofChoice = input('\nChoose a host to spoof ' + activeHosts[int(victimChoice)]['IP'] + ' with, from the list of active hosts above by specifying the '
                        'corresponding ID, or enter a legitimate IPv4 address:\n')

                    if spoofChoice in allIDs: #spoofChoice from active hosts, i.e., not manually inputted
                        if spoofChoice == victimChoice:
                            print('No point in trying to make the victim think their own IPv4 address is at your MAC. Try again.')
                            continue
                        else:
                            spoofIP = activeHosts[int(spoofChoice)]['IP']  
                            spoofMAC = activeHosts[int(spoofChoice)]['MAC'] 
                    else: #spoofChoice is manually inputted IPv4
                        if spoofChoice == activeHosts[int(victimChoice)]['IP']:
                            print('No point in trying to make the victim think their own IPv4 address is at your MAC. Try again.')
                            continue
                        else:
                            spoofIP = spoofChoice

                            spoofHost = arpingHost(iface, spoofChoice)

                            if spoofHost:
                                spoofMAC = spoofHost['MAC']
                            else:
                                spoofMAC = ''

                    victimIP = activeHosts[int(victimChoice)]['IP']
                    victimMAC = activeHosts[int(victimChoice)]['MAC']

                    #Store appropriate ARP attack tuple
                    arpTuples.append({'VIP' : victimIP, 'VMAC': victimMAC, 'SIP' : spoofIP, 'SMAC' : spoofMAC})

                    #Remove selected victim ID from remaining IDs to make sure the victim isn't selected twice
                    remainingIDs.remove(victimChoice)

                    print('\n' + victimIP + ' will be tricked into thinking ' + spoofIP + ' is at your MAC address.')
            else:
                break

        if not remainingIDs:
        	print('\nNo victims left to choose. Automatically proceeding.')
        return arpTuples

    def arpTuplesChoiceManual(self, iface):
        arpTuples = []

        #Need at least one tuple
        while not arpTuples:
        	victimIPs = []
        	selection = True
        	#Tuple creation process
	        while selection:
	            victimIP = input('\nEnter the IPv4 address of a victim, or quit the selection process by inputting Q:\n')

	            if victimIP == 'q' or victimIP == 'Q':
	            	break

	            #If victim already selected, do not add and continue with a next iteration of this loop (i.e., user tries again)
	            if victimIP in victimIPs:
	                print('This victim was already selected in a previous iteration. Try again.')
	                continue

	            spoofIP = input('\nEnter the IPv4 address of the host you wish to spoof ' + victimIP + ' with:\n')

	            #No use in having same victimIP and spoofIP
	            if victimIP == spoofIP:
	                print('No point in trying to make the victim think their own IPv4 address is at your MAC. Try again.')
	                continue

	            victim = arpingHost(iface, victimIP)

	            #If the victim was not active, go to another iteration of the outer while loop
	            if not victim:
	            	print('\n' + victimIP + ' is currently not active. Try again.')
	            	continue

	            #However, if victim was active
	            victimIPs.append(victimIP)

	            spoofHost = arpingHost(iface, spoofIP)

	            #If spoofed host is active, store MAC. Else, no MAC to be stored.
	            if spoofHost:
	                spoofMAC = spoofHost['MAC']
	            else:
	                spoofMAC = ''

	            #Store appropriate ARP attack tuple
	            arpTuples.append({'VIP' : victimIP, 'VMAC': victim['MAC'], 'SIP' : spoofIP, 'SMAC' : spoofMAC})

	            print('\n' + victimIP + ' will be tricked into thinking ' + spoofIP + ' is at your MAC address.')

	            selection = eval(input('\nDo you want to quit selecting (0) or still add a different host as victim (1)?:\n'))

	        #Check if there are any tuples
	        if not arpTuples:
	        	print('No ARP attack combination (i.e., victim and spoofed host) specified. Try again.')

        return arpTuples

    def dnsTuplesChoice(self, arpTuples):
        dnsTuples = []
        allIDs = list(map(str, range(len(arpTuples)))) #List of all IDs given to active host in activeHosts
        remainingIDs = list(map(str, range(len(arpTuples)))) #List of IDs of hosts that are available for selection (as a victim). A host cannot be picked twice.
        
        while remainingIDs:
            victimChoice = input('\nChoose a DNS Spoof victim from the table of ARP Cache Poisoning victims '
                'by specifying the victim\'s corresponding ID, or quit the selection process by inputting Q:\n')

            #Process input of the user
            if victimChoice != 'Q' and victimChoice != 'q':
                    
                #Check if the choice is included in the remainingIDs array
                if not victimChoice in remainingIDs:
                    print('Either the host was already selected in previous iteration or the specified ID does not correspond ' 
                        'to any ARP Cache Poisoning victim in the table. Try again.')
                    continue
                else:
                    domainTuples = {} #Used to store the domain tuples. Format: {IPToSpoofTo1 : [domain1, domain2], IPToSpoofTo2 : [domain3, domain4], ...}
                    spoofSelection = True
                    spoofIPs = [] #Stores specified IPv4s to spoof to, used to make sure no IP is specified twice

                    while spoofSelection:
                        domSelection = True
                        domains = [] #Stores specified domains 
                        
                        spoofIP = input('\nProvide an IPv4 address to which you want to redirect, for ' + arpTuples[int(victimChoice)]['VIP']+ ', some domain(s):\n')
                        
                        if spoofIP in spoofIPs:
                            print('That IPv4 was already specified in a previous iteration. Try again.')
                            continue

                        #Ask for domains to spoof
                        while domSelection:
                        	cont = False #determines whether to continue to next iteration of loop, based on specified domain

                        	domainChoice = input('\nSpecify a domain that is to be redirected to ' + spoofIP + ', for ' +
                        		arpTuples[int(victimChoice)]['VIP'] + ':\n')

                        	#Check if domain is a valid choice w.r.t. previously chosen domains. If not, continue.
                        	if domainChoice in domains:
                        		cont = True

                        	for domainList in domainTuples.values():
                        		for domain in domainList:
                        			if domainChoice == domain:
                        				cont = True
                        				break

                        	if cont:
                        		print('That domain was already specified in a previous iteration. Try again.')
                        		continue

                        	domains.append(domainChoice)

                        	domSelection = eval(input('\nDo you want to quit the domain selection process (0), or add another domain to be redirected to ' 
                                + spoofIP + ', for ' + arpTuples[int(victimChoice)]['VIP'] + ' (1)?:\n'))

                        domainTuples[spoofIP] = domains
                        spoofIPs.append(spoofIP)

                        spoofSelection = eval(input('\nDo you want to quit adding new IPv4s (0), '
                            'or add another IPv4 (1)?:\n'))
                    
                    #Remove selected victim ID from remaining IDs to make sure the victim isn't selected twice
                    remainingIDs.remove(victimChoice)

                    #Store appropriate DNS attack tuple
                    dnsTuples.append({'VIP' : arpTuples[int(victimChoice)]['VIP'], 'SMAC' : arpTuples[int(victimChoice)]['SMAC'], 'DomainTuples' : domainTuples})
            else:
                break

            if not remainingIDs:
                print('Out of ARP Cache Poisoning victims to choose from. All of them will be targets of DNS Spoofing as well!')

        return dnsTuples

    def fingerprintActiveHosts(self, activeHosts):
        fingerprint = eval(input('\nDo you want to immediately continue (0), or first perform some extra fingerprinting on the active hosts (1)?:\n'))

        if fingerprint:
            print('\nInitiating fingerprinting process.')

        #Fingerprint active hosts 
        #Format: [{'IP' : IP1, 'MAC' : MAC1, 'Fingerprint' : {'OS' : os1, 'Type' : type1, 'OpenTCP' : openTCPports1}], ...])
        for i in range(len(activeHosts)):
            if fingerprint:
                activeHosts[i]['Fingerprint'] =  fingerprintHost(activeHosts[i]['IP'])
            else:
                activeHosts[i]['Fingerprint'] = {'OS': 'N/A', 'Type': 'N/A', 'OpenTCP': []}

        return activeHosts

    def allowIPForward(self):
        doForward = input('\nDo you want to disable (0) or enable (1) IP forwarding? (enabling advised when only ARP Cache Poisoning):\n')

        #Make sure input is valid, as this input is going to be part of kernel command
        while doForward != '0' and doForward != '1':
            print('Invalid input. Try again.')
            doForward = input('\nDo you want to disable (0) or enable (1) IP forwarding? (enabling advised when only ARP Cache Poisoning):\n')

        return doForward

