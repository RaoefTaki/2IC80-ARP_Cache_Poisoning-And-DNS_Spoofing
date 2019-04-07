#!/usr/bin/env python3

"""constants.py: Constants used throughout the project."""

ARP_TIMEOUT = 0.005 #Timeout concerning arp responses

#Warning concerning DNS Spoof implementation disables IP Forwarding
FORWARD_WARNING = ('\n[!] Warning:\n'
'[!] Just before initiating the DNS Spoofing procedure, the tool disables the operating system\'s IPv4 forwarding.\n'
'[!] This because the tool itself already forwards IP traffic from victims.\n'
'[!] Having the operating system\'s IPv4 forwarding enabled would result in traffic being forwarded twice.\n'
'[!] Also, this would cause the operating system to forward DNS requests we want to spoof.\n'
'[!] Be warned when your device requires IPv4 forwarding for other reasons.\n')

#Explanatory about dns tuple selection procedure 
DNS_EXPLANATION = ('\nBefore continuing, a short explanation about the upcoming selection process is given.\n'
'You will be presented a table of your selected ARP Cache Poisoning victims.\n'
'At each iteration of the selection process, you can choose 1 of these victims.\n'
'For the chosen victim, you can then specify what domains you want to spoof to what IPv4 address.\n'
'Specifically, after choosing a victim, you will be asked to enter an IPv4 address.\n'
'After entering this IPv4 address, you are asked to specify the domains that, for the victim, will be redirected to this address.\n'
'For each victim, you can specify as many of these IPv4 addresses as you want.\n'
'For each IPv4 address, you can specify as many domains as you want.\n')
