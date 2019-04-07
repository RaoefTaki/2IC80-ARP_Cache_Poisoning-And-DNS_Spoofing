#!/usr/bin/env python3

"""networkreconnaissance.py: Implementation of several relevant network reconnaissance operations.""" 

import random #Used to randomize
import nmap #Used to fingerprint hosts
from scapy.all import * #Import scapy
from constants import * #Import used constants
from interfaceoperations import *
from ipconversions import *

#Scans subnet attached to the given interface for active hosts (apart from your own host)
def arpingSubnet(iface):
    activeHosts = []

    #Get relevant chosen interface metadata
    ownIP = getIP(iface)
    ownMAC = getMAC(iface)
    subnetMask = getSubnetMask(iface)

    binarySubnetPrefix = computeBinaryIPv4SubnetPrefix(ownIP, subnetMask)
    binaryHostSuffixes = computeBinaryIPv4HostSuffixes(len(binarySubnetPrefix))
            
    #Make sure we do not scan for our own IPv4
    binaryHostSuffixes.remove(convertIPv4ToBinary(ownIP)[len(binarySubnetPrefix):])

    #Randomize order of suffixes
    randomizedHostSuffixes = random.sample(binaryHostSuffixes, len(binaryHostSuffixes))
    
    print('\nScanning subnet for active hosts...')

    #Arping possible IPv4s in subnet
    for i in range(len(binaryHostSuffixes)):
        hostIP = convertBinaryToIPv4(binarySubnetPrefix + randomizedHostSuffixes[i])
        
        arpFrame = Ether(dst='ff:ff:ff:ff:ff:ff', src=ownMAC)/ARP(op="who-has", pdst=hostIP, hwsrc=ownMAC) #Create frame
        
        #Send frame, returns on first response
        ans = srp1(arpFrame, iface=iface, verbose=0, timeout=ARP_TIMEOUT)

        print('Sent packet ' + str(i + 1) + '/' + str(len(binaryHostSuffixes)) + ': ' + arpFrame.summary())

        #If response received, store IP and MAC
        if ans is not None:
            print('Received response from ' + ans.psrc + '. This host is active!')

            activeHosts.append({'IP' : ans.psrc, 'MAC' : ans.hwsrc})

    print('Completed scanning of subnet!')
    print('Found ' + str(len(activeHosts)) + ' active hosts (excluding yourself) in your network.')
    
    return activeHosts

#Arpings a single host, checking for activity.
#Returns {'IP' : hostIP, 'MAC' : hostMAC} if active, Else returns 
def arpingHost(iface, hostIP):
    activeHost = {'IP' : hostIP, 'MAC' : ''}

    ownMAC = getMAC(iface)

    print('\nFinding out whether ' + hostIP + ' is active...')

    arpFrame = Ether(dst='ff:ff:ff:ff:ff:ff', src=ownMAC)/ARP(op="who-has", pdst=hostIP, psrc=getIP(iface), hwsrc=ownMAC) #Create frame

    #Check activity 5 times
    for i in range(5):
        ans = srp1(arpFrame, iface=iface, verbose=0, timeout=ARP_TIMEOUT)

        print('Sent ARP request ' + str(i + 1) + ': ' + arpFrame.summary())

        #If response received, store IP and MAC
        if ans is not None:
            print('Received response from ' + ans.psrc + '. This host is active!\n')

            activeHost['MAC'] = ans.hwsrc
            break

        #Print status        
        print('ARP request number ' + str(i + 1) + ' did not receive a response from ' + hostIP + '.')

        if i == 4:
            print(hostIP + ' is not active.')
            return False

    return activeHost

#Fingerprints given host IPv4. In particular, tries to find:
# OS (if multiple possible matches, returns first match);
# Device type;
# Open ports out of top 10 most popular ports (according to nmap)
def fingerprintHost(hostIP):
    fingerprint = {}
    openPorts = []

    nm = nmap.PortScanner()

    print('Fingerprinting ' + hostIP + '...')
    
    nm.scan(hostIP, arguments='--top-ports 10 -O')

    #Get first os match name and device type
    if len(nm[hostIP]['osmatch']) > 0:
        fingerprint['OS'] = nm[hostIP]['osmatch'][0]['name'].split(' or', 1)[0]
        fingerprint['Type'] = nm[hostIP]['osmatch'][0]['osclass'][0]['type']
    else:
        fingerprint['OS'] = 'N/A'
        fingerprint['Type'] = 'N/A'

    #Get open ports
    for port in nm[hostIP].all_tcp():
        if nm[hostIP]['tcp'][port]['state'] == 'open':
            openPorts.append(port)
    
    fingerprint['OpenTCP'] = sorted(openPorts) 

    return fingerprint
