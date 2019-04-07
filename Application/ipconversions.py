#!/usr/bin/env python3

"""ipconversions.py: Implementation of several IPv4 <---> Binary conversions, used in network reconnaissance part of the attack.""" 

import re

#Converts an IPv4 address into the corresponding binary string of 32 bits (i.e., no '.', only bits)
def convertIPv4ToBinary(ip):
    binaryIP = ""
    decimalIPSplit = ip.split('.') #Separated decimal numbers of IP argument
    binaryIPSplit = [] #Separated 8-bit binary numbers of IP argument
    
    #Translate decimal numbers into binary numbers
    for i in range(len(decimalIPSplit)):
        binaryIPSplit.append('{0:08b}'.format(int(decimalIPSplit[i])))

    #Return concatenated binary numbers of IP address to get complete binary IP string
    return ''.join(binaryIPSplit)

#Converts a binary string of 32 bits into (i.e., no '.', only bits) the corresponding IPv4 address 
def convertBinaryToIPv4(binaryIP):
    ip = ""
    binaryIPSplit = re.findall('........', binaryIP)
    decimalIPSplit = []

    for byte in binaryIPSplit:
        decimalIPSplit.append(str(int(byte, 2)))

    return '.'.join(decimalIPSplit)

#Computes the binary subnet prefix based on given IP and subnet mask (both in IPv4 format)
def computeBinaryIPv4SubnetPrefix(ip, subnetMask):
    subnetMaskOneCount = 0
    binaryIP = convertIPv4ToBinary(ip)
    binarySubnetMask = convertIPv4ToBinary(subnetMask) 
        
    #Uses the fact that a (binary) subnet mask is of the form: '1'...'1''0'...'0'
    for bit in binarySubnetMask:
        if bit == '1':
            subnetMaskOneCount += 1
        elif bit == '0':
            break
    
    #Return binary subnet prefix
    return binaryIP[:subnetMaskOneCount]

#Computes all possible host suffixes, assuming IPv4 format, given the length of the subnet prefix
def computeBinaryIPv4HostSuffixes(subnetPrefixLength):
    hostSuffixLength = 32 - subnetPrefixLength
    possibleSuffixes = []

    #Computes host suffixes and stores them in possibleSuffixes array
    for decimalSuffix in range(2 ** hostSuffixLength):
        binarySuffix = "{0:08b}".format(decimalSuffix)
        possibleSuffixes.append(binarySuffix)
    
    return possibleSuffixes