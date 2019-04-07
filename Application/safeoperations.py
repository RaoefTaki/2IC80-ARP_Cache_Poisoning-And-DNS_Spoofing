#!/usr/bin/env python3

'''safeoperations.py: Thread safe operations used throughout the program.'''

#Safely prints to console, using given mutex
def sprint(lock, text):
	lock.acquire()
	print(text)
	lock.release()