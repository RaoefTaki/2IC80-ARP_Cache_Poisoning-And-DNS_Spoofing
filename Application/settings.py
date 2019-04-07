#!/usr/bin/env python3

"""settings.py: File containing and initalizing global variables used accross the program."""

from threading import Lock #Import mutex

def init():
	global printMutex

	printMutex = Lock() 