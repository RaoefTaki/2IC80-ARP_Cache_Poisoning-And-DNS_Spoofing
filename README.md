# ARP Cache Poisoning And DNS Spoofing
This tool is an implementation of the ARP Cache Poisoning and DNS Spoofing attack. Here, the DNS Spoofing attack runs on top of the ARP Cache Poisoning. The user can choose between only ARP Cache Poisoning, or both ARP Cache Poisoning and DNS Spoofing. The tool provides a CLI (Command Line Interface) for the user to specify the paramters of the attack.

This tool was made by team Schoolbook_RSA for the course 2IC80 Lab on Offensive Computer Security, given at the TU/e.

## Prerequisites
*Disclaimer: This tool is designed to run on Linux 18.3 Mint Sylvia. There is no guarantee it will run on any other operating system (or Linux distribution).*

The tool requires the following installations:
* [Python 3.4+](https://www.python.org/downloads/);
* [Scapy 2.4.2](https://scapy.readthedocs.io/en/latest/installation.html#current-development-version);
* [netifaces](https://github.com/al45tair/netifaces#2-how-do-i-use-it);
* [python-nmap](https://bitbucket.org/xael/python-nmap).

## Running The Application
In order to run the application, do the following (using [git](http://ask.xmodulo.com/install-git-linux.html)):
* Open up a terminal;
* Enter `git clone https://github.com/RaoefTaki/2IC80-ARP_Cache_Poisoning-And-DNS_Spoofing`;
* Afterwards, enter `cd 2IC80-ARP_Cache_Poisoning-And-DNS_Spoofing/Application`;
* Finally, enter `sudo python3 Schoolbook_RSA.py`.

Alternatively (not using git):
* Use the GitHub web interface to clone/download this repository;
* Open up a terminal at the location of the repository;
* Navigate to the *Application* folder (e.g., by `cd Application`);
* Finally, enter `sudo python3 Schoolbook_RSA.py`.

## Authors
Team Schoolbook_RSA:
* M.C.F.H.P. Meijers;
* R. Taki.
