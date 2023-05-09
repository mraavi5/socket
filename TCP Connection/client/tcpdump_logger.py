#!/usr/bin/python3

import datetime
import os
import time
import sys
import random
import string

# Send commands to the Linux terminal
def terminal(cmd):
	return os.popen(cmd).read()

if len(sys.argv) >= 1:
	sampleTag = sys.argv[1]
else:
	print('Please provide the sample tag')
	sys.exit()

print('Starting PCAP Logger...')
terminal(f'sudo tcpdump -w PCAPs/tcpdump_sample_{sampleTag}.pcap \'port 2060\'')