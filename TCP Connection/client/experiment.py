#!/usr/bin/python3

import datetime
import os
import time
import sys
import random
import string
import errno

if os.geteuid() != 0:
	sys.exit('You need root permissions to run this script.')

experimentName = input('Enter an experiment name, recommended format: "DD-MM-YY-something": ')

numSamples = 1000
numEntriesList = [1, 10, 100, 1000]

# Send commands to the Linux terminal
def terminal(cmd):
	return os.popen(cmd).read()

def startTcpDump(directory, experimentName, sampleNum, numEntries):
	terminal(f'sudo gnome-terminal -t "TCPDUMP LOGGER" -- /bin/sh -c \'tcpdump -w {directory}/tcpdump_sample_{experimentName}_{sampleNum}_{numEntries}.pcap "port 2060"\'')
	time.sleep(1)

def stopTcpDump():
	terminal('sudo pkill -SIGTERM tcpdump')
	time.sleep(1)
	while terminal('ps -A | grep tcpdump').strip() != '':
		print('Waiting for tcpdump to terminate...')
		time.sleep(1)
		terminal('sudo pkill -SIGTERM tcpdump')

def runExperiment(directory, experimentName, sampleNum, numEntries):
	startTcpDump(directory, experimentName, sampleNum, numEntries)
	output = terminal(f'./run.sh {numEntries}')
	stopTcpDump()
	time.sleep(0.5)

	while 'ERROR:' in output:
		print('\tAn error was detected, retrying...')
		startTcpDump(directory, experimentName, sampleNum, numEntries)
		output = terminal(f'./run.sh {numEntries}')
		stopTcpDump()
		time.sleep(0.5)

directory = f'PCAPS_{experimentName}'
print('Experiment directory:', directory)
if not os.path.exists(directory):
	os.mkdir(directory)

for sampleNum in range(numSamples):
	for numEntries in numEntriesList:
		filePath = f'{directory}/tcpdump_sample_{experimentName}_{sampleNum}_{numEntries}.pcap'
		if os.path.exists(filePath):
			print(f'Skipping sample {sampleNum} entries {numEntries}.')
			continue
		else:
			print(f'Running sample {sampleNum} entries {numEntries}...')
			runExperiment(directory, experimentName, sampleNum, numEntries)
