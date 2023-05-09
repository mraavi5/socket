import csv
import datetime
import os
import platform
import pyshark
import re
import sys
import time

assert platform.system() == 'Linux', 'Sorry, but this script can only run in a debian-based linux machine (e.g. Ubuntu or Linux Mint).'

def terminal(cmd):
	return os.popen(cmd).read()

# Given a regular expression, list the files that match it, and ask for user input
def selectFile(regex, subdirs = False):
	files = []
	if subdirs:
		for (dirpath, dirnames, filenames) in os.walk('.'):
			for file in filenames:
				path = os.path.join(dirpath, file)
				if path[:2] == '.\\': path = path[2:]
				if bool(re.match(regex, path)):
					files.append(path)
	else:
		for file in os.listdir(os.curdir):
			if os.path.isfile(file) and bool(re.match(regex, file)):
				files.append(file)
	
	print()
	if len(files) == 0:
		print(f'No files were found that match "{regex}"')
		print()
		return ''

	print('List of files:')
	for i, file in enumerate(files):
		print(f'  File {i + 1}  -  {file}')
	print()

	selection = None
	while selection is None:
		try:
			i = int(input(f'Please select a file (1 to {len(files)}): '))
		except KeyboardInterrupt:
			sys.exit()
		except:
			pass
		if i > 0 and i <= len(files):
			selection = files[i - 1]
	print()
	return selection

# Given a regular expression, list the directories that match it, and ask for user input
def selectDir(regex, subdirs = False):
	dirs = []
	if subdirs:
		for (dirpath, dirnames, filenames) in os.walk('.'):
			if dirpath[:2] == '.\\': dirpath = dirpath[2:]
			if bool(re.match(regex, dirpath)):
				dirs.append(dirpath)
	else:
		for obj in os.listdir(os.curdir):
			if os.path.isdir(obj) and bool(re.match(regex, obj)):
				dirs.append(obj)

	print()
	if len(dirs) == 0:
		print(f'No directories were found that match "{regex}"')
		print()
		return ''

	print('List of directories:')
	for i, directory in enumerate(dirs):
		print(f'  Directory {i + 1}  -  {directory}')
	print()

	selection = None
	while selection is None:
		try:
			i = int(input(f'Please select a directory (1 to {len(dirs)}): '))
		except KeyboardInterrupt:
			sys.exit()
		except:
			pass
		if i > 0 and i <= len(dirs):
			selection = dirs[i - 1]
	print()
	return selection

# List the files with a regular expression
def listFiles(regex, directory = ''):
	path = os.path.join(os.curdir, directory)
	return [os.path.join(path, file) for file in os.listdir(path) if os.path.isfile(os.path.join(path, file)) and bool(re.match(regex, file))]

def header():
	line = 'File path,'
	line += 'Number of entries,'
	line += 'Start time,'
	line += 'End time,'
	line += 'Duration (ms),'
	line += 'Number of packets,'
	line += 'Transmission size (B),'
	return line


def log(directory, filePath):
	startTime = None
	endTime = None
	totalPackets = 0
	totalSize = 0

	fileName = filePath
	startString = f'./{directory}/'
	if fileName.startswith(startString): fileName = fileName[len(startString):]
	match = re.search(r'.*_([0-9]+)\.pcap', fileName)
	if match is not None:
		numEntries = int(match.group(1))
	else:
		numEntries = ''

	pcap = pyshark.FileCapture(filePath)
	packetNum = 0
	running = True
	timestamp = ''
	timestamp_seconds = ''
	packetSizeBytes = 0
	while running:
		try:
			packet = pcap[packetNum]
			timestamp = packet.sniff_time
			timestamp_seconds = (timestamp - datetime.datetime(1970, 1, 1)).total_seconds()
			packetSizeBytes = packet.length
			totalPackets += 1
			if startTime is None:
				startTime = timestamp_seconds
		except (StopIteration, KeyError): # End of file
		 	running = False
		 	break
		packetNum += 1
		totalSize += int(packetSizeBytes)

	endTime = timestamp_seconds
	pcap.close()

	line = str(filePath) + ','
	line += str(numEntries) + ','
	line += str(startTime) + ','
	line += str(endTime) + ','
	if startTime is not None and endTime is not None:
		line += str((endTime - startTime) * 1000) + ','
	else:
		line += ','
	line += str(packetNum) + ','
	line += str(totalSize) + ','
	outputFile.write(line + '\n')


directory = selectDir(f'^PCAPS', False)
outputFilePath = f'{directory}_processed_TCP_pcaps.csv'
outputFile = open(outputFilePath, 'w')
outputFile.write(header() + '\n')

files = listFiles('.*', directory)
for filePath in files:
	print('Processing', filePath)
	log(directory, filePath)

outputFile.close()
print(f'Successfully wrote to {outputFilePath}. Have a nice day.')