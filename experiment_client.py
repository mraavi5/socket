import csv
import json
import os
import random
import re
import sys
import time
import signal


numSamplesPerAlgorithm = 100


if os.geteuid() != 0:
	exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

algorithms = ["secp224r1", "secp256k1", "secp384r1", "secp521r1", "sect571r1", "rsa1024", "rsa2048", "rsa4096", "Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024", "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple"]

resultsDirectory = 'online_experiment_results'
if not os.path.exists(resultsDirectory):
	os.makedirs(resultsDirectory)

def terminal(cmd):
	return os.popen(cmd).read()

def startTcpdump(algorithm):
	sanitizedAlgorithm = re.sub(r'[^a-z0-9]', '', algorithm.lower())
	pcapName = os.path.join(resultsDirectory, f'experiment_online_results_{sanitizedAlgorithm}.pcap')
	cmd = f'nohup sudo tcpdump -i any -w {pcapName} port 5300 >/dev/null 2>&1 &'
	return terminal(cmd)

def isTcpdumpRunning():
	cmd = 'ps -A | grep tcpdump'
	return not terminal(cmd).strip() == ''

def stopTcpdump():
	attempts = 0
	while isTcpdumpRunning() and attempts < 10:
		terminal('sudo pkill tcpdump')
		time.sleep(1)
		attempts += 1
	if not isTcpdumpRunning():
		return
	cmd_forceful = 'sudo pkill -SIGTERM tcpdump'
	while isTcpdumpRunning():
		terminal(cmd_forceful)
		time.sleep(1)


if __name__ == '__main__':
	os.system('clear')
	if len(sys.argv) > 1:
		ip = sys.argv[1]
	else:
		ip = '127.0.0.1'

	sampleNum = 0
	samplesForAlgorithm = 0
	algorithm = algorithms[0]
	prevAlgorithm = ''
	outputFile = None

	# Keep a list of all the domains so that we can select them randomly
	domains = []
	file = open('alexa_top_1000.csv', 'r')
	reader = csv.reader(file)
	header = next(reader)
	for row in reader:
		 domains.append(row[0])

	while True:
		if samplesForAlgorithm >= numSamplesPerAlgorithm:
			time.sleep(1)
			stopTcpdump()
			if outputFile is not None:
				print(f'\tFinalized "{outputFileName}/.pcap"')
				outputFile.close()

			algorithm = terminal('./is_server_up')
			while algorithm == 'OFFLINE':
				algorithm = terminal('./is_server_up')
		if algorithm != prevAlgorithm:
			if algorithm == algorithms[0] and sampleNum >= numSamplesPerAlgorithm:
				# Full loop completed
				break
			terminal('./download_alg_and_pubkey')
			print(f'Using algorithm "{algorithm}"...')
			sanitizedAlgorithm = re.sub(r'[^a-z0-9]', '', algorithm.lower())
			outputFileName = os.path.join(resultsDirectory, f'experiment_online_results_{sanitizedAlgorithm}.csv')
			outputFile = open(outputFileName, 'w')
			line = f'Sample Number for {algorithm},'
			line += 'Total Handshake Duration (ms),'
			line += 'Hash Check Duration (ms),'
			line += 'Data Check Duration (ms),'
			line += 'Signature Check Duration (ms),'
			outputFile.write(line + '\n')
			prevAlgorithm = algorithm
			samplesForAlgorithm = 0
			startTcpdump(algorithm)
			time.sleep(2)
		
		domain = random.choice(domains)
		
		result = terminal(f'./experiment_client {ip} {domain}')
		total_ms = ''
		hash_check_ms = ''
		data_check_ms = ''
		signature_check_ms = ''
		try:
			obj = json.loads(result)
			total_ms = obj['total_ms']
			hash_check_ms = obj['hash_check_ms']
			data_check_ms = obj['data_check_ms']
			signature_check_ms = obj['signature_check_ms']
		except:
			 print('\tERROR: Failed to log sample')
			 
		sampleNum += 1
		samplesForAlgorithm += 1
		line = str(samplesForAlgorithm) + ','
		line += str(total_ms) + ','
		line += str(hash_check_ms) + ','
		line += str(data_check_ms) + ','
		line += str(signature_check_ms) + ','
		outputFile.write(line + '\n')
		time.sleep(0.1)

	print(f'Finalized "{outputFileName}"')
	outputFile.close()
	print('Experiment complete, goodbye.')
