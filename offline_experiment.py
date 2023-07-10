import csv
import json
import os
import random
import re
import sys
import time

#alexaFiles = ["alexa_top_100000.csv", "alexa_top_10000.csv", "alexa_top_1000.csv", "alexa_top_100.csv", "alexa_top_10.csv", "alexa_top_1.csv"]
alexaFiles = ["alexa_top_10000.csv", "alexa_top_1000.csv", "alexa_top_100.csv", "alexa_top_10.csv", "alexa_top_1.csv"]

numSamplesPerAlgorithm = len(alexaFiles)

algorithms = ["secp224r1", "secp256k1", "secp384r1", "secp521r1", "sect571r1", "rsa1024", "rsa2048", "rsa4096", "Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024", "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple"]

resultsDirectory = 'offline_experiment_results'
if not os.path.exists(resultsDirectory):
	os.makedirs(resultsDirectory)

def terminal(cmd):
	return os.popen(cmd).read()


if __name__ == '__main__':
	os.system('clear')
	sampleNum = 0
	samplesForAlgorithm = 0
	algorithm = algorithms[0]
	prevAlgorithm = ''
	outputFile = None

	while True:
		algorithm = algorithms[int(sampleNum / numSamplesPerAlgorithm) % len(algorithms)]
		
		if algorithm != prevAlgorithm:
			if outputFile is not None:
				print(f'\tFinalized "{outputFileName}"')
				outputFile.close()
			if algorithm == algorithms[0] and sampleNum >= numSamplesPerAlgorithm:
				# Full loop completed
				break
			sanitizedAlgorithm = re.sub(r'[^a-z0-9]', '', algorithm.lower())
			outputFileName = os.path.join(resultsDirectory, f'experiment_offline_results_{sanitizedAlgorithm}.csv')
			outputFile = open(outputFileName, 'w')
			line = f'Sample Number for {algorithm},'
			line += 'Number of Domains Added,'
			line += 'Number of Fragments,'
			line += 'Total Time to Fill Database (ms),'
			line += 'Total Time for One Entry (ms),'
			line += 'Key Generation (ms),'
			line += 'Message Signing (ms),'
			line += 'Message Verifying (ms),'
			line += 'Time for Hash Step (ms),'
			line += 'Time for Redis Step (ms),'
			line += 'Public Key Length (B),'
			line += 'Private Key Length (B),'
			line += 'Avg Signature Length (B),'
			outputFile.write(line + '\n')
			prevAlgorithm = algorithm
			samplesForAlgorithm = 0
		
		alexaFileName = alexaFiles[sampleNum % len(alexaFiles)]
		print(f'Sample {samplesForAlgorithm + 1}, Using algorithm "{algorithm}", and "{alexaFileName}""...')
		result = terminal(f'./experiment_database_filler {algorithm} {alexaFileName}')
		num_fragments = ''
		num_domains_added = ''
		total_database_fill_ms = ''
		total_entry_ms = ''
		keygen_ms = ''
		sign_step = ''
		verify_step = ''
		hash_step = ''
		redis_step = ''
		public_key_length = ''
		secret_key_length = ''
		avg_signature_length = ''
		try:
			obj = json.loads(result)
			num_fragments = obj['num_fragments']
			num_domains_added = obj['num_domains_added']
			total_database_fill_ms = obj['total_database_fill_ms']
			total_entry_ms = obj['total_entry_ms']
			keygen_ms = obj['keygen_ms']
			sign_step = obj['sign_step']
			verify_step = obj['verify_step']
			hash_step = obj['hash_step']
			redis_step = obj['redis_step']
			public_key_length = obj['public_key_length']
			secret_key_length = obj['secret_key_length']
			avg_signature_length = obj['avg_signature_length']
		except:
			 print('\tERROR: Failed to log sample')
			 
		sampleNum += 1
		samplesForAlgorithm += 1
		line = str(samplesForAlgorithm) + ','
		line += str(num_domains_added) + ','
		line += str(num_fragments) + ','
		line += str(total_database_fill_ms) + ','
		line += str(total_entry_ms) + ','
		line += str(keygen_ms) + ','
		line += str(sign_step) + ','
		line += str(verify_step) + ','
		line += str(hash_step) + ','
		line += str(redis_step) + ','
		line += str(public_key_length) + ','
		line += str(secret_key_length) + ','
		line += str(avg_signature_length) + ','
		outputFile.write(line + '\n')

	print('Experiment complete, goodbye.')
