import os
import sys
import time

numSamplesPerAlgorithm = 100

algorithms = ["secp224r1", "secp256k1", "secp384r1", "secp521r1", "sect571r1", "rsa1024", "rsa2048", "rsa4096", "Dilithium2", "Dilithium3", "Dilithium5", "Falcon-512", "Falcon-1024", "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple", "SPHINCS+-SHA2-192f-simple", "SPHINCS+-SHA2-192s-simple", "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple", "SPHINCS+-SHAKE-128f-simple", "SPHINCS+-SHAKE-128s-simple", "SPHINCS+-SHAKE-192f-simple", "SPHINCS+-SHAKE-192s-simple", "SPHINCS+-SHAKE-256f-simple", "SPHINCS+-SHAKE-256s-simple"]

def terminal(cmd):
	return os.popen(cmd).read()

if __name__ == '__main__':
	os.system('clear')
	prevAlgorithm = ''
	sampleNum = 0
	while True:
		try:
			algorithm = algorithms[int(sampleNum / numSamplesPerAlgorithm) % len(algorithms)]
			if prevAlgorithm != algorithm:
				if algorithm == algorithms[0] and sampleNum > numSamplesPerAlgorithm:
					# Full loop completed
					break
				print(f'Sample {sampleNum + 1}: {algorithm}, filling database, please wait...')
				terminal('./database_filler ' + algorithm)
				prevAlgorithm = algorithm
				print(f'\tReady, listening...')
			else:
				print(f'Sample {sampleNum + 1}: {algorithm}')

			if terminal('ps -A | grep redis-server').strip() == '':
				print('\tStarting redis-server...')
				terminal('redis-server &')

			terminal('./experiment_server')
			sampleNum += 1
		except KeyboardInterrupt:
			print('Goodbye!')
			sys.exit()