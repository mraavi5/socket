#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <sys/socket.h>
#include <sys/types.h>
#include <thread>
#include <unistd.h>
using namespace std;

#define PORT 5300
#define MAX_FRAME_LENGTH 1232   // Size in bytes per frame
#define DOMAIN_NAME_SIZE 256	// Domain names greater than this are not allowed
#define FRAME_TIMEOUT 100	   // Milliseconds to wait until re-sending frame
#define WINDOW_SIZE 12		  // Number of frames in the window

int sock; // Socket descriptor
struct sockaddr_in server, client;
socklen_t clientLength;

// Window of received acks
bool *windowReceivedLog;
// Keep the window safe from race conditions when multithreading
mutex windowModificationMutex;
int maxBufferSize, lastAckedFrame, lastFrameSent;
// Track the timestamps for frames and acks
chrono::high_resolution_clock::time_point startTime, *windowSentTimeLog;

// Upon fatal error, gracefully terminate with a message
void fatal(string str) {
	cout << "ERROR: " << str << endl;
	exit(1);
}

// Given a shell command, execute it, and return the response
string terminal(const string& cmd) {
	array<char, 128> buffer;
	string result;
	unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd.c_str(), "r"), pclose);
	if (!pipe) {
		throw runtime_error("popen() failed!");
	}
	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
		result += buffer.data();
	}
	return result;
}

// Remove whitespace from the beginning and end of a string
string trim(const string& str) {
	const string whitespace = " \t\n\r\f\v";
	size_t first = str.find_first_not_of(whitespace);
	if (string::npos == first) {
		return str;
	}
	size_t last = str.find_last_not_of(whitespace);
	return str.substr(first, (last - first + 1));
}

// Given a long url, extract just the domain e.g. www.example.com
string extractDomain(const string& url) {
	regex pattern(R"((http|https)://([A-Za-z0-9.-]*))");
	smatch matches;
	if (regex_search(url, matches, pattern) && matches.size() > 2) {
		return matches.str(2);
	} else {
		return string();
	}
}

// lossProbability = 0% then no frames are dropped
// lossProbability = 100% then all frames are dropped
bool isFrameDropped(int lossProbability) {
	int r = 1 + rand() % 100; // 1 to 100
	return r <= lossProbability;
}

// Listen for acks (needs to be multithreaded with mutex locks over the AckLogs)
void asyncListenForAcksThenRespond();
// Encode an Ack into two bytes
void serializeAck(int seqNum, char *ack, bool error);
// Encode the data for packing into a frame
int serializeFrame(bool endOfTransmission, int seqNum, char *frame, char *data, int dataSize);
// Decode an Ack from two bytes
bool deserializeAck(int *seqNum, bool *error, char *ack);

// Return the SHA-256 hash of a string
string sha256(const string str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Given an array, compute the 4-byte CRC checksum
char computeCrcChecksum(char *buf, int len) {
	int crc = 0xFFFF;
	for (int i = 0; i < len; i++) {
		crc ^= (int) buf[i] & 0xFF;	 // XOR byte into least sig. byte of crc
		for (int i = 8; i != 0; i--) {  // Loop over each bit
			if ((crc & 0x0001) != 0) {  // If the LSB is set
				crc >>= 1;			  // Shift right and XOR 0xA001
				crc ^= 0xA001;
			} else {					// Else LSB is not set
				crc >>= 1;			  // Just shift right
			}
		}
	}
	// Note, this number has low and high bytes swapped, so use it accordingly (or swap bytes)
	return crc & 0xFFFFFFFF;
}

// Listen for a file name, then send an ACK back: 'K'
void receiveDomainName(char (&domainName)[DOMAIN_NAME_SIZE]) {
	// Receive the file's name
	char domainNameRaw[DOMAIN_NAME_SIZE];
	int domainNameLen = 0;
	while(domainNameLen <= 0) {
		domainNameLen = recvfrom(sock, (char*) domainNameRaw, DOMAIN_NAME_SIZE, MSG_WAITALL, (struct sockaddr *) &client, &clientLength);
	}
	cout << "Copying first " << domainNameLen << " bytes of \"" << domainNameRaw << "\" into the file name array..." << endl;
	strncpy(domainName, domainNameRaw, domainNameLen);
	domainName[domainNameLen] = '\0';
	char ack[1] = {'K'};
	sendto(sock, ack, 2, 0, (const struct sockaddr *) &client, clientLength);
}

void sendDomainNotFound() {
	char ack[1] = {'N'};
	sendto(sock, ack, 2, 0, (const struct sockaddr *) &client, clientLength);
}

// Server-side needs: UDP_Server lossProbability protocolType
// protocolType = 1 for lossProbability (1 to 100)
// protocolType = 2 for protocolType (1 for ARQ stop-and-wait, 2 for ARQ selective repeat)
int main(int argc, char *argv[]) {
	int numFramesTotal = 0;
	int numFramesDropped = 0;

	if (argc != 3) fatal("Usage: \"UDP_Server lossProbability protocolType\"");

	int lossProbability = stoi(argv[1]);
	int protocolType = stoi(argv[2]);


	if(protocolType == 1) {
		cout << endl;
		cout << endl;
		cout << "==================================================" << endl;
		cout << "=====			ARQ STOP-AND-WAIT		   =====" << endl;
		cout << "==================================================" << endl;
		cout << endl;
	} else if(protocolType == 2) {
		cout << endl;
		cout << endl;
		cout << "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" << endl;
		cout << "@@@@@		  ARQ SELECTIVE REPEAT		  @@@@@" << endl;
		cout << "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" << endl;
		cout << endl;
	}


	maxBufferSize = MAX_FRAME_LENGTH * WINDOW_SIZE;

	cout << "Creating socket..." << endl;
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		fatal("Can't create a socket");
	}

	// Zero out the server
	memset(&server, 0, sizeof(server));
	memset(&client, 0, sizeof(client));
	//bzero((char*)&server, sizeof(server));

	server.sin_family = AF_INET;
	server.sin_port = htons(PORT);
	server.sin_addr.s_addr = htonl(INADDR_ANY);

	cout << "Binding name to socket..." << endl;
	if (bind(sock, (struct sockaddr *) &server, sizeof(server)) == -1) {
		fatal("Can't bind name to socket");
	}
	// Connection established








	/*
	 *  ARQ Stop-and-Wait
	 */
	if(protocolType == 1) {

		while (true) {
			// Clear the client to allow new requests
			memset(&client, 0, sizeof(client));
			clientLength = sizeof(client);
			cout << "\nListening..." << endl;

			char domainName[DOMAIN_NAME_SIZE];
			receiveDomainName(domainName);
			cout << "Received domain name for reading: \"" << domainName << "\"" << endl;

			string query = extractDomain(domainName);
			string response = trim(terminal("./redis_researcher/run_read.sh " + query));

			if (response.length() == 0) {
				cout << "Error 404, domain not found" << endl;
				sendDomainNotFound();
				continue; // Don't terminate the server
			}

            // Force recvfrom to terminate after FRAME_TIMEOUT milliseconds
            struct timeval readTimeout;
            readTimeout.tv_sec = 0;
            readTimeout.tv_usec = FRAME_TIMEOUT * 1000; // Milliseconds to microseconds
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&readTimeout, sizeof readTimeout);

            char frame[MAX_FRAME_LENGTH + 10]; // 10 for the checksum
            char ack[2];
            int seqNum = 0, receivedSeqNum, totalBytes = 0;
            char data[MAX_FRAME_LENGTH];
            bool ackNeg;

            // Send data
            bool isSending = true;
            int responseIndex = 0;
            while (isSending) {
                int bytesToRead = std::min(MAX_FRAME_LENGTH, (int)(response.size() - responseIndex));
                strncpy(data, response.c_str() + responseIndex, bytesToRead);

                if (bytesToRead < MAX_FRAME_LENGTH) {
                    isSending = false;
                }
                totalBytes += bytesToRead;
                responseIndex += bytesToRead;

                int frameSize = serializeFrame(!isSending, seqNum, frame, data, bytesToRead);
                
                bool isAwaitingResponse = true;
                while(isAwaitingResponse) {

                    // Handle frame dropping in a lossy network
                    if(!isFrameDropped(lossProbability)) {
                        cout << "Sending frame #" << seqNum << " from bytes [" << (totalBytes - bytesToRead) << " to " << (totalBytes - 1) << "]" << endl;
                        sendto(sock, frame, frameSize, 0, (const struct sockaddr *) &client, clientLength);   //sizeof(client));
                    } else {
                        cout << "Dropping frame #" << seqNum << " from bytes [" << (totalBytes - bytesToRead) << " to " << (totalBytes - 1) << "]" << endl;
                        numFramesDropped++;
                    }
                    numFramesTotal++;

                    int ackSize = recvfrom(sock, (char*) ack, 2, MSG_WAITALL, (struct sockaddr *) &client, &clientLength);
                    bool ackError = true;
                    if(ackSize > 0) {
                        ackError = !deserializeAck(&receivedSeqNum, &ackNeg, ack);
                    }
                    if(!ackError && !ackNeg) {
                        // Success!
                        isAwaitingResponse = false;
                    }
                }

                seqNum++;
            }
            cout << totalBytes << " bytes sent" << endl;
            cout << "Transmission complete." << endl;

			
		}












	/*
	 *  ARQ Selective Repeat
	 */
	} else if(protocolType == 2) {

		startTime = chrono::high_resolution_clock::now();
		while (true) {
			// Clear the client to allow new requests
			memset(&client, 0, sizeof(client));
			clientLength = sizeof(client);
			cout << "\nListening..." << endl;

            char domainName[DOMAIN_NAME_SIZE];
            receiveDomainName(domainName);
            cout << "Received domain name for reading: \"" << domainName << "\"" << endl;

            string query = extractDomain(domainName);
            string response = trim(terminal("./redis_researcher/run_read.sh " + query));

            if (response.length() == 0) {
                cout << "Error 404, domain not found" << endl;
                sendDomainNotFound();
                continue; // Don't terminate the server
            }

            const char* buffer = response.c_str();
            size_t bufferSize = response.size();

            // Start thread to listen for ack
            std::thread ackReceiver(asyncListenForAcksThenRespond);

            char frame[MAX_FRAME_LENGTH + 10];  // 10 for the checksum
            char data[MAX_FRAME_LENGTH];
            int frameSize;
            int dataSize;

            // Send file
            bool isSending = true;
            int bufferNum = 0;
            while (isSending) {

                // Read part of response to buffer
                if (bufferSize < maxBufferSize) {
                    isSending = false;
                } else if (bufferSize == maxBufferSize) {
                    // Check if it's the end of the string
                    if (bufferSize == response.size()) {
                        isSending = false;
                    }
                }
                windowModificationMutex.lock();

                // Initialize sliding window variables
                int seqCount = bufferSize / MAX_FRAME_LENGTH + ((bufferSize % MAX_FRAME_LENGTH == 0) ? 0 : 1);
                int seqNum;
                windowSentTimeLog = new chrono::high_resolution_clock::time_point[WINDOW_SIZE];
                windowReceivedLog = new bool[WINDOW_SIZE];
                bool windowSentLog[WINDOW_SIZE];
                for (int i = 0; i < WINDOW_SIZE; i++) {
                    windowReceivedLog[i] = false;
                    windowSentLog[i] = false;
                }
                lastAckedFrame = -1;
                lastFrameSent = lastAckedFrame + WINDOW_SIZE;
                windowModificationMutex.unlock();

                // Send current buffer with sliding window
                bool isSendDone = false;
                while (!isSendDone) {
                    // The rest of the code is unchanged...
                }
                bufferNum += 1;
                if (!isSending) break;
            }

            // cout << bufferNum *maxBufferSize + bufferSize << " bytes successfully sent." << endl;
            cout << "\nTransmission complete: Sent \"" << domainName << "\"" << endl;
            cout << numFramesDropped << " / " << numFramesTotal << " frames were dropped." << endl;

            delete[] windowReceivedLog;
            delete[] windowSentTimeLog;
            ackReceiver.detach();

		}
	}

	cout << "Goodbye." << endl;
	return 0;
}

// Encode an Ack into two bytes
void serializeAck(int seqNum, char *ack, bool error) {
	ack[0] = error ? 0 : 1; // Negated ACK (NACK)
	memcpy(ack + 1, &seqNum, 1);
}

// Encode the data for packing into a frame
int serializeFrame(bool endOfTransmission, int seqNum, char *frame, char *data, int dataSize) {
	frame[0] = endOfTransmission ? 0 : 1;
	uint32_t _seqNum = htonl(seqNum);
	uint32_t _dataSize = htonl(dataSize);
	memcpy(frame + 1, &_seqNum, 4);
	memcpy(frame + 5, &_dataSize, 4);
	memcpy(frame + 9, data, dataSize);
	frame[dataSize + 9] = computeCrcChecksum(frame, dataSize + (int) 9);
	//cout << "EOT: " << endOfTransmission << " Data: " << data << " Data Size: " << dataSize << endl;
	return dataSize + (int) 10;
}

// Decode an Ack from two bytes
// Returns true if valid, false if invalid
bool deserializeAck(int *seqNum, bool *error, char *ack) {
	*error = ack[0] == 0;
	char _seqNum;
	memcpy(&_seqNum, ack + 1, 1);
	*seqNum = _seqNum;
	//cout << "ACK: " << (int)ack[0] << (int)ack[1] << endl;
	return true;
}

// Listen for acks (needs to be multithreaded with mutex locks over the AckLogs)
void asyncListenForAcksThenRespond() {
	char ack[2];
	bool ackError;
	bool ackNeg;
	int ackSeqNum;
	int ackSize;

	// Listen for ack from reciever
	while (true) {
		ackSize = recvfrom(sock, (char*) ack, 2, MSG_WAITALL, (struct sockaddr *) &client, &clientLength);
		ackError = !deserializeAck(&ackSeqNum, &ackNeg, ack);

		windowModificationMutex.lock();
		if (!ackError && ackSeqNum > lastAckedFrame && ackSeqNum <= lastFrameSent) {
			if (!ackNeg) {
				cout << "Received ACK for Frame #" << ackSeqNum << endl;
				windowReceivedLog[ackSeqNum - (lastAckedFrame + 1)] = true;
			} else {
				cout << "Received NACK for Frame #" << ackSeqNum << endl;
				windowSentTimeLog[ackSeqNum - (lastAckedFrame + 1)] = startTime;
			}
		}
		windowModificationMutex.unlock();
	}
}