#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Invalid number of parameters, $0 ServerIP DomainName"
	exit 1
fi

rm -rf DNS_UDP_Client
g++ -std=c++11 DNS_UDP_Client.cpp -o DNS_UDP_Client -lpthread

rm -rf file.pdf

# DNS_UDP_Client ServerIP DomainName ProtocolType
./DNS_UDP_Client $1 $2 1