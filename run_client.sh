rm -rf DNS_UDP_Client
g++ -std=c++11 DNS_UDP_Client.cpp -o DNS_UDP_Client -lpthread

rm -rf file.pdf

# DNS_UDP_Client serverHostname fileName protocolType
./DNS_UDP_Client 10.0.2.5 file.pdf 2