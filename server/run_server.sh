rm -rf DNS_UDP_Server
g++ -std=c++11 DNS_UDP_Server.cpp -o DNS_UDP_Server -lpthread

# DNS_UDP_Server loss_probability protocol_type
while true; do ./DNS_UDP_Server 0 2; done