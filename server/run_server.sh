if [ ! -f redis_researcher/src/redis-server ]; then
	echo "Redis binary not found, compiling..."
	cd redis_researcher
	./compile.sh
	cd ..
fi

if ! ps -A | grep -q 'redis-server'; then
	echo "Redis is not running, starting..."
	cd redis_researcher
	./run.sh
	cd ..
fi

rm -rf DNS_UDP_Server
g++ -std=c++11 DNS_UDP_Server.cpp -o DNS_UDP_Server -lpthread -lssl -lcrypto


# DNS_UDP_Server loss_probability protocol_type
while true; do ./DNS_UDP_Server 0 2; done