g++ -g server.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o server -lpthread -lboost_system -lhiredis -lredis++ -lcrypto
g++ -g client.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o client -lpthread -lboost_system -loqs -lcrypto
g++ -g database_filler.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o database_filler -loqs -lhiredis -lredis++ -lcrypto

echo "Done!"
