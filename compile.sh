g++ server.cpp -I redisclient/src -L/usr/local/lib -o server -lpthread -lboost_system -lhiredis -lredis++ -lcrypto
g++ client.cpp -I redisclient/src -L/usr/local/lib -o client -lpthread -lboost_system -loqs -lcrypto
g++ database_filler.cpp -I redisclient/src -L/usr/local/lib -o database_filler -loqs -lhiredis -lredis++ -lcrypto

echo "Done!"