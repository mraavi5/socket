g++ is_server_up.cpp -std=c++17 -o is_server_up -lboost_system -lpthread
g++ server.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o server -lpthread -lboost_system -lhiredis -lredis++ -lcrypto
g++ client.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o client -lpthread -lboost_system -loqs -lcrypto
g++ database_filler.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o database_filler -loqs -lhiredis -lredis++ -lcrypto

echo "Done!"