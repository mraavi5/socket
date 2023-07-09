echo "Compiling main files..."
g++ -g server.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o server -lpthread -lboost_system -lhiredis -lredis++ -lcrypto
g++ -g client.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o client -lpthread -lboost_system -loqs -lcrypto
g++ -g database_filler.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o database_filler -loqs -lhiredis -lredis++ -lcrypto

echo "Compiling helper files..."
g++ -g is_server_up.cpp -std=c++17 -o is_server_up -lboost_system -lpthread
g++ -g download_alg_and_pubkey.cpp -std=c++17 -o download_alg_and_pubkey -lboost_system

echo "Compiling experiment files..."
g++ -g experiment_server.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o experiment_server -lpthread -lboost_system -lhiredis -lredis++ -lcrypto
g++ -g experiment_client.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o experiment_client -lpthread -lboost_system -loqs -lcrypto
g++ -g experiment_database_filler.cpp -std=c++17 -I redisclient/src -L/usr/local/lib -o experiment_database_filler -loqs -lhiredis -lredis++ -lcrypto

echo "Done!"