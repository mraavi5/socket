#!/bin/bash

echo
echo "If you get this error:"
echo "  ./database_filler: error while loading shared libraries: libredis++.so.1: cannot open shared object file: No such file or directory"
echo "Solution, paste this:"
echo "  export LD_LIBRARY_PATH=\$LD_LIBRARY_PATH:/usr/local/lib"
echo
echo "Starting application..."
echo

# Check if Redis is running
if ! pgrep -x "redis-server" > /dev/null
then
    echo "Starting Redis server..."
    redis-server &
fi

# "secp224r1", "secp256k1", "secp384r1", "secp521r1", "sect571r1",
# "rsa1024", "rsa2048", "rsa4096", "Dilithium2", "Dilithium3", "Dilithium5",
# "Falcon-512", "Falcon-1024", 
# "SPHINCS+-SHA2-128f-simple", "SPHINCS+-SHA2-128s-simple",
# "SPHINCS+-SHA2-256f-simple", "SPHINCS+-SHA2-256s-simple"


./database_filler SPHINCS+-SHA2-256s-simple

echo
echo
echo
./pubkey_send.sh