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

./database_filler Dilithium2
echo
echo
echo
./pubkey_send.sh