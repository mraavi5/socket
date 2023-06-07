#!/bin/bash

# Check if Redis is running
if ! pgrep -x "redis-server" > /dev/null
then
    echo "Starting Redis server..."
    redis-server &
fi

./database_filler Dilithium2
