#!/bin/bash

ip=$(curl ifconfig.me)
clear
echo
echo "Your public IP is \"$ip\""
echo

# Check if Redis is running
if ! pgrep -x "redis-server" > /dev/null
then
    echo "Starting Redis server..."
    redis-server &
fi

./server