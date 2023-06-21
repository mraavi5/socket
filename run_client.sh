#!/bin/bash

# Check if first argument exists, otherwise default to 127.0.0.1
if [ -n "$1" ]
then
    IP=$1
else
    IP="127.0.0.1"
fi

# Check if second argument exists, otherwise default to https://www.google.com
if [ -n "$2" ]
then
    DOMAIN=$2
else
    DOMAIN="https://www.google.com"
fi

# Print the selected IP and domain
echo "Selected IP: $IP"
echo "Selected domain: $DOMAIN"

# Run the client with the selected IP and domain
./client $IP $DOMAIN
