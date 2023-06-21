#!/bin/bash

# Check if the IP argument exists
if [ -z "$1" ]
then
    echo "Please provide the server's IP address as an argument."
    exit 1
fi

# Set the server's IP address and filename
IP=$1
FILENAME="pubkey.key"

# Connect to the server and save the received file
nc $IP 5300 > $FILENAME

echo "Received file $FILENAME from $IP"
