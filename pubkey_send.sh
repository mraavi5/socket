#!/bin/bash

# Set filename
FILENAME="pubkey.key"
ip=$(curl ifconfig.me)

echo
echo
echo "Listening for a pubkey receiver..."
echo "   Type \"./pubkey_receive.sh $ip\" on the client end."
echo "   To re-run the pubkey sender, type \"./pubkey_send.sh\""
# Start listening and send the file to the first client that connects,
# then stop listening
nc -l 5300 < $FILENAME

echo "Sent file $FILENAME"
