#!/bin/bash

ipAddress=$2
fileName=$2
if [ $# -ne 2 ]; then
  echo "Usage: $0 IP_ADDRESS FILE_NAME"
  exit 1
fi

rm -rf $fileName
./TCP_Client $ipAddress $fileName
