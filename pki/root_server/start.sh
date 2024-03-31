#!/bin/bash

# Command 1
echo "Running command 1"
marblerun manifest verify manifest.json localhost:4433 --coordinator-cert marblerunCA.crt

# Command 2
echo "Running command 2"

./root_server
# Command 3
echo "Running command 3"
