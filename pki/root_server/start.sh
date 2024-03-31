#!/bin/bash

marblerun manifest set manifest.json localhost:4433

marblerun manifest verify manifest.json localhost:4433 --coordinator-cert marblerunCA.crt

./root_server

