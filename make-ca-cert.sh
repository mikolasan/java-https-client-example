#!/bin/bash

PUBLIC_CA_CERT=src/main/resources/ca.crt
PRIVATE_CA_CERT=server.pem

# read 'nodes' as 'no DES'
openssl req -new -x509 \
    -nodes -days 1825 \
    -keyout $PRIVATE_CA_CERT -out $PUBLIC_CA_CERT \
    -newkey rsa:4096 -sha256 \
    -subj "/C=US/ST=Nevada/L=Las Vegas/O=mikolasan/CN=localhost" 

cat $PUBLIC_CA_CERT >> $PRIVATE_CA_CERT
