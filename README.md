# Java HTTPS Client example

## Prep

Generate CA certificate and private key:

```
./make-ca-cert.sh
```

## Test server

Need root to use port 443:

```
sudo python test-server.py
```

## Java client

Create connection to the server:

```
gradle run
```
