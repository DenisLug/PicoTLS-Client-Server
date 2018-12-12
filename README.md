# PicoTLS client/server application

This application shows an example of a client/server implementation with PicoTLS.

## Prerequisites
1. Create a certificate and key file with this command:
```
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365
```
2. Change the paths of the certificate and key file in PicoTLSTest.h.

## Start
1. Change include path, path to OpenSSL library (used as backend) and path to PicoTLS library in makefile.
2. Start server (standard port is 8000).
3. Start client.
3. When TLS handshake is finished try sending a message by typing into the console of the client.

## Other useful examples
- [Wiki of PicoTLS](https://github.com/h2o/picotls/wiki/Using-picotls)
- [PicoTLS server implementation](https://gist.github.com/64/39c7f82c159b53a104961caf965696e1)