/*
 * PicoTLS.h
 *
 *  Created on: 10.12.2018
 *  Author: Denis Lugowski
 */

#ifndef PICOTLSTEST_H_
#define PICOTLSTEST_H_

#include <netinet/in.h>
#include <cstddef>
#include "picotls/openssl.h"

class PicoTLSTest
{
public:
    PicoTLSTest();
    virtual ~PicoTLSTest();

    // Socket functions
    void createClientSocket();
    void createServerSocket(int port);
    void connectToServer(int port);
    void waitForIncomingConnection();
    void writeToSocket();
    char* readFromSocket();
    void closeSocket();

    // OpenSSL_BIO_Client functions
    void initPicoTLS();
    void cleanupPicoTLS();
    void doSSLHandshake();

private:
    void setupCertVerification();
    void readCert();
    void readPrivateKey();
    void writeAll(ptls_buffer_t& sendbuf);

    int port;
    int clientSocket;
    int serverSocket;
    struct sockaddr_in serverAddress;
    struct sockaddr_in clientAddress;
    bool isServer = false;

    ptls_context_t context;
    ptls_openssl_verify_certificate_t verifier;
    ptls_t* tls = nullptr;

    const int BUFFER_SIZE = 4096;
    const char* CERT_FILE = "/home/denis/workspace_cpp/OpenSSL/assets/cert.pem";
    const char* KEY_FILE = "/home/denis/workspace_cpp/OpenSSL/assets/key.pem";
};

#endif /* PICOTLSTEST_H_ */
