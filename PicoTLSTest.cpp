/*
 * PicoTLS.cpp
 *
 *  Created on: 10.12.2018
 *  Author: Denis Lugowski
 *
 *  Parts of this code were taken from https://github.com/h2o/picotls/wiki/Using-picotls
 */

#include "PicoTLSTest.h"

#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <cstdlib>
#include "openssl/pem.h"

PicoTLSTest::PicoTLSTest() {}

PicoTLSTest::~PicoTLSTest() {}

void PicoTLSTest::createClientSocket()
{
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (clientSocket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
}

void PicoTLSTest::createServerSocket(int port)
{
    isServer = true;
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    if (serverSocket < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    // Allow binding to already used port
    int optval = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));

    if (bind(serverSocket, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Unable to bind socket");
        exit(EXIT_FAILURE);
    }

    if (listen(serverSocket, 1) < 0) {
        perror("Listen on socket failed");
        exit(EXIT_FAILURE);
    }
}

void PicoTLSTest::connectToServer(int port)
{
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);

    if (connect(clientSocket, (struct sockaddr*) &serverAddress, sizeof(serverAddress)) < 0) {
        perror("Unable to connect");
        exit(EXIT_FAILURE);
    }

    printf("Connected to server\n");

    doSSLHandshake();
}

void PicoTLSTest::waitForIncomingConnection()
{
    printf("Waiting for incoming connection...\n");
    unsigned int clientAddressLen = sizeof(clientAddress);

    clientSocket = accept(serverSocket, (struct sockaddr*) &clientAddress, &clientAddressLen);

    if (clientSocket < 0) {
        perror("Accept on socket failed");
        exit(EXIT_FAILURE);
    }

    printf("Connection accepted!\n");

    doSSLHandshake();
}

void PicoTLSTest::writeAll(ptls_buffer_t& sendbuf)
{
    size_t writtenBytes = 0;
    uint8_t* sendBufPtr = sendbuf.base;

    while (sendbuf.off != 0) {
        writtenBytes = write(clientSocket, sendBufPtr, sendbuf.off);

        if (writtenBytes < 0) {
            perror("Error on write");
            exit(EXIT_FAILURE);
        }

        sendbuf.off -= writtenBytes;
        sendBufPtr += writtenBytes;
    }
}

void PicoTLSTest::doSSLHandshake()
{
    uint8_t recvbuf[BUFFER_SIZE];
    ptls_buffer_t sendbuf;
    int ret;
    size_t receivedBytes = 0;

    ptls_buffer_init(&sendbuf, const_cast<char*>(""), 0);

    while ((ret = ptls_handshake(tls, &sendbuf, recvbuf, &receivedBytes, NULL))
            == PTLS_ERROR_IN_PROGRESS) {
        if (sendbuf.off > 0) {
            printf("Host has %lu bytes encrypted data to send\n", sendbuf.off);
            writeAll(sendbuf);
        }
        else {
            receivedBytes = read(clientSocket, recvbuf, sizeof(recvbuf));
            if (receivedBytes > 0) {
                printf("Host has received %lu bytes data\n", receivedBytes);
            }
        }
    }

    // Send remaining server_hello and application data
    writeAll(sendbuf);

    if (ret == 0) {
        // handshake succeeded (we might have some application data after recvbuf + roff)
        printf("Host SSL handshake done!\n");
    }
    else {
        // handshake failed
        printf("Host SSL handshake failed with code %d!\n", ret);
    }

    ptls_buffer_dispose(&sendbuf);
}

void PicoTLSTest::writeToSocket()
{
    char buffer[BUFFER_SIZE] = { 0 };
    ptls_buffer_t sendbuf;

    ptls_buffer_init(&sendbuf, const_cast<char*>(""), 0);

    int msgSize = read(STDIN_FILENO, buffer, sizeof(buffer));

    if (msgSize > 0) {
        int ret = ptls_send(tls, &sendbuf, buffer, msgSize);
        assert(ret == 0);

        printf("Host has %lu bytes encrypted data to send\n", sendbuf.off);
        writeAll(sendbuf);
    }

    ptls_buffer_dispose(&sendbuf);
}

char* PicoTLSTest::readFromSocket()
{
    size_t input_off = 0;
    ptls_buffer_t plaintextbuf;
    int ret;
    char* buffer[BUFFER_SIZE];
    char* msg = nullptr;

    size_t receivedBytes = read(clientSocket, buffer, BUFFER_SIZE);

    if (receivedBytes > 0) {
        ptls_buffer_init(&plaintextbuf, const_cast<char*>(""), 0);

        do {
            size_t consumed = receivedBytes - input_off;
            ret = ptls_receive(tls, &plaintextbuf, buffer + input_off, &consumed);
            input_off += consumed;
        } while (ret == 0 && input_off < receivedBytes);

        msg = new char[plaintextbuf.off];
        memcpy(msg, plaintextbuf.base, plaintextbuf.off);

        ptls_buffer_dispose(&plaintextbuf);

        printf("Host has received %lu bytes encrypted data\n", receivedBytes);
    }

    return msg;
}

void PicoTLSTest::initPicoTLS()
{
    // Initialize context
    memset(&context, 0, sizeof(context));
    context.random_bytes = ptls_openssl_random_bytes;
    context.key_exchanges = ptls_openssl_key_exchanges;
    context.cipher_suites = ptls_openssl_cipher_suites;
    context.get_time = &ptls_get_time;

    if (isServer) {
        readCert();
        readPrivateKey();
    }
    else {
        setupCertVerification();
    }

    tls = ptls_new(&context, isServer);

    // Not needed when certificate verifier is NULL.
    // See: https://github.com/h2o/picotls/issues/165
    //ptls_set_server_name(tls, "localhost", 9);
}

void PicoTLSTest::setupCertVerification()
{
    ptls_openssl_init_verify_certificate(&verifier, NULL);
    // Don't verify the self signed certificates which would cause unknown_certificate error (46)
    //context.verify_certificate = &verifier.super;
    context.verify_certificate = NULL;
}

void PicoTLSTest::readPrivateKey()
{
    static ptls_openssl_sign_certificate_t signer;

    FILE* fp = fopen(KEY_FILE, "rb");
    assert(fp != NULL);

    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    assert(pkey != NULL);

    ptls_openssl_init_sign_certificate(&signer, pkey);
    EVP_PKEY_free(pkey);
    context.sign_certificate = &signer.super;
    fclose(fp);
}

void PicoTLSTest::readCert()
{
    static ptls_iovec_t certs[16];
    size_t count = 0;
    FILE* fp = fopen(CERT_FILE, "rb");
    assert(fp != NULL);
    X509* cert;

    // Uses openssl pem.h
    while ((cert = PEM_read_X509(fp, NULL, NULL, NULL)) != NULL) {
        ptls_iovec_t* dst = certs + count++;
        dst->len = i2d_X509(cert, &dst->base);
    }

    fclose(fp);
    context.certificates.list = certs;
    context.certificates.count = count;
}

void PicoTLSTest::closeSocket()
{
    close(clientSocket);
}

void PicoTLSTest::cleanupPicoTLS()
{
    ptls_free(tls);
}
