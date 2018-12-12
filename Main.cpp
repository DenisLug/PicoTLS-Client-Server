/*
 * Main.cpp
 *
 *  Created on: 10.12.2018
 *  Author: Denis Lugowski
 */

#include <iostream>
#include "PicoTLSTest.h"

int main(int argc, char **argv)
{
    PicoTLSTest* tls = nullptr;

    char isServer;
    std::cout << "Does host acts as a server (y/n)?";
    std::cin >> isServer;

    if (isServer == 'y') {
        // Server
        tls = new PicoTLSTest();
        tls->createServerSocket(8000);
        tls->initPicoTLS();
        tls->waitForIncomingConnection();

        while (1) {
            char* msg = tls->readFromSocket();
            printf("Message: %s\n", msg);
            delete (msg);
        }
    }
    else {
        // Client
        tls = new PicoTLSTest();
        tls->createClientSocket();
        tls->initPicoTLS();
        tls->connectToServer(8000);

        while (1) {
            tls->writeToSocket();
        }
    }

    tls->cleanupPicoTLS();
    tls->closeSocket();

}

