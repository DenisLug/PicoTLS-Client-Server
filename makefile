CC = g++
FLAGS = -Wall -g
INCLUDES = -I/home/denis/TLS-Bibliotheken/picotls/include
LIBS = -L/home/denis/TLS-Bibliotheken/openssl-OpenSSL_1_1_1-stable -L/home/denis/TLS-Bibliotheken/picotls -lcrypto -lpicotls-core -lpicotls-openssl
OBJ = Main.o PicoTLSTest.o

# Link files
main: $(OBJ)
	$(CC) $(FLAGS) -o main $(OBJ) $(LIBS)

# Compile files
Main.o: Main.cpp
	$(CC) $(FLAGS) -c $(INCLUDES) Main.cpp

PicoTLSTest.o: PicoTLSTest.cpp PicoTLSTest.h
	$(CC) $(FLAGS) -c $(INCLUDES) PicoTLSTest.cpp

clean:
	$(RM) $(OBJ) main
