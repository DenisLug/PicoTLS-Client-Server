CC = g++-4.9
FLAGS = -Wall -g -std=c++11
INCLUDES = -I/tmp/picotls/include
LIBS = -L/tmp/picotls -lcrypto -lpicotls-core -lpicotls-openssl
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
