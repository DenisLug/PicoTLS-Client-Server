CC = g++
FLAGS = -Wall -g
INCLUDES = -I/tmp/picotls-d94a67d4d9733fa7b72c331d238c6160298d39b3/include
LIBS = -L/tmp/picotls-d94a67d4d9733fa7b72c331d238c6160298d39b3 -lcrypto -lpicotls-core -lpicotls-openssl
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
