CC=gcc
CXX=g++
CFLAGS=-std=c99 -g
CXXFLAGS=-O2
LDFLAGS=

BIN=cuckoo_hash

$(BIN): cuckoo_hash.c
	$(CC) $(CFLAGS) -o $@ $^ 

clean:
	rm -f *.o $(BIN)
