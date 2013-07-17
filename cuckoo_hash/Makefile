CC=gcc
CXX=g++
CFLAGS=-std=c99 -g
CXXFLAGS=-O2
LDFLAGS=

BIN=cuckoo_hash.o

$(BIN): cuckoo_hash.c cuckoo_hash.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(BIN)
