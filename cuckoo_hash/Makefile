CC=gcc
CXX=g++
CFLAGS=-std=c99 -O2 
CXXFLAGS=-O2
LDFLAGS=

BIN=cuckoo_hash

$(BIN).o: cuckoo_hash.c cuckoo_hash.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(BIN)
