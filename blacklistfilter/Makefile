CC=gcc
CXX=g++
CFLAGS=-O2 -std=c99
CXXFLAGS=-std=c++98 -O2
LDFLAGS=
LDLIBS= ../../unirec/unirec.o ../cuckoo_hash/cuckoo_hash.o -ltrap -lcommlbr -lrt


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=blacklistfilter
all: ${MODULES}

doxygen:
	doxygen spoofing.cpp


clean:
	rm -f *.o ${MODULES}

