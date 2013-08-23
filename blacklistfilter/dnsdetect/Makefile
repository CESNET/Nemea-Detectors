C=gcc
CXX=g++
CFLAGS=-O2 -std=c99
CXXFLAGS=-std=c++98 -O2
LDFLAGS=
LDLIBS= ../../../unirec/unirec.o ../../../common/cuckoo_hash_v2/libcuckoo_hash_lock.a ../../../common/cuckoo_hash/libcuckoo_hash.a -lpthread -ltrap -lidn


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=dnsblacklistfilter
all: ${MODULES}

doxygen:
	doxygen dnsblacklistfilter.cpp


clean:
	rm -f *.o ${MODULES}

