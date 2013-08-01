CC=gcc
CXX=g++
CFLAGS=-O2 -std=c99
CXXFLAGS=-std=c++98 -O2 -g
LDFLAGS=
LDLIBS= ../../../unirec/unirec.o ../../../common/cuckoo_hash/libcuckoo_hash.a -ltrap -lidn


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=urlblacklistfilter
all: ${MODULES}

doxygen:
	doxygen urlblacklistfilter.cpp


clean:
	rm -f *.o ${MODULES}

