CC=gcc
CXX=g++
CFLAGS=-O2 -std=c99
CXXFLAGS=-g -std=c++98
LDFLAGS=
LDLIBS= ../../unirec/unirec.o ../../common/cuckoo_hash/libcuckoo_hash.a -ltrap


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=spoofing
all: ${MODULES}

doxygen:
	doxygen spoofing.cpp


clean:
	rm -f *.o ${MODULES}

