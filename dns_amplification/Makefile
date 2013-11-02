CC=gcc
CXX=g++
CFLAGS=-O2 -std=c99
CXXFLAGS=-O2 -std=c++98
LDFLAGS=
LDLIBS= ../../unirec/unirec.o -ltrap


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=dns_amplification
all: unirec  ${MODULES}

unirec:
	$(MAKE) -C ../../unirec/

doxygen:
	doxygen dns_amplification.cpp


clean:
	rm -f *.o ${MODULES}

