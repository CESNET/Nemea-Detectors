CC=gcc
CXX=g++
CFLAGS=-std=c99 -O2 -g
CXXFLAGS=-O2 -g
LDFLAGS=
	
LDLIBS=../../../unirec/unirec.o -ltrap -lstdc++

MODULES=timebin_division

# Uses default rules
all: ${MODULES}

clean:
	rm -f *.o ${MODULES}
