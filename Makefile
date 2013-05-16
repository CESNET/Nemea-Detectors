CC=gcc
CXX=g++
CFLAGS=-O2
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=-ltrap


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=nfdump_reader flow_counter nfdump_reader_test

all: ${MODULES}

nfdump_reader: nfdump_reader.o
	$(CC) ${LDFLAGS} -o nfdump_reader nfdump_reader.o ./nfreader.so ${LDLIBS}

nfdump_reader_test: nfdump_reader_test.o
	$(CXX) ${LDFLAGS} -o nfdump_reader_test nfdump_reader_test.o ./nfreader.so ${LDLIBS}

clean:
	rm -f *.o ${MODULES}
