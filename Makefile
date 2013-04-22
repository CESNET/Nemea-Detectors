CC=gcc
CFLAGS=-O2 -ltrap


# if no special flags or libraries are needed, it's sufficient to add name of
# the new module here (when no rule is found, make uses default one)
MODULES=nfdump_reader flow_counter

all: ${MODULES}

nfdump_reader: nfdump_reader.o
	gcc ${CFLAGS} -o nfdump_reader nfdump_reader.o ./nfreader.so

clean:
	rm -f *.o ${MODULES}
