CC=gcc
CXX=g++
CFLAGS=-O2 -g
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=-ltrap -lcommlbr -lrt


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=PCA_sketch

all: ${MODULES}

flowdirection: PCA_sketch.o
	$(CC) $(CFLAGS) -o PCA_sketch PCA_sketch.o ../nfreader.so

clean:
	rm -f *.o ${MODULES}
