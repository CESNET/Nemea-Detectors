CC=gcc
CXX=g++
CFLAGS=-std=c99 -O2
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=../../unirec/unirec.o -ltrap


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)
MODULES=alertsaver

all: ${MODULES}


clean:
	rm -f *.o ${MODULES}
	@for i in $(SUBDIRS) ; do $(MAKE) -C $$i clean ; done

