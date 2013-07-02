CC=gcc
CXX=g++
CFLAGS=-O2
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=-ltrap -lcommlbr -lrt

SUBDIRS=nfreader flowcounter transitfilter


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)

all: others

.PHONY: others
others:
	@for directory in $(SUBDIRS); do \
		make -C "$$directory"; \
	done

clean:
	rm -f *.o ${MODULES}
	@for i in $(SUBDIRS) ; do $(MAKE) -C $$i clean ; done

