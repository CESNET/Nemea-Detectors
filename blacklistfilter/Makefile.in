CC=gcc
CXX=g++
CFLAGS=-O2
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=-ltrap

SUBDIRS=ipdetect dnsdetect urldetect

all: others

others:
	@for directory in $(SUBDIRS); do \
		make -C "$$directory"; \
	done

clean:
	@for i in $(SUBDIRS) ; do $(MAKE) -C $$i clean ; done

