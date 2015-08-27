bin_PROGRAMS=dnsblacklistfilter
dnsblacklistfilter_SOURCES=dnsblacklistfilter.cpp \
			dnsblacklistfilter.h
dnsblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
dnsblacklistfilter_CFLAGS=-O2 -std=c99
dnsblacklistfilter_CXXFLAGS=-std=c++98 -O2 -Wno-write-strings
pkgdocdir=${docdir}/dnsblacklistfilter
pkgdoc_DATA=README
include ../../aminclude.am