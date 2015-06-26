bin_PROGRAMS=ipblacklistfilter
ipblacklistfilter_SOURCES=ipblacklistfilter.cpp \
                          ipblacklistfilter.h \
                          ../blacklist_downloader/blacklist_downloader.c \
                          ../blacklist_downloader/blacklist_downloader.h
ipblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
ipblacklistfilter_CFLAGS=-O2 -std=gnu99
ipblacklistfilter_CXXFLAGS=-std=c++98 -O2 -Wno-write-strings
pkgdocdir=${docdir}/ipblacklistfilter
pkgdoc_DATA=README
include ../../aminclude.am