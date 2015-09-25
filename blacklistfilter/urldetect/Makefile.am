bin_PROGRAMS=urlblacklistfilter
urlblacklistfilter_SOURCES=urlblacklistfilter.cpp \
                           urlblacklistfilter.h \
                           ../blacklist_downloader/blacklist_downloader.c \
                           ../blacklist_downloader/blacklist_downloader.h \
                           fields.c fields.h
urlblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec
urlblacklistfilter_CFLAGS=-O2 -std=gnu99
urlblacklistfilter_CXXFLAGS=-std=c++98 -O2 -Wno-write-strings
pkgdocdir=${docdir}/urlblacklistfilter
pkgdoc_DATA=README
include ../../aminclude.am
