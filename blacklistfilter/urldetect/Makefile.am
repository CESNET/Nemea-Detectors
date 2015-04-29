bin_PROGRAMS=urlblacklistfilter
urlblacklistfilter_SOURCES=urlblacklistfilter.cpp \
                           urlblacklistfilter.h \
                           ../blacklist_downloader/blacklist_downloader.c \
                           ../blacklist_downloader/blacklist_downloader.h
urlblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
urlblacklistfilter_CFLAGS=-O2 -std=gnu99
urlblacklistfilter_CXXFLAGS=-std=c++98 -O2
pkgdocdir=${docdir}/urlblacklistfilter
pkgdoc_DATA=README
