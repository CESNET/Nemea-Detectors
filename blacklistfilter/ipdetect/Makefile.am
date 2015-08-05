bin_PROGRAMS=ipblacklistfilter
ipblacklistfilter_SOURCES=ipblacklistfilter.cpp \
                          ipblacklistfilter.h \
                          patternstrings.h \
                          ../blacklist_downloader/blacklist_downloader.c \
                          ../blacklist_downloader/blacklist_downloader.h
ipblacklistfilter_LDADD=-lpthread -ltrap -lunirec -lnemea-common
ipblacklistfilter_CFLAGS=-g -std=gnu99
ipblacklistfilter_CXXFLAGS=-std=c++98 -g
pkgdocdir=${docdir}/ipblacklistfilter
pkgdoc_DATA=README
