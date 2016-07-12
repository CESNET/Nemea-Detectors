bin_PROGRAMS=urlblacklistfilter
urlblacklistfilter_SOURCES=urlblacklistfilter.cpp \
                           urlblacklistfilter.h \
                           patternstrings.h \
                           ../blacklist_downloader/blacklist_downloader.c \
                           ../blacklist_downloader/blacklist_downloader.h \
                           fields.c fields.h
urlblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
urlblacklistfilter_CFLAGS=-O2 -std=gnu99
urlblacklistfilter_CXXFLAGS=-std=c++11 -O2 -Wno-write-strings
pkgdocdir=${docdir}/urlblacklistfilter
pkgdoc_DATA=README
urlblacklistfiltersysconfdir=${sysconfdir}/urlblacklistfilter
dist_urlblacklistfiltersysconf_DATA=userConfigFile.xml bld_userConfigFile.xml
include ../../aminclude.am
