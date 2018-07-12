bin_PROGRAMS=urlblacklistfilter
urlblacklistfilter_SOURCES=urlblacklistfilter.cpp \
                           urlblacklistfilter.h \
                           patternstrings.h \
                           ../blacklist_watcher/blacklist_watcher.cpp \
                           ../blacklist_watcher/blacklist_watcher.h \
                           fields.c fields.h

urlblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
urlblacklistfilter_CFLAGS=-std=gnu99
urlblacklistfilter_CXXFLAGS=-std=c++11 -Wno-write-strings -Wall -pedantic -DDEBUG
pkgdocdir=${docdir}/urlblacklistfilter
pkgdoc_DATA=README
urlblacklistfiltersysconfdir=${sysconfdir}/urlblacklistfilter
dist_urlblacklistfiltersysconf_DATA=userConfigFile.xml
include ../../aminclude.am
