bin_PROGRAMS=ipblacklistfilter
ipblacklistfilter_SOURCES=ipblacklistfilter.cpp \
                          ipblacklistfilter.h \
                          patternstrings.h \
                          ../blacklist_downloader/blacklist_downloader.c \
                          ../blacklist_downloader/blacklist_downloader.h \
                          fields.c fields.h
ipblacklistfilter_LDADD=-lpthread -ltrap -lunirec -lnemea-common
ipblacklistfilter_CFLAGS=-std=gnu99
ipblacklistfilter_CXXFLAGS=-std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/ipblacklistfilter
pkgdoc_DATA=README
ipblacklistfiltersysconfdir=${sysconfdir}/ipblacklistfilter
dist_ipblacklistfiltersysconf_DATA=userConfigFile.xml bld_userConfigFile.xml
include ../../aminclude.am
