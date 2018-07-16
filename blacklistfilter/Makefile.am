bin_PROGRAMS=ipblacklistfilter urlblacklistfilter

#dnsblacklistfilter_SOURCES=dnsblacklistfilter.cpp \
#			dnsblacklistfilter.h fields.c fields.h
#dnsblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
#dnsblacklistfilter_CFLAGS=-std=c99
#dnsblacklistfilter_CXXFLAGS=-std=c++98 -Wno-write-strings

ipblacklistfilter_SOURCES=ipblacklistfilter.cpp \
			ipblacklistfilter.h \
			ipdetect/patternstrings.h \
			blacklist_watcher.cpp \
			blacklist_watcher.h \
			fields.c fields.h
ipblacklistfilter_LDADD=-lpthread -ltrap -lunirec -lnemea-common
ipblacklistfilter_CFLAGS=-std=gnu99
ipblacklistfilter_CXXFLAGS=-std=c++11 -Wall -pedantic
ipblacklistfiltersysconfdir=${sysconfdir}/ipblacklistfilter
dist_ipblacklistfiltersysconf_DATA=ipdetect/userConfigFile.xml


urlblacklistfilter_SOURCES=urlblacklistfilter.cpp \
                           urlblacklistfilter.h \
                           ipdetect/patternstrings.h \
                           blacklist_watcher.cpp \
                           blacklist_watcher.h \
                           fields.c fields.h
urlblacklistfilter_LDADD=-lpthread -ltrap -lidn -lunirec -lnemea-common
urlblacklistfilter_CFLAGS=-std=gnu99
urlblacklistfilter_CXXFLAGS=-std=c++11 -Wno-write-strings -Wall -pedantic
urlblacklistfiltersysconfdir=${sysconfdir}/urlblacklistfilter
dist_urlblacklistfiltersysconf_DATA=urldetect/userConfigFile.xml

EXTRA_DIST=blacklist_downloader/bl_downloader.py  \
	   blacklist_downloader/bld_userConfigFile.xml \
	   urldetect/patternstrings.h \
	   urldetect/README \
	   urldetect/userConfigFile.xml \
	   urldetect/Makefile.am \
	   ipdetect/patternstrings.h \
	   ipdetect/README \
	   ipdetect/userConfigFile.xml \
	   ipdetect/Makefile.am \
	   dnsdetect/README \
	   dnsdetect/Makefile.am

bin_SCRIPTS=blacklist_downloader/bl_downloader.py

dist_blacklistfilter_DATA=blacklist_downloader/bld_userConfigFile.xml
urldetectsysconfdir=${sysconfdir}/blacklist_downloader/urldetect
urldetectsysconf_DATA=urldetect/userConfigFile.xml
ipdetectsysconfdir=${sysconfdir}/blacklist_downloader/ipdetect
ipdetectsysconf_DATA=ipdetect/userConfigFile.xml

dnspkgdocdir=${docdir}/dnsblacklistfilter
dnspkgdoc_DATA=dnsdetect/README
ippkgdocdir=${docdir}/ipblacklistfilter
ippkgdoc_DATA=ipdetect/README
urlpkgdocdir=${docdir}/urlblacklistfilter
urlpkgdoc_DATA=urldetect/README

include ../aminclude.am

