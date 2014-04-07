HOSTSTATSNEMEASRCS=src/aux_func.h \
		   src/BloomFilter.hpp \
		   src/config.cpp \
		   src/config.h \
		   src/detectionrules.cpp \
		   src/detectionrules.h \
		   src/eventhandler.cpp \
		   src/eventhandler.h \
		   src/filter.h \
		   src/hoststatserv.cpp \
		   src/hoststats.h \
		   src/processdata.cpp \
		   src/processdata.h \
		   src/profile.cpp \
		   src/profile.h \
		   src/subprofiles.cpp \
		   src/subprofiles.h
bin_PROGRAMS=hoststatsnemea
hoststatsnemea_SOURCES=$(HOSTSTATSNEMEASRCS)
hoststatsnemea_LDADD=-lnemea-common -ltrap -lunirec
hoststatsnemea_CXXFLAGS=-pthread
pkgdocdir=${docdir}/hoststatsnemea
pkgdoc_DATA=README
dist_sysconf_DATA=hoststats.conf hoststats.conf.default

