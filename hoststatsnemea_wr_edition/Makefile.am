HOSTSTATSNEMEA_WB_EDITION_SRCS=src/aux_func.h \
		   src/config.cpp \
		   src/config.h \
		   src/detectionrules.cpp \
		   src/detectionrules.h \
		   src/eventhandler.cpp \
		   src/eventhandler.h \
		   src/hoststatserv.cpp \
		   src/hoststats.h \
		   src/processdata.cpp \
		   src/processdata.h \
		   src/profile.cpp \
		   src/profile.h \
		   src/subprofiles.cpp \
		   src/subprofiles.h
bin_PROGRAMS=hoststatsnemea_wb_edition
hoststatsnemea_wb_edition_SOURCES=$(HOSTSTATSNEMEA_WB_EDITION_SRCS)
hoststatsnemea_wb_edition_LDADD=-lnemea-common -ltrap -lunirec
hoststatsnemea_wb_edition_CXXFLAGS=-pthread
pkgdocdir=${docdir}/hoststatsnemea_wb_edition
pkgdoc_DATA=README
dist_sysconf_DATA=hoststats.conf hoststats.conf.default

