HOSTSTATSNEMEASRCS=src/aux_func.h \
		   src/config.cpp \
		   src/hs_config.h \
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
bin_PROGRAMS=hoststatsnemea
hoststatsnemea_SOURCES=$(HOSTSTATSNEMEASRCS)
hoststatsnemea_LDADD=-lnemea-common -ltrap -lunirec
hoststatsnemea_CXXFLAGS=-pthread -Wno-write-strings
pkgdocdir=${docdir}/hoststatsnemea
pkgdoc_DATA=README
dist_sysconf_DATA=hoststats.conf hoststats.conf.default
BUILT_SOURCES = src/fields.h src/fields.c
src/fields.h src/fields.c: $(UNIRECPROC)
	$(PYTHON) $(UNIRECPROC)

CLEANFILES = src/fields.c src/fields.h