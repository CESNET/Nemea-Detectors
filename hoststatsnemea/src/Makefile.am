include ../../aminclude.am

HOSTSTATSNEMEASRCS=aux_func.h \
		   config.cpp \
		   hs_config.h \
		   detectionrules.cpp \
		   detectionrules.h \
		   eventhandler.cpp \
		   eventhandler.h \
		   hoststatserv.cpp \
		   hoststats.h \
		   processdata.cpp \
		   processdata.h \
		   profile.cpp \
		   profile.h \
		   subprofiles.cpp \
		   subprofiles.h \
		   fields.c fields.h

bin_PROGRAMS=hoststatsnemea
hoststatsnemea_SOURCES=$(HOSTSTATSNEMEASRCS)
hoststatsnemea_LDADD=-lnemea-common -ltrap -lunirec
hoststatsnemea_CXXFLAGS=-pthread -Wno-write-strings

