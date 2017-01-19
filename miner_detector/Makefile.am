
bin_PROGRAMS=miner_detector
miner_detector_SOURCES=main.cpp miner_detector.cpp miner_detector.h sender.cpp sender.h utils.cpp utils.h fields.c fields.h patternstrings.h
miner_detector_LDADD=-lunirec -ltrap -lnemea-common -lpthread
EXTRA_DIST=default_blacklisted_ip.txt README.md
miner_detectorsysconfdir=${sysconfdir}/miner_detector
dist_miner_detectorsysconf_DATA=userConfigFile.xml

pkgdocdir=${docdir}/miner_detector
pkgdoc_DATA=README.md

include ../aminclude.am
