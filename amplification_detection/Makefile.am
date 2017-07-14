
bin_PROGRAMS=amplification_detection
amplification_detection_SOURCES=amplification_detection.cpp \
			amplification_detection.h fields.c fields.h
amplification_detection_LDADD=-ltrap -lunirec -lpthread 
amplification_detection_CXXFLAGS=-std=c++98 -Wno-write-strings

EXTRA_DIST=README.md

pkgdocdir=${docdir}/amplification_detection
pkgdoc_DATA=README.md

include ../aminclude.am
