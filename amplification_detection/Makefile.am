include ../aminclude.am

bin_PROGRAMS=amplification_detection
amplification_detection_SOURCES=amplification_detection.cpp \
			amplification_detection.h fields.c fields.h
amplification_detection_LDADD=-ltrap -lunirec -lpthread 
amplification_detection_CXXFLAGS=-O2 -std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/amplification_detection
pkgdoc_DATA=README

