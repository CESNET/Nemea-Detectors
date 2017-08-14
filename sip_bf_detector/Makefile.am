bin_PROGRAMS=sip_bf_detector
sip_bf_detector_SOURCES=sip_bf_detector.cpp sip_bf_detector.h fields.c fields.h
sip_bf_detector_LDADD=-ltrap -lunirec -lnemea-common
sip_bf_detector_CXXFLAGS=-std=c++98

EXTRA_DIST=README.md
pkgdocdir=${docdir}/sip_bf_detector
pkgdoc_DATA=README.md

include ../aminclude.am
