bin_PROGRAMS=sip_bf_detector
sip_bf_detector_SOURCES=sip_bf_detector.cpp sip_bf_detector.h fields.c fields.h
sip_bf_detector_LDADD=-ltrap -lunirec -lnemea-common
sip_bf_detector_CXXFLAGS=-Wall -std=c++98 -O3
pkgdocdir=${docdir}/sip_bf_detector

doc:
	doxygen

clean-local:
	rm -rf doc
include ../aminclude.am
