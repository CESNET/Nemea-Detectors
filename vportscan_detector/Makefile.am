include ../aminclude.am

bin_PROGRAMS=vportscan_detector
vportscan_detector_SOURCES=vportscan_detector.c fields.c fields.h
vportscan_detector_LDADD=-ltrap -lunirec -lnemea-common
vportscan_detector_CXXFLAGS=-O2
vportscan_detector_CFLAGS=-O2

EXTRA_DIST=vportscan_aggregator.py
bin_SCRIPTS=vportscan_aggregator.py
