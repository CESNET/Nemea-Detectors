
bin_PROGRAMS=vportscan_detector
vportscan_detector_SOURCES=vportscan_detector.c fields.c fields.h
vportscan_detector_LDADD=-ltrap -lunirec -lnemea-common

EXTRA_DIST=vportscan_aggregator.py README.md
bin_SCRIPTS=vportscan_aggregator.py

pkgdocdir=${docdir}/vportscan_detector
pkgdoc_DATA=README.md
include ../aminclude.am
