ACLOCAL_AMFLAGS = -I m4
mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))
bin_PROGRAMS=dga_detector
dga_detector_SOURCES=dga_detector.c estimator.c fields.c fields.h
dga_detector_LDADD=-lunirec -ltrap -lm 
dga_detector_CFLAGS= -DVAR=\"$(mkfile_dir)\"
include ./aminclude.am
