bin_PROGRAMS=cpd_module entropy_module cpd sdmcpd
cpd_module_SOURCES=cpd.c entropy.c cpd_module.c
cpd_module_LDFLAGS=-lm -ltrap ../../../unirec/unirec.o

entropy_module_SOURCES=entropy.c entropy_module.c
entropy_module_LDFLAGS=-lm -ltrap ../../../unirec/unirec.o
EXTRA_DATA=log2s.x log2s.data

cpd_SOURCES=cpd.c entropy.c
cpd_CPPFLAGS=-DTESTCPD_C
cpd_LDFLAGS=-lm

sdmcpd_SOURCES=cpd.c
sdmcpd_CPPFLAGS=-DSDM_CPD
sdmcpd_LDFLAGS=-lm

