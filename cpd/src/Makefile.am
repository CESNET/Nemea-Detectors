bin_PROGRAMS=cpd_module cpd sdmcpd
cpd_module_SOURCES=cpd.c entropy.c cpd_module.c
cpd_module_LDFLAGS=-lm -ltrap ../../../unirec/unirec.o

cpd_SOURCES=cpd.c entropy.c
cpd_CPPFLAGS=-DTESTCPD_C
cpd_LDFLAGS=-lm

sdmcpd_SOURCES=cpd.c
sdmcpd_CPPFLAGS=-DSDM_CPD
sdmcpd_LDFLAGS=-lm

