bin_PROGRAMS=cpd_module entropy_module cpd sdmcpd
LDADD=../../../unirec/unirec.o ../../../common/cuckoo_hash_v2/libcuckoo_hash_lock.a
AM_CFLAGS=-Wall
AM_LDFLAGS=-lm -ltrap
cpd_module_SOURCES=cpd.c entropy.c cpd_module.c
#cpd_module_LDFLAGS=-lm -ltrap

entropy_module_SOURCES=entropy.c entropy_module.c
#entropy_module_LDFLAGS=-lm -ltrap

EXTRA_DATA=log2s.x log2s.data

cpd_SOURCES=cpd.c entropy.c
cpd_CPPFLAGS=-DTESTCPD_C
cpd_LDFLAGS=-lm

sdmcpd_SOURCES=cpd.c
sdmcpd_CPPFLAGS=-DSDM_CPD
sdmcpd_LDFLAGS=-lm

