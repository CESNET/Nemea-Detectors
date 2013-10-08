bin_PROGRAMS=cpd_module entropy_module cpd
LDADD=../../../unirec/unirec.o ../../../common/cuckoo_hash_v2/libcuckoo_hash_lock.a
AM_CFLAGS=-Wall
AM_LDFLAGS=-lm -ltrap
cpd_module_SOURCES=cpd.c entropy.c cpd_module.c linux_ewma.c

entropy_module_SOURCES=entropy.c entropy_module.c

EXTRA_DATA=log2s.x log2s.data

cpd_SOURCES=cpd.c entropy.c linux_ewma.c
cpd_CPPFLAGS=-DTESTCPD_C
cpd_LDFLAGS=-lm

