CC=c99
CFLAGS=-g -pg -Wall -pedantic
LDFLAGS=-g -pg -lm -ltrap

cpd_module: cpd_module.c common.o cpd.o cpd
	$(CC) $(LDFLAGS) ../../unirec/unirec.o cpd.o common.o cpd_module.c -o $@

cpd.o: cpd.c

cpd: cpd.c common.o
	$(CC) -DTESTCPD_C $(LDFLAGS) cpd.c common.o -o $@

common.o: common.c

.PHONY: clean
clean:
	rm -f *.o cpd cpd_module

