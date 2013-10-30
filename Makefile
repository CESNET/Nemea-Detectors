CC=gcc
CXX=g++
CFLAGS=-O2
CXXFLAGS=-O2
LDFLAGS=
LDLIBS=-ltrap

SUBDIRS=nfreader flowcounter transitfilter flowdirection ipspoofingdetector traffic_repeater traffic_merger cpd_module entropy_module simplebotnetdetector pca logger delaybuffer anonymizer blacklistfilter hoststatsnemea trapdump trapreplay


# if no special flags or libraries are needed, it's sufficient to add the name
# of a new module here (when no rule is found, make uses default one)

all: others

.PHONY: bootstraps
bootstraps:
	@for directory in $(SUBDIRS); do \
		(cd "$$directory" ; \
		test ! -e configure -a -f "bootstrap.sh" -a -x "bootstrap.sh" && \
		echo "Bootstrap for $$directory" && \
		./bootstrap.sh && ./configure || true);  \
	done

.PHONY: others
others: ../unirec/unirec.o bootstraps
	@for directory in $(SUBDIRS); do \
		make -C "$$directory"; \
	done

# modules usually depend on unirec -> make it
../unirec/unirec.o:
	make -C "../unirec"

clean:
	rm -f *.o ${MODULES}
	@for i in $(SUBDIRS) ; do $(MAKE) -C $$i clean ; done

