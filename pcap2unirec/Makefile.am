bin_PROGRAMS=pcap2unirec
pcap2unirec_SOURCES=pcap2unirec.cpp \
		    pcap2unirec.h \
		    packet.h \
		    packetreceiver.h \
		    pcapreader.h \
		    flowifc.h \
		    flowcache.h \
		    flowwriter.h \
		    pcapreader.cpp \
		    mapflowcache.cpp \
		    mapflowcache.h \
		    nhtflowcache.cpp \
		    nhtflowcache.h \
		    flowwriter.cpp \
		    stats.cpp \
		    stats.h \
		    flowcacheplugin.h


pcap2unirec_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/pcap2unirec
pkgdoc_DATA=README
