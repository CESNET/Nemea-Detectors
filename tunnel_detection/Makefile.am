bin_PROGRAMS=tunnel_detection_dns
tunnel_detection_dns_SOURCES=b_plus_tree.cpp \
			b_plus_tree.h\
			tunnel_detection_dns.c \
			tunnel_detection_dns.h \
			parser_pcap_dns.c \
			parser_pcap_dns.h \
			prefix_tree.c \
			prefix_tree.h \
			tunnel_detection_dns_structs.h 
tunnel_detection_dns_LDADD=-ltrap -lunirec -lm
tunnel_detection_dns_CXXFLAGS=-std=c++98 -O2
tunnel_detection_dns_CFLAGS=-std=c99 -O2
pkgdocdir=${docdir}/tunnel_detection_dns
dist_pkgdoc_DATA=README
