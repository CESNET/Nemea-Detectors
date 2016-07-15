include ../aminclude.am

bin_PROGRAMS=brute_force_detector
brute_force_detector_SOURCES=telnet_server_profile.cpp telnet_server_profile.h record.h record.cpp brute_force_detector.h brute_force_detector.cpp config.h config.cpp host.h host.cpp sender.h sender.cpp whitelist.cpp whitelist.h fields.c fields.h
whitelist_unit_test_SOURCES=whitelist_unit_test.cpp whitelist.h whitelist.cpp
brute_force_detector_LDADD= -lunirec -ltrap
brute_force_detector_CXXFLAGS=-Wno-write-strings

check_PROGRAMS=whitelist_unit_test
TESTS = whitelist_unit_test

EXTRA_DIST=README.md
pkgdocdir=${docdir}/brute_force_detector
pkgdoc_DATA=README.md

