SUBDIRS=adaptive_filter_files

pkgdocdir=${docdir}/adaptive_filter
dist_pkgdoc_DATA=README.md
dist_bin_SCRIPTS=adaptive_filter

# TODO: How to run this only for local build? 
# Install dependency for dns queries when installing locally
# install-exec-local:
#	pip3 install dnspython
#

bin_PROGRAMS=split_evidence
split_evidence_SOURCES=split_evidence.c

include ../../aminclude.am
