ACLOCAL_AMFLAGS = -I m4

SUBDIRS=anonymizer \
astute \
attack_gen \
blacklistfilter \
deduplication \
delaybuffer \
dns_amplification \
dns_amp_twente \
entropy_module \
example \
flow_gen \
flow_sanity_check \
flowcounter \
flowdirection \
hoststatsnemea \
ipspoofingdetector \
logger \
pca \
protocolcounters \
simplebotnetdetector \
test_threads \
timestamp_checker \
transitfilter \
trapdump \
trapreplay

RPMDIR = RPMBUILD

if MAKE_RPMS
RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)
.PHONY: rpm
rpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -ba $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

rpm-clean:
	rm -rf $(RPMDIR)
else
endif
#pca/pca-test-receiver 
#cpd_module 
