ACLOCAL_AMFLAGS = -I m4

SUBDIRS=anonymizer \
astute \
blacklistfilter \
cpd_module \
delaybuffer \
entropy_module \
example \
flow_gen \
flowcounter \
flowdirection \
hoststatsnemea \
ipspoofingdetector \
logger \
nfreader \
pca \
pca/pca-test-receiver \
protocolcounters \
simplebotnetdetector \
test_threads \
timestamp_checker \
traffic_merger \
traffic_repeater \
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

