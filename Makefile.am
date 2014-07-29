ACLOCAL_AMFLAGS = -I m4

SUBDIRS=anonymizer \
astute \
attack_gen \
blacklistfilter \
basic2collector \
brute_force_detector \
deduplication \
delaybuffer \
dns_amplification \
dns_amp_twente \
entropy_module \
email_reporter \
example \
flow_gen \
flow_sanity_check \
flowcounter \
flowdirection \
flowtools_reader \
heartbleed_detector \
hoststatsnemea \
ipspoofingdetector \
ipv6stats \
logger \
logreplay \
merger \
pca \
p2pbotnet_detection \
p2pdetector \
protocolcounters \
python_example \
rrd_updater \
report_handler \
sampler \
simplebotnetdetector \
test_threads \
timestamp_checker \
traffic_delayer \
traffic_merger \
traffic_repeater \
transitfilter \
trapdump \
trapreplay \
tunnel_detection \
slowthreatdetector \
sshcure \
synflood/synfindiff \
synflood/synrate \
synflood/pcf \
warden_collector


EXTRA_DIST = nfreader flow_meter portscan_detector debug_sender

if HAVE_LIBNFDUMP
SUBDIRS += nfreader
endif
if HAVE_LIBPCAP
SUBDIRS += flow_meter portscan_detector
endif

RPMDIR = RPMBUILD

if DEBUG
AM_CFLAGS = -g -O0
AM_CXXFLAGS = -g -O0
else
AM_CFLAGS = -O2
AM_CXXFLAGS = -O2
endif

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
