ACLOCAL_AMFLAGS = -I m4

SUBDIRS=amplification_detection \
	blacklistfilter \
	blacklistfilter/adaptive_filter \
	brute_force_detector \
	ddos_detector \
	dga_detector \
	hoststatsnemea \
	haddrscan_detector \
	miner_detector \
	sip_bf_detector \
	smtp_spam_detector \
	tunnel_detection \
	voip_fraud_detection \
	vportscan_detector \
	waintrusion_detector

RPMDIR = RPMBUILD

EXTRA_DIST = AUTHORS COPYING ChangeLog INSTALL NEWS README.md \
	debian/README.Debian \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/patches \
	debian/rules \
	debian/source \
	debian/watch

if MAKE_RPMS
RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)
.PHONY: rpm
rpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -ba $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

else
endif

rpm-clean:
	rm -rf $(RPMDIR)


if MAKE_DEB
.PHONY: deb
deb:
	make distdir && cd nemea-detectors-@VERSION@ && debuild -i -us -uc -b
else
endif

deb-clean:
	rm -rf nemea-detectors_*.build* nemea-detectors_*.changes nemea-detectors*.deb nemea-detectors_*.orig.tar.gz nemea-detectors-*.tar.gz nemea-detectors-@VERSION@

clean-local: rpm-clean deb-clean

