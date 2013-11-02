#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-modules], [0.0.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([trapdump/trapdump.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror silent-rules])
LT_INIT

USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`

AC_CONFIG_MACRO_DIR([m4])


# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])

# Checks for libraries.
AC_CHECK_LIB([trap], [trap_init])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT64_T

# Checks for library functions.

#RPM & Doxygen
AC_SUBST(RPMBUILD)
if test -z "$RPMBUILD"; then
	AC_MSG_WARN([Due to missing rpmbuild you will not able to generate RPM package.])
fi

RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

#DX_INIT_DOXYGEN([nemea-cpd], [Doxyfile], [doc])

# for modules with configure script
AC_CONFIG_SUBDIRS([entropy_module cpd_module])
# list of all *.in (and Makefile.am) files to process by configure script
AC_CONFIG_FILES([Makefile
                 anonymizer/Makefile
                 astute/Makefile
                 blacklistfilter/Makefile
                 blacklistfilter/dnsdetect/Makefile
                 blacklistfilter/ipdetect/Makefile
                 blacklistfilter/urldetect/Makefile
                 delaybuffer/Makefile
                 example/Makefile
                 flow_gen/Makefile
                 flowcounter/Makefile
                 flowdirection/Makefile
                 hoststatsnemea/Makefile
                 ipspoofingdetector/Makefile
                 logger/Makefile
                 nfreader/Makefile
                 pca/Makefile
                 pca/src/timebin_division/Makefile
                 pca/pca-test-receiver/Makefile
                 protocolcounters/Makefile
                 simplebotnetdetector/Makefile
                 test_threads/Makefile
                 timestamp_checker/Makefile
                 traffic_merger/Makefile
                 traffic_repeater/Makefile
                 transitfilter/Makefile
                 trapdump/Makefile
                 trapreplay/Makefile])


AC_OUTPUT
