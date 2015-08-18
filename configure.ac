#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-modules], [1.0.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([trapdump/trapdump.c])
AC_CONFIG_HEADERS([config.h])
RELEASE=2
AC_SUBST(RELEASE)
USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)
AM_INIT_AUTOMAKE([-Wall silent-rules subdir-objects])
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])
# Must be checked before default -g -O2 is set:
AC_ARG_ENABLE([debug],
        AC_HELP_STRING([--enable-debug],
        [Enable build with debug symbols and without optimizations.]),
        [if test "$enableval" = "yes"; then
                CFLAGS="-Wall -g -O0 $CFLAGS"
                CXXFLAGS="-Wall -g -O0 $CXXFLAGS"
        fi], [CFLAGS="-Wall -O3 $CFLAGS"
              CXXFLAGS="-Wall -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

LT_INIT()

pkgdatadir=${datadir}/nemea
PKGDATADIR=$(eval echo $(eval echo ${pkgdatadir}))
AC_SUBST(PKGDATADIR)
AC_SUBST(pkgdatadir)
AC_DEFINE_DIR(PKGDATADIR, [pkgdatadir], [Path to configuration files])
AC_DEFINE_DIR(SYSCONFDIR, [sysconfdir], [Path to configuration files])

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_PROG(PYTHON, python, python, [""])
AC_SUBST(PYTHON)
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
AX_PTHREAD([LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread not found])])

AC_ARG_ENABLE(repobuild, AS_HELP_STRING([--disable-repobuild],
		[disable local compilation without system installed Nemea libraries, default: yea]),
[case "${enableval}" in
	yes) repobuild=true ;;
	no)  repobuild=false ;;
	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-repobuild]) ;;
esac], [repobuild=true])

AX_LIBTRAP_CHECK
AX_UNIREC_CHECK
AX_NEMEACOMMON_CHECK

AC_CHECK_HEADER(idna.h,
         AC_CHECK_LIB(idn, stringprep_check_version, [libidn=yes], AC_MSG_WARN([libidn not found. The ipdetect module from blacklistfilter will not be compiled.])), AC_MSG_WARN([libidn.h not found. Blacklistfilter modules will not be compiled.]))

AM_CONDITIONAL(HAVE_LIBIDN, test x${libidn} = xyes)

# Checks for libraries.
AC_CHECK_LIB(nf, lnf_open, [libnf=yes],
  [AC_CHECK_LIB(nfdump, nfdump_init, [libnfdump=yes],
    [AC_MSG_WARN([libnf and libnfdump not found. The nfreader module will not be compiled.])]
  )]
)

AM_CONDITIONAL(HAVE_LIBNFDUMP, test x${libnfdump} = xyes)
AM_CONDITIONAL(HAVE_LIBNF, test x${libnf} = xyes)

AC_CHECK_HEADER(pcap.h,
	AC_CHECK_LIB(pcap, pcap_open, [libpcap=yes], AC_MSG_WARN([libpcap not found. The flow_meter and portscan_detector modules will not be compiled.])), AC_MSG_WARN([pcap.h not found. The flow_meter and portscan_detector modules will not be compiled.]))

AM_CONDITIONAL(HAVE_LIBPCAP, test x${libpcap} = xyes)

AC_CHECK_HEADER(rrd.h,
	AC_CHECK_LIB(rrd, rrd_update, [rrdtool=yes], AC_MSG_WARN([rrdtool not found. The rrd_updater module will not be compiled.])), AC_MSG_WARN([rrd.h not found. The rrd_updater module will not be compiled.]))

AM_CONDITIONAL(HAVE_RRDTOOL, test x${rrdtool} = xyes)

AC_CHECK_PROG(BISON, bison, yes, [""])
AC_CHECK_PROG(FLEX, flex, yes, [""])

AM_CONDITIONAL(HAVE_BISON, test xyes = x${BISON} -a xyes = x${FLEX})

PKG_CHECK_MODULES([FASTBIT],[fastbit],[libfastbit=yes],[AC_MSG_WARN([libfastbit was not found by pkg-config. The fbreader module will not be compiled.])])

AM_CONDITIONAL(HAVE_LIBFASTBIT, test x${libfastbit} = xyes)


# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h locale.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm clock_gettime floor gettimeofday localeconv memset mkdir pow setlocale sqrt strchr strdup strerror strstr strtol strtoul])

# Check for sigaction
AC_CHECK_FUNC(sigaction, AC_DEFINE(HAVE_SIGACTION, 1, [Define if you have the 'sigaction' function]))

#RPM & Doxygen
AC_SUBST(RPMBUILD)
if test -z "$RPMBUILD"; then
	AC_MSG_WARN([Due to missing rpmbuild you will not able to generate RPM package.])
fi

RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

#DX_INIT_DOXYGEN([nemea-cpd], [Doxyfile], [doc])

# list of all *.in (and Makefile.am) files to process by configure script
AC_CONFIG_FILES([Makefile
                 alertfilter/Makefile
                 anonymizer/Makefile
                 astute/Makefile
                 attack_gen/Makefile
                 basic2collector/Makefile
                 blacklistfilter/Makefile
                 blacklistfilter/ipdetect/Makefile
                 brute_force_detector/Makefile
                 brute_force_hist_detector/Makefile
                 configurator_examples/Makefile
                 configurator_examples/simple_types/Makefile
                 configurator_examples/structures/Makefile
                 configurator_examples/arrays/Makefile
                 configurator_examples/complex_example/Makefile
                 deduplication/Makefile
                 delaybuffer/Makefile
                 dns_amp_twente/Makefile
                 amplification_detection/Makefile
                 email_reporter/Makefile
                 entropy_module/Makefile
                 example/Makefile
                 fbreader/Makefile
                 flow_gen/Makefile
                 flow_meter/Makefile
                 flowcounter/Makefile
                 flowdirection/Makefile
                 flow_statistic/Makefile
                 flowtools_reader/Makefile
                 heartbleed_detector/Makefile
                 hoststatsnemea/Makefile
                 ipspoofingdetector/Makefile
                 ipv6stats/Makefile
                 logger/Makefile
                 logreplay/Makefile
                 merger/Makefile
                 nemea-modules.spec
                 nemea2sdmcap/Makefile
                 nfreader/Makefile
                 p2pbotnet_detection/Makefile
                 p2pdetector/Makefile
                 pca/Makefile
                 portscan_detector/Makefile
                 protocolcounters/Makefile
                 python_example/Makefile
                 rrd_updater/Makefile
                 sampler/Makefile
                 sdmcap_controller/Makefile
                 simplebotnetdetector/Makefile
                 slowthreatdetector/Makefile
                 synflood/pcf/Makefile
                 synflood/synfindiff/Makefile
                 synflood/synrate/Makefile
                 test_threads/Makefile
                 timestamp_checker/Makefile
                 traffic_delayer/Makefile
                 traffic_merger/Makefile
                 report_handler/Makefile
                 traffic_repeater/Makefile
                 transitfilter/Makefile
                 trapdump/Makefile
                 trapreplay/Makefile
                 tunnel_detection/Makefile
                 unirecfilter/Makefile
                 vermon/Makefile
                 voip_fraud_detection/Makefile
                 warden_collector/Makefile
               ])


AC_OUTPUT

echo
echo
echo "------------------------------------------------------------------------"
echo "$PACKAGE $VERSION"
echo "------------------------------------------------------------------------"
echo
echo
echo "Configuration Options Summary:"
echo
echo "  ASM.(32 bit only)..: $ASM"
echo "  Static binary......: $static"
echo
echo "Documentation..........: ${build_doc}"
echo
echo "UniRec processor.......: $UNIRECPROC"
echo "Compilation............: make (or gmake)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  CXXFLAGS.............: $CXXFLAGS"
echo "  LDFLAGS..............: $LDFLAGS"
echo "  LIBS.................: $LIBS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo

