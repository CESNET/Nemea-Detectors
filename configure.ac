#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-modules], [1.0.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([trapdump/trapdump.c])
AC_CONFIG_HEADERS([config.h])
RELEASE=1
AC_SUBST(RELEASE)
USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)
AM_INIT_AUTOMAKE([-Wall -Werror silent-rules])
LT_INIT
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])

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
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
AC_CHECK_PROG(PYTHON, python, python, [""])
AC_SUBST(PYTHON)
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])

AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug],
		[enable debugging, default: no]),
[case "${enableval}" in
	yes) debug=true ;;
	no)  debug=false ;;
	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
esac], [debug=false])

AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

if test -z "$TRAPLIB"; then
	PKG_CHECK_MODULES([LIBTRAP],[libtrap], [TRAPLIB="yes"], [AC_MSG_WARN([Libtrap was not found by pkg-config])])
	LDFLAGS="$LIBTRAP_LDFLAGS $LDFLAGS"
	LIBS="$LIBTRAP_LIBS $LIBS"
	CFLAGS="$LIBTRAP_CFLAGS $CFLAGS"
	CXXFLAGS="$LIBTRAP_CFLAGS $CXXFLAGS"
fi
if test -z "$TRAPLIB"; then
	# Check for TRAP toolkit as a superproject.
	if test -d "$srcdir/../libtrap"; then
	TRAPINC='$(top_srcdir)/../libtrap/include'
	TRAPLIB='$(top_builddir)/../libtrap/src/.libs'
	fi
	# AC_SUBST command line variables from TRAPLIB and TRAPINC.
	if test -n "$TRAPLIB"; then
	AC_SUBST([TRAP_LTLIB], ["$TRAPLIB/libtrap.la"])
	AC_SUBST([TRAP_INCLUDE], ["-I$TRAPINC"])
	LDFLAGS="-L$TRAPLIB $LDFLAGS"
	CFLAGS="-I$TRAPINC $CFLAGS"
	CXXFLAGS="-I$TRAPINC $CXXFLAGS"
	fi
fi

if test -z "$UNIRECLIB"; then
	PKG_CHECK_MODULES([UNIREC], [unirec], [UNIRECLIB="yes"], AC_MSG_WARN([UNIREC was not found by pkg-config]))
	LDFLAGS="$UNIREC_LDFLAGS $LDFLAGS"
	LIBS="$UNIREC_LIBS $LIBS"
	CFLAGS="$UNIREC_CFLAGS $CFLAGS"
	CXXFLAGS="$UNIREC_CFLAGS $CXXFLAGS"
fi
# Still empty? Check for *installed* UNIREC.
if test -z "$UNIRECLIB"; then
	# Check for UNIREC toolkit as a superproject.
	if test -d "$srcdir/../unirec"; then
	UNIRECINC='$(top_srcdir)/../'
	UNIRECLIB='$(top_builddir)/../unirec'
	fi
	# AC_SUBST command line variables from UNIRECLIB and UNIRECINC.
	if test -n "$UNIRECLIB"; then
	AC_SUBST([UNIREC_LTLIB], ["$UNIRECLIB/libunirec.la"])
	AC_SUBST([UNIREC_INCLUDE], ["-I$UNIRECINC"])
	LDFLAGS="-L$UNIRECLIB  $LDFLAGS"
	CFLAGS="-I$UNIRECINC $CFLAGS"
	CXXFLAGS="-I$UNIRECINC $CXXFLAGS"
	fi
fi

if test -z "$NEMEACOMMONLIB"; then
	PKG_CHECK_MODULES([NEMEACOMMON], [nemea-common], [NEMEACOMMONLIB="yes"], AC_MSG_WARN([Nemea-common was not found by pkg-config]))
	LDFLAGS="$NEMEACOMMON_LDFLAGS $LDFLAGS"
	LIBS="$NEMEACOMMON_LIBS $LIBS"
	CFLAGS="$NEMEACOMMON_CFLAGS $CFLAGS"
	CXXFLAGS="$NEMEACOMMON_CFLAGS $CXXFLAGS"
fi
if test -z "$NEMEACOMMONLIB"; then
	# Check for NEMEACOMMON toolkit as a superproject.
	if test -d "$srcdir/../common"; then
	NEMEACOMMONINC='$(top_srcdir)/../common/include'
	NEMEACOMMONLIB='$(top_builddir)/../common'
	fi
	# AC_SUBST command line variables from NEMEACOMMONLIB and NEMEACOMMONINC.
	if test -n "$NEMEACOMMONLIB"; then
	AC_SUBST([NEMEACOMMON_LTLIB], ["$NEMEACOMMONLIB/libnemea-common.la"])
	AC_SUBST([NEMEACOMMON_INCLUDE], ["-I$NEMEACOMMONINC"])
	LDFLAGS="-L$NEMEACOMMONLIB $LDFLAGS"
	CFLAGS="-I$NEMEACOMMONINC $CFLAGS"
	CXXFLAGS="-I$NEMEACOMMONINC $CXXFLAGS"
	fi
fi

AC_CHECK_HEADER(idna.h,
         AC_CHECK_LIB(idn, stringprep_check_version, [libidn=yes], AC_MSG_WARN([libidn not found. The ipdetect module form blacklistfilter will not be compiled.])), AC_MSG_WARN([libidn.h not found. Blacklistfilter modules will not be compiled.]))

AM_CONDITIONAL(HAVE_LIBIDN, test x${libidn} = xyes)

# Checks for libraries.

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
                 anonymizer/Makefile
                 astute/Makefile
                 attack_gen/Makefile
                 basic2collector/Makefile
                 blacklistfilter/Makefile
                 blacklistfilter/dnsdetect/Makefile
                 blacklistfilter/ipdetect/Makefile
                 blacklistfilter/urldetect/Makefile
                 deduplication/Makefile
                 delaybuffer/Makefile
                 dns_amp_twente/Makefile
                 dns_amplification/Makefile
                 entropy_module/Makefile
                 example/Makefile
                 flow_gen/Makefile
                 flow_meter/Makefile
                 flow_sanity_check/Makefile
                 flowcounter/Makefile
                 flowdirection/Makefile
                 heartbleed_detector/Makefile
                 hoststatsnemea/Makefile
                 ipspoofingdetector/Makefile
                 ipv6stats/Makefile
                 logger/Makefile
                 logreplay/Makefile
                 merger/Makefile
                 nemea-modules.spec
                 nfreader/Makefile
                 p2pbotnet_detection/Makefile
                 pca/Makefile
                 portscan_detector/Makefile
                 protocolcounters/Makefile
                 simplebotnetdetector/Makefile
                 synflood/pcf/Makefile
                 synflood/synfindiff/Makefile
                 synflood/synrate/Makefile
                 test_threads/Makefile
                 timestamp_checker/Makefile
                 traffic_merger/Makefile
                 traffic_repeater/Makefile
                 transitfilter/Makefile
                 trapdump/Makefile
                 trapreplay/Makefile
		   p2pdetector/Makefile
		   tunnel_detection/Makefile
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
echo "Compilation............: make (or gmake)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  CXXFLAGS.............: $CXXFLAGS"
echo "  LDFLAGS..............: $LDFLAGS"
echo "  LIBS.................: $LIBS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo "Subdirs................: $ENABLEDTESTS"
echo

