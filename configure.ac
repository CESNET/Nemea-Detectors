#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-detectors], [1.7.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([hoststatsnemea/src/hoststatserv.cpp])
AC_CONFIG_HEADERS([config.h])
RELEASE=1
AC_SUBST(RELEASE)
USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`
AC_SUBST(USERNAME)
AC_SUBST(USERMAIL)
AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects])
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])
# Must be checked before default -g -O2 is set:
AC_ARG_ENABLE([debug],
        AC_HELP_STRING([--enable-debug],
        [Enable build with debug symbols and without optimizations.]),
        [if test "$enableval" = "yes"; then
                CFLAGS="-Wall -g -O0 $CFLAGS"
                CXXFLAGS="-Wall -g -O0 $CXXFLAGS"
        fi], [CFLAGS="-Wall -g -O3 $CFLAGS"
              CXXFLAGS="-Wall -g -O3 $CXXFLAGS"
              CPPFLAGS="-DNDEBUG=1 $CPPFLAGS"])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

LT_INIT()

pkgdatadir=${datadir}/nemea
PKGDATADIR=$(eval echo $(eval echo ${pkgdatadir}))
AC_SUBST(PKGDATADIR)
AC_SUBST(pkgdatadir)
waidetectordatadir=${pkgdatadir}/wai_detector
WAIDETECTORDATADIR=$(eval echo $(eval echo ${waidetectordatadir}))
AC_SUBST(WAIDETECTORDATADIR)
AC_DEFINE_DIR(PKGDATADIR, [pkgdatadir], [Path to configuration files])
AC_DEFINE_DIR(SYSCONFDIR, [sysconfdir], [Path to configuration files])

blacklistfilterdir=${sysconfdir}/blacklistfilter
BLACKLISTFILTERDIR=$(eval echo $(eval echo ${blacklistfilterdir}))
AC_SUBST(BLACKLISTFILTERDIR)
AC_SUBST(blacklistfilterdir)
AC_DEFINE_DIR(BLACKLISTFILTERDIR, [blacklistfilterdir], [Path to configuration files of blacklistfilter])

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_PROG(PYTHON, python3, python3, [""])
AC_SUBST(PYTHON)
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])
AC_CHECK_PROG(DEBUILD, debuild, debuild, [""])
AX_PTHREAD([LIBS="$PTHREAD_LIBS $LIBS"
    CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
    CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"],
    [AC_MSG_ERROR([pthread not found])])

AC_ARG_ENABLE(repobuild, AS_HELP_STRING([--enable-repobuild],
		[enable local compilation without system installed NEMEA libraries, default: no]),
[case "${enableval}" in
	yes) repobuild=true ;;
	no)  repobuild=false ;;
	*)   AC_MSG_ERROR([bad value ${enableval} for --enable-repobuild]) ;;
esac], [repobuild=false])

AX_LIBTRAP_CHECK
AX_UNIREC_CHECK
AX_NEMEACOMMON_CHECK

AC_CHECK_HEADER(idna.h,
         AC_CHECK_LIB(idn, stringprep_check_version, [libidn=yes], AC_MSG_WARN([libidn not found. The ipdetect module from blacklistfilter will not be compiled.])), AC_MSG_WARN([libidn.h not found. Blacklistfilter modules will not be compiled.]))

AM_CONDITIONAL(HAVE_LIBIDN, test x${libidn} = xyes)

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h sys/socket.h sys/time.h syslog.h unistd.h])

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

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_STRTOD
AC_CHECK_FUNCS([alarm clock_gettime floor gettimeofday localeconv memset regcomp setlocale sqrt strchr strdup strerror strstr strtol strtoul strtoull])

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
AM_CONDITIONAL(MAKE_DEB, test x$DEBUILD != x)

# list of all *.in (and Makefile.am) files to process by configure script
AC_CONFIG_FILES([Makefile
                 backscatter_classifier/Makefile
                 blacklistfilter/Makefile
                 blacklistfilter/blacklist_downloader/bl_downloader.py
                 blacklistfilter/adaptive_filter/Makefile
                 blacklistfilter/adaptive_filter/adaptive_filter
                 blacklistfilter/adaptive_filter/adaptive_filter_files/Makefile
                 brute_force_detector/Makefile
                 ddos_detector/Makefile 
                 amplification_detection/Makefile
                 hoststatsnemea/Makefile
                 hoststatsnemea/src/Makefile
                 haddrscan_detector/Makefile
                 miner_detector/Makefile
                 sip_bf_detector/Makefile
                 smtp_spam_detector/Makefile
                 smtp_spam_detector/smtp_spam_detector
                 smtp_spam_detector/smtp_spam_detector_files/Makefile
                 tunnel_detection/Makefile
                 voip_fraud_detection/Makefile
                 vportscan_detector/Makefile
                 waintrusion_detector/Makefile
                 waintrusion_detector/waintrusion_detector.py
                 nemea-detectors.spec
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

