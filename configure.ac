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
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])

# Checks for libraries.
AC_CHECK_LIB([trap], [trap_init])

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
