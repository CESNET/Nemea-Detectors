#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([tunnel_detection_dns], [1.0.0], [rosazden@fit.cvut.cz])
AC_CONFIG_SRCDIR([tunnel_detection_dns.c])
AM_INIT_AUTOMAKE([-Wall])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-ltrap':
AC_CHECK_LIB([trap], [main])
# FIXME: Replace `main' with a function in `-lunirec':
AC_CHECK_LIB([unirec], [main])
# Checks for library nemea-common
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

# Checks for header files.
AC_CHECK_HEADERS([inttypes.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_CHECK_FUNCS([memmove memset mkdir])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
