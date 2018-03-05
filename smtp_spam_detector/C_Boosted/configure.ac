#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([detection_example], [1.0.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([smtp_spam.c])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign silent-rules subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

AX_LIBTRAP_CHECK
AX_UNIREC_CHECK
AX_NEMEACOMMON_CHECK

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
TRAPLIB=""
PKG_CHECK_MODULES([libtrap], [libtrap], [TRAPLIB="yes"])
if test -n "$TRAPLIB"; then
  LDFLAGS="$libtrap_LDFLAGS $LDFLAGS"
  LIBS="$libtrap_LIBS $LIBS"
  CFLAGS="$libtrap_CFLAGS $CFLAGS"
  CXXFLAGS="$libtrap_CFLAGS $CXXFLAGS"
else
  AC_MSG_ERROR([Libtrap was not found.])
fi

UNIRECLIB=""
PKG_CHECK_MODULES([unirec], [unirec], [UNIRECLIB="yes"])
if test -n "$UNIRECLIB"; then
  LDFLAGS="$unirec_LDFLAGS $LDFLAGS"
  LIBS="$unirec_LIBS $LIBS"
  CFLAGS="$unirec_CFLAGS $CFLAGS"
  CXXFLAGS="$unirec_CFLAGS $CXXFLAGS"
else
  AC_MSG_ERROR([unirec was not found.])
fi

AC_PATH_PROG(UNIRECPROC, ur_processor.sh, [], [/usr/bin/nemea/$PATH_SEPARATOR$PATH])
AC_SUBST(UNIRECPROC)

## If nemea-common is needed, uncomment the following code:
#NEMEACOMMONLIB=""
#PKG_CHECK_MODULES([nemeacommon], [nemea-common], [NEMEACOMMONLIB="yes"])
#if test -n "$NEMEACOMMONLIB"; then
# LDFLAGS="$nemeacommon_LDFLAGS $LDFLAGS"
# LIBS="$nemeacommon_LIBS $LIBS"
# CFLAGS="$nemeacommon_CFLAGS $CFLAGS"
# CXXFLAGS="$nemeacommon_CFLAGS $CXXFLAGS"
#else
# AC_MSG_ERROR([nemea-common was not found.])
#fi


# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
