#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([voip_fraud_detection], [1.0.0], [truxaluk@fit.cvut.cz])
AC_MSG_NOTICE([voip_fraud_detection module])

AC_CONFIG_SRCDIR([voip_fraud_detection.c])
AM_INIT_AUTOMAKE([-Wall])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Check for Trap.
AC_CHECK_LIB(trap, trap_ifcctl)

# Check for UniRec.
AC_CHECK_LIB(unirec, ur_create)

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h stdio.h stdarg.h string.h time.h unistd.h ctype.h signal.h])

# Checks for GeoIP support.
AC_CHECK_LIB(GeoIP,GeoIP_id_by_addr_gl,LIBGEOIP="yes",LIBGEOIP="no")
AC_CHECK_HEADERS(GeoIP.h,GEOIP_H="yes",GEOIP_H="no")
if test "$LIBGEOIP" == "yes" && test "$GEOIP_H" == "yes"; then
	# Enable GeoIP
	CFLAGS+=" -D ENABLE_GEOIP"
	LIBS+=" -lGeoIP"
else
	AC_MSG_ERROR([For detection of calling to different country need GeoIP!])
fi

# Checks for library nemea-common.
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

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile])

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
echo "Compilation............: make (or gmake)"
echo "  CPPFLAGS.............: $CPPFLAGS"
echo "  CFLAGS...............: $CFLAGS"
echo "  CXXFLAGS.............: $CXXFLAGS"
echo "  LDFLAGS..............: $LDFLAGS"
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo
