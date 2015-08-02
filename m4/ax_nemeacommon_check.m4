dnl @synopsis AX_NEMEACOMMON_CHECK
dnl
dnl This macro test if libtrap is installed or if it is
dnl in parent directory.  It sets CFLAGS, CXXFLAGS, LDFLAGS,
dnl LIBS if libtrap is found.  Otherwise, error is returned.
dnl
dnl @category InstalledPackages
dnl @author Tomas Cejka <cejkat@cesnet.cz>
dnl @version 2015-08-02
dnl @license BSD

AC_DEFUN([AX_NEMEACOMMON_CHECK], [
  PKG_CHECK_MODULES([nemeacommon], [nemea-common], [NEMEACOMMONLIB="yes"], [
    # AC_MSG_WARN([nemea-common was not found by pkg-config])
    AC_MSG_CHECKING([for nemea-common in parent directory])
    # Check for nemea-common as a superproject.
    if test -d "$srcdir/../common"; then
      NEMEACOMMONINC='$(top_srcdir)/../common/include'
      NEMEACOMMONLIB='$(top_builddir)/../common'
    elif test -d "$srcdir/../../libtrap"; then
      NEMEACOMMONINC='$(top_srcdir)/../../common/include'
      NEMEACOMMONLIB='$(top_builddir)/../../common'
    fi
    if test -n "$NEMEACOMMONLIB"; then
      AC_SUBST([NEMEACOMMON_LTLIB], ["$NEMEACOMMONLIB/libnemea-common.la"])
      AC_SUBST([NEMEACOMMON_INCLUDE], ["-I$NEMEACOMMONINC"])
      LDFLAGS="-L$NEMEACOMMONLIB $LDFLAGS"
      CFLAGS="-I$NEMEACOMMONINC $CFLAGS"
      CXXFLAGS="-I$NEMEACOMMONINC $CXXFLAGS"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  ])
  if test -n "$NEMEACOMMONLIB"; then
    LDFLAGS="$nemeacommon_LDFLAGS $LDFLAGS"
    LIBS="$nemeacommon_LIBS $LIBS"
    CFLAGS="$nemeacommon_CFLAGS $CFLAGS"
    CXXFLAGS="$nemeacommon_CFLAGS $CXXFLAGS"
  else
    AC_MSG_ERROR([nemea-common was not found.])
  fi
])

