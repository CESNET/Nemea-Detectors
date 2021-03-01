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
  NEMEACOMMONLIB=""
  if test "${repobuild}" = "false"; then
    # find installed library:
    PKG_CHECK_MODULES([nemeacommon], [nemea-common], [NEMEACOMMONLIB="yes"])
  fi
  if test "${NEMEACOMMONLIB}" != "yes"; then
    # repobuild
    AC_MSG_CHECKING([for nemea-common in parent directory])
    if test -d "${srcdir}/../common"; then
      NEMEACOMMONINC='${top_srcdir}/../common/include'
      NEMEACOMMONLIB='${top_builddir}/../common/.libs'
    elif test -d "${srcdir}/../../common"; then
      NEMEACOMMONINC='${srcdir}/../../common/include'
      NEMEACOMMONLIB='${top_builddir}/../../common/.libs'
    elif test -d "${srcdir}/nemea-framework/common"; then
      NEMEACOMMONINC='${top_srcdir}/nemea-framework/common/include'
      NEMEACOMMONLIB='${top_builddir}/nemea-framework/common/.libs'
    elif test -d "${srcdir}/../nemea-framework/common"; then
      NEMEACOMMONINC='$(top_srcdir)/../nemea-framework/common/include'
      NEMEACOMMONLIB='$(top_builddir)/../nemea-framework/common/.libs'
    fi
    if test -n "$NEMEACOMMONLIB"; then
      nemeacommon_LIBS="-L$NEMEACOMMONLIB"
      nemeacommon_CFLAGS="-I$NEMEACOMMONINC"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
      NEMEACOMMONLIB=""
      PKG_CHECK_MODULES([nemeacommon], [nemea-common], [NEMEACOMMONLIB="yes"])
    fi
  fi
  if test -n "$NEMEACOMMONLIB"; then
    LDFLAGS="$nemeacommon_LDFLAGS $LDFLAGS"
    LIBS="$nemeacommon_LIBS $LIBS"
    CFLAGS="$nemeacommon_CFLAGS $CFLAGS"
    CXXFLAGS="$nemeacommon_CFLAGS $CXXFLAGS"
  else
    AC_MSG_ERROR([nemea-common was not found.])
  fi
])

