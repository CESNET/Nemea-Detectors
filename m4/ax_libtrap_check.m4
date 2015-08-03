dnl @synopsis AX_LIBTRAP_CHECK
dnl
dnl This macro test if libtrap is installed or if it is
dnl in parent directory.  It sets CFLAGS, CXXFLAGS, LDFLAGS,
dnl LIBS if libtrap is found.  Otherwise, error is returned.
dnl
dnl @category InstalledPackages
dnl @author Tomas Cejka <cejkat@cesnet.cz>
dnl @version 2015-08-02
dnl @license BSD

AC_DEFUN([AX_LIBTRAP_CHECK], [
  TRAPLIB=""
  if test "${repobuild}" = "false"; then
  echo "do pkgconfig"
    PKG_CHECK_MODULES([libtrap], [libtrap], [TRAPLIB="yes"])
  fi
  if test "${TRAPLIB}" != "yes"; then
    # repobuild 
    AC_MSG_CHECKING([for libtrap in parent directory])
    if test -d "$srcdir/../libtrap"; then
      TRAPINC='$(top_srcdir)/../libtrap/include'
      TRAPLIB='$(top_builddir)/../libtrap/src/.libs'
    elif test -d "$srcdir/../../libtrap"; then
      TRAPINC='$(top_srcdir)/../../libtrap/include'
      TRAPLIB='$(top_builddir)/../../libtrap/src/.libs'
    fi
    if test -n "$TRAPLIB"; then
      libtrap_LDFLAGS="-L${TRAPLIB}"
      libtrap_CFLAGS="-I${TRAPINC}"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
      TRAPLIB=""
    fi
  fi
  if test -n "$TRAPLIB"; then
    LDFLAGS="$libtrap_LDFLAGS $LDFLAGS"
    LIBS="$libtrap_LIBS $LIBS"
    CFLAGS="$libtrap_CFLAGS $CFLAGS"
    CXXFLAGS="$libtrap_CFLAGS $CXXFLAGS"
  else
    AC_MSG_ERROR([Libtrap was not found.])
  fi
])

