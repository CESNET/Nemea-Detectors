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
  PKG_CHECK_MODULES([libtrap],[libtrap], [TRAPLIB="yes"], [
    # AC_MSG_WARN([libtrap was not found by pkg-config])
    AC_MSG_CHECKING([for libtrap in parent directory])
    # Check for TRAP toolkit as a superproject.
    if test -d "$srcdir/../libtrap"; then
      TRAPINC='$(top_srcdir)/../libtrap/include'
      TRAPLIB='$(top_builddir)/../libtrap/src/.libs'
    elif test -d "$srcdir/../../libtrap"; then
      TRAPINC='$(top_srcdir)/../../libtrap/include'
      TRAPLIB='$(top_builddir)/../../libtrap/src/.libs'
    fi
    # AC_SUBST command line variables from TRAPLIB and TRAPINC.
    if test -n "$TRAPLIB"; then
      AC_SUBST([TRAP_LTLIB], ["$TRAPLIB/libtrap.la"])
      AC_SUBST([TRAP_INCLUDE], ["-I$TRAPINC"])
      LDFLAGS="-L$TRAPLIB $LDFLAGS"
      CFLAGS="-I$TRAPINC $CFLAGS"
      CXXFLAGS="-I$TRAPINC $CXXFLAGS"
      AC_MSG_RESULT([yes])
    else
      AC_MSG_RESULT([no])
    fi
  ])
  if test -n "$TRAPLIB"; then
    LDFLAGS="$libtrap_LDFLAGS $LDFLAGS"
    LIBS="$libtrap_LIBS $LIBS"
    CFLAGS="$libtrap_CFLAGS $CFLAGS"
    CXXFLAGS="$libtrap_CFLAGS $CXXFLAGS"
  else
    AC_MSG_ERROR([Libtrap was not found.])
  fi
])

