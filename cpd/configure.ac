#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([nemea-cpd], [0.0.0], [traffic-analysis@cesnet.cz])
AC_CONFIG_SRCDIR([src/cpd_module.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])
RELEASE=1
AC_SUBST(RELEASE)
USERNAME=`git config --get user.name`
USERMAIL=`git config --get user.email`

AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
# Check for rpmbuild
AC_CHECK_PROG(RPMBUILD, rpmbuild, rpmbuild, [""])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [pow])
# FIXME: Replace `main' with a function in `-ltrap':
AC_CHECK_LIB([trap], [trap_init])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h string.h])

AC_ARG_ENABLE(openmp,
	AS_HELP_STRING([--disable-openmp],[ disable OpenMP]),
	[], [AC_CHECK_HEADERS([omp.h],
		[CFLAGS="$CFLAGS -fopenmp ";
		AC_CHECK_LIB(gomp, omp_get_num_procs)],
		[AC_MSG_ERROR(omp.h not found. please either install gcc version 4.2 or any later version or use the --disable-openmp options..)])
	])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset pow sqrt])

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 Doxyfile])
AC_SUBST(RPMBUILD)
if test -z "$RPMBUILD"; then
	AC_MSG_WARN([Due to missing rpmbuild you will not able to generate RPM package.])
fi

RPM_RELEASE=1
AC_SUBST(RPM_RELEASE)
AM_CONDITIONAL(MAKE_RPMS, test x$RPMBUILD != x)

DX_INIT_DOXYGEN([nemea-cpd], [Doxyfile], [doc])

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
echo
echo "Installation...........: make install (as root if needed, with 'su' or 'sudo')"
echo "  prefix...............: $prefix"
echo "Subdirs................: $ENABLEDTESTS"
echo

