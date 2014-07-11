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
