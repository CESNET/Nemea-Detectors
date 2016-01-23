dnl Copyright (C) 2013,2014 CESNET
dnl
dnl LICENSE TERMS
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl 1. Redistributions of source code must retain the above copyright
dnl    notice, this list of conditions and the following disclaimer.
dnl 2. Redistributions in binary form must reproduce the above copyright
dnl    notice, this list of conditions and the following disclaimer in
dnl    the documentation and/or other materials provided with the
dnl    distribution.
dnl 3. Neither the name of the Company nor the names of its contributors
dnl    may be used to endorse or promote products derived from this
dnl    software without specific prior written permission.
dnl
dnl ALTERNATIVELY, provided that this notice is retained in full, this
dnl product may be distributed under the terms of the GNU General Public
dnl License (GPL) version 2 or later, in which case the provisions
dnl of the GPL apply INSTEAD OF those given above.
dnl
dnl This software is provided ``as is'', and any express or implied
dnl warranties, including, but not limited to, the implied warranties of
dnl merchantability and fitness for a particular purpose are disclaimed.
dnl In no event shall the company or contributors be liable for any
dnl direct, indirect, incidental, special, exemplary, or consequential
dnl damages (including, but not limited to, procurement of substitute
dnl goods or services; loss of use, data, or profits; or business
dnl interruption) however caused and on any theory of liability, whether
dnl in contract, strict liability, or tort (including negligence or
dnl otherwise) arising in any way out of the use of this software, even
dnl if advised of the possibility of such damage.

AC_DEFUN([UNIREC_PATH],[
if test "x$repobuild" = "xtrue"; then
AC_PATH_PROG(UNIRECPROC, ur_processor.sh, [],
    [$PWD/../unirec$PATH_SEPARATOR$PATH])
else
AC_PATH_PROG(UNIRECPROC, ur_processor.sh, [],
    [$PATH$PATH_SEPARATOR/usr/bin/nemea$PATH_SEPARATOR$PWD/../unirec$PATH_SEPARATOR])
fi

if test -z "$UNIRECPROC"; then
    AC_MSG_ERROR([UniRec processor was not found. Add path to "unirec_generate_fields_files.py" into PATH or install UniRec."])
fi

AC_SUBST(UNIRECPROC)
])

