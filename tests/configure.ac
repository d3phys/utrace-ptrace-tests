dnl Process this file with autoconf to produce a configure script.
dnl This software is provided 'as-is', without any express or implied
dnl warranty.  In no event will the authors be held liable for any damages
dnl arising from the use of this software.
dnl
dnl Permission is granted to anyone to use this software for any purpose,
dnl including commercial applications, and to alter it and redistribute it
dnl freely.

AC_PREREQ(2.59)
AC_INIT([ptrace regression test suite], [0.1],
        [utrace-devel@redhat.com], [ptrace-tests])
AC_CONFIG_SRCDIR(attach-sigcont-wait.c)
AC_CONFIG_AUX_DIR([../config])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AM_PROG_CC_C_O
AC_GNU_SOURCE

m4_include([../config/biarch.m4])
utrace_BIARCH
# `$utrace_biarch' will be `-m64' even on an uniarch i386 machine.
AS_IF([test $utrace_cv_cc_biarch = yes],
      [CC_BIARCH="$CC $utrace_biarch"],
      [CC_BIARCH="$CC"])
AC_SUBST([CC_BIARCH])

AC_SYS_LARGEFILE

AC_OUTPUT
