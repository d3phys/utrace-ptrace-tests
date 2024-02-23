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
AC_CONFIG_SRCDIR([tests/attach-sigcont-wait.c])
AC_CONFIG_AUX_DIR([config])
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip
 		  -Wall -Werror -Wno-portability])
AC_CONFIG_FILES([Makefile])

dnl The test programs have their own configure script so they can easily
dnl be built separately for cross-testing.
AC_CONFIG_SUBDIRS(tests)

# On a 64-bit host where can can use $CC -m32, we'll run two sets of tests.
# Likewise in a 32-bit build on a host where $CC -m64 works.
utrace_BIARCH
test $utrace_cv_cc_biarch = no || {
  AC_CONFIG_SUBDIRS(biarch-tests)
}

AC_OUTPUT
