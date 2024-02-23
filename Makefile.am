# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely.

ACLOCAL_AMFLAGS = -I config

SUBDIRS = $(subdirs)
DIST_SUBDIRS = tests

EXTRA_DIST = bootstrap.sh \
	     biarch-tests/configure.ac biarch-tests/configure \
	     biarch-tests/Makefile.am biarch-tests/Makefile.in \
	     biarch-tests/aclocal.m4

PHONY = xcheck
xcheck:
	@$(MAKE) TESTS='$$(xcheck_TESTS)' check

PHONY += native-check native-xcheck
native-check:
	$(MAKE) -C native-tests check
native-xcheck:
	$(MAKE) -C native-tests xcheck

if BIARCH
PHONY += biarch-check biarch-xcheck
biarch-check:
	$(MAKE) -C biarch-tests check
biarch-xcheck:
	$(MAKE) -C biarch-tests xcheck
endif

.PHONY: $(PHONY)

if BIARCH
distclean-local:
	$(MAKE) -C biarch-tests distclean
endif
