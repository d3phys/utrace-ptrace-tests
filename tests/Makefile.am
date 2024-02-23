# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely.

SAFE = ptrace-on-job-control-stopped		\
       attach-wait-on-stopped			\
       detach-can-signal			\
       attach-into-signal			\
       attach-sigcont-wait			\
       attach-sigcont-wait-3x			\
       sa-resethand-on-cont-signal		\
       ptrace_cont-defeats-sigblock		\
       ptrace-cont-sigstop-detach		\
       ptrace_event_clone			\
       tif-syscall-trace-after-detach		\
       event-exit-proc-maps			\
       event-exit-proc-environ			\
       x86_64-ia32-gs				\
       x86_64-gsbase				\
       powerpc-altivec				\
       peekpokeusr				\
       watchpoint				\
       block-step				\
       step-jump-cont				\
       step-jump-cont-strict			\
       ppc-dabr-race				\
       signal-loss				\
       step-into-handler			\
       step-into-handler-cont			\
       user-area-access				\
       user-regs-peekpoke			\
       erestartsys				\
       erestartsys-debugger			\
       step-to-breakpoint			\
       syscall-reset				\
       reparent-zombie				\
       step-simple				\
       step-through-sigret			\
       stop-attach-then-wait			\
       detach-stopped				\
       detach-stopped-rhel5			\
       clone-multi-ptrace			\
       clone-ptrace				\
       o_tracevfork				\
       o_tracevforkdone				\
       detach-parting-signal			\
       detach-sigkill-race			\
       waitpid-double-report			\
       o_tracevfork-parent			\
       stopped-detach-sleeping			\
       stopped-detach-sleeping-3x		\
       stopped-attach-transparency		\
       erestartsys-trap				\
       highmem-debugger				\
       sigint-before-syscall-exit		\
       syscall-from-clone step-from-clone	\
       step-fork				\
       erestartsys-trap-debugger		\
       erestartsys-trap-32fails-debugger	\
       state-tracing-stop			\
       step-detach				\
       watchpoint-zeroaddr			\
       bogus-echild				\
       eintr-on-attach				\
       fpregs-smp				\
       ret-to-nxpage				\
       pid-namespace				\
       restart_block				\
       watchpoint-32bit				\
       aarch64-watchpoint			\
       watchpoint-step

# These tests will crash the machine if it is still buggy.
CRASHERS = late-ptrace-may-attach-check		\
	   tracer-lockup-on-sighandler-kill	\
	   clone-get-signal			\
	   ppc-ptrace-exec-full-regs		\
	   x86_64-cs				\
	   user-area-padding			\
	   reparent-zombie-clone

BUILT_SOURCES = erestartsys-debuggee highmem-debuggee \
		erestartsys-trap-debuggee erestartsys-trap-32fails-debuggee
EXTRA_DIST = erestartsys-debuggee.c highmem-debuggee.c \
	     erestartsys-trap-debuggee.c erestartsys-trap-32fails-debuggee.c

clean-local:
	$(RM) erestartsys-debuggee highmem-debuggee \
	erestartsys-trap-debuggee erestartsys-trap-32fails-debuggee

# Substitute $(COMPILE).
erestartsys-debuggee: erestartsys-debuggee.c
	$(CC_BIARCH) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
		     $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

highmem-debuggee: highmem-debuggee.c
	$(CC_BIARCH) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
		     $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

erestartsys-trap-debuggee: erestartsys-trap-debuggee.c
	$(CC_BIARCH) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
		     $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

erestartsys-trap-32fails-debuggee: erestartsys-trap-32fails-debuggee.c
	$(CC_BIARCH) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
		     $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -o $@ $<

# Build all the test programs in "make all", since they are all we build.
noinst_PROGRAMS = $(SAFE) $(CRASHERS)

# Some distros use -D_FORTIFY_SOURCE=2 by default so we try to be compatible.
# FIXME: -fno-strict-aliasing
AM_CFLAGS = -std=gnu99 -Wall -Werror -D_FORTIFY_SOURCE=2 -fno-strict-aliasing

x86_64_ia32_gs_LDFLAGS = -lpthread
late_ptrace_may_attach_check_LDFLAGS = -lpthread
ppc_dabr_race_LDFLAGS = -lpthread
erestartsys_LDFLAGS = -lutil
erestartsys_debugger_LDFLAGS = -lutil
reparent_zombie_LDFLAGS = -lpthread
reparent_zombie_clone_LDFLAGS = -lpthread
detach_stopped_LDFLAGS = -lpthread
detach_stopped_rhel5_LDFLAGS = -lpthread
stopped_attach_transparency_LDFLAGS = -lpthread
erestartsys_trap_LDFLAGS = -lutil
erestartsys_trap_debugger_LDFLAGS = -lutil
erestartsys_trap_32fails_debugger_LDFLAGS = -lutil
# After clone syscall it must call no glibc code (such as _dl_runtime_resolve).
clone_get_signal_LDFLAGS = -Wl,-z,now
clone_multi_ptrace_LDFLAGS = -Wl,-z,now
clone_ptrace_LDFLAGS = -Wl,-z,now
detach_sigkill_race_LDFLAGS = -Wl,-z,now
ptrace_event_clone_LDFLAGS = -Wl,-z,now

check_TESTS = $(SAFE)
xcheck_TESTS = $(CRASHERS)
XFAIL_TESTS = restart_block

TESTS = $(check_TESTS)

.PHONY: xcheck
xcheck:
	@$(MAKE) TESTS='$$(xcheck_TESTS)' check
