/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.
   
   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Reproducibility according to Roland McGrath (approx. cite):
   maybe only ever bit ppc64 on >2.6.22,
   bit only ppc32 kernels (with just nonfatal dmesg/syslog noise) before that.
   however, if i were to update the 2.6.22/2.6.18 backports of the powerpc
   regset code, it would reintroduce the BUG_ON and triggers without the fix.
   */

#define _GNU_SOURCE 1
#ifdef __ia64__
#define ia64_fpreg ia64_fpreg_DISABLE
#define pt_all_user_regs pt_all_user_regs_DISABLE
#endif	/* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
#undef ia64_fpreg
#undef pt_all_user_regs
#endif	/* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
#include <sys/debugreg.h>
#endif

#include <stddef.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <error.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/types.h>

/* On RHEL-4 it is present only in <linux/ptrace.h> in
   /lib/modules/`uname -r`/{build,source}.  */
#ifndef PTRACE_SETOPTIONS
#define PTRACE_SETOPTIONS	0x4200
#endif
#ifndef PTRACE_O_TRACEEXEC
#define PTRACE_O_TRACEEXEC	0x00000010
#endif
#ifndef PTRACE_EVENT_EXEC
#define PTRACE_EVENT_EXEC	4
#endif

int
main (void)
{
  pid_t child = fork ();
  if (child == 0)
    {
      ptrace (PTRACE_TRACEME);
      raise (SIGTERM);
      execl ("/bin/true", "true", NULL);
      _exit (127);
    }
  else
    {
      int status;
      if (waitpid (child, &status, 0) != child)
	error (1, errno, "waitpid");
      if (!WIFSTOPPED (status) || WSTOPSIG (status) != SIGTERM)
	error (1, 0, "first status %x", status);
      if (ptrace (PTRACE_SETOPTIONS, child, 0L, PTRACE_O_TRACEEXEC) != 0)
	error (1, errno, "PTRACE_SETOPTIONS");
      if (ptrace (PTRACE_CONT, child, 0L, 0L) != 0)
	error (1, errno, "PTRACE_CONT");
      if (waitpid (child, &status, 0) != child)
	error (1, errno, "waitpid");
      if (!WIFSTOPPED (status)
	  || (status >> 8) != (SIGTRAP | (PTRACE_EVENT_EXEC<<8)))
	error (1, 0, "second status %x", status);
#if 0
      error (0, 0, "gpr0 value %lx", ptrace (PTRACE_PEEKUSER, child, 0L, 0L));
#endif
      if (ptrace (PTRACE_CONT, child, 0L, 0L) != 0)
	error (1, errno, "PTRACE_CONT");
      if (waitpid (child, &status, 0) != child)
	error (1, errno, "waitpid");
      if (!WIFEXITED (status) || WEXITSTATUS (status) != 0)
	error (2, 0, "third status %x", status);
    }
  return 0;
}
