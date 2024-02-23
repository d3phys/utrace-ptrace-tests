/* Test case for PTRACE_PEEKUSR/PTRACE_POKEUSR bugs.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

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

#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <error.h>

#if defined __x86_64__ || defined __i386__
# define CANPOKE(a)	(a < sizeof (struct user_regs_struct)		   \
			 || (a >= offsetof (struct user, u_debugreg[0])	   \
			     && (a < offsetof (struct user, u_debugreg[4]) \
				 || a > offsetof (struct user, u_debugreg[5]))))

#elif defined __powerpc__
# define CANPOKE(a)	(a <= PT_CCR * sizeof (long))
#elif defined __sparc__		/* Dummy PTRACE_PEEKUSR, no PTRACE_POKEUSR.  */
# define MAX_PEEKUSR	sizeof (long)
# define CANPOKE(addr)	0
#elif defined __ia64__
# include <asm/ptrace_offsets.h>
# define MAX_PEEKUSR	PT_AR_CSD
/* GDB also does not touch PT_AR_UNAT..PT_AR_BSPSTORE and PT_AR_CCV..PT_AR_FPSR
   (everything inclusive) but it can be read/written.  */
# define VALID(a)	(a < PT_NAT_BITS				\
			 || (a >= PT_NAT_BITS + 0x10 && a <= PT_R7)	\
			 || (a >= PT_B1 && a < PT_AR_EC)		\
			 || a >= PT_CR_IPSR)
/* CANPOKE zero has no effect on the accessible VALID ranges.  */
#elif defined __aarch64__
/* aarch64 does not support PTRACE_PEEKUSER, it has PTRACE_GETREGSET.  */
# define MAX_PEEKUSR 0
#endif

#ifndef MAX_PEEKUSR
# define MAX_PEEKUSR	sizeof (struct user)
#endif
#ifndef VALID
# define VALID(addr)	1
#endif
#ifndef CANPOKE
# define CANPOKE(addr)	1
#endif

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

int
main (void)
{
  pid_t got_pid;
  int status;
  long l, addr, val;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
      case -1:
        assert (0);
      case 0:
	l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
	assert (l == 0);

	status = raise (SIGUSR1);
	assert (status == 0);

	/* NOTREACHED */
	assert (0);
      default:
        break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  status = 0;
  for (addr = 0; addr < MAX_PEEKUSR; addr += sizeof (long))
    {
      if (!VALID (addr))
        continue;
      errno = 0;
      val = ptrace (PTRACE_PEEKUSER, child, addr, 0l);
      if (val == -1l && errno != 0)
	{
	  status = 1;
	  error (0, errno, "PTRACE_PEEKUSR at %#lx", addr);
	}
      else if (CANPOKE (addr))
	{
	  l = ptrace (PTRACE_POKEUSER, child, addr, val);
	  if (l == -1l)
	    {
	      status = 1;
	      error (0, errno, "PTRACE_POKEUSR at %#lx: %#lx", addr, val);
	    }
	}
    }

  return addr == 0 ? 77 : status;
}
