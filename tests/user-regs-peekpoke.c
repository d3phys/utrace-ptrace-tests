/* Test case for PTRACE_SETREGS modifying the requested ragisters.
   x86* counterpart of the s390* testcase `user-area-access.c'.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* FIXME: EFLAGS should be tested restricted on the appropriate bits.  */

#define _GNU_SOURCE 1

#if defined __powerpc__ || defined __sparc__
# define user_regs_struct pt_regs
#endif

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
#include <asm/unistd.h>

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <string.h>
#include <stddef.h>

/* ia64 has PTRACE_SETREGS but it has no USER_REGS_STRUCT.  */
#if !defined PTRACE_SETREGS || defined __ia64__

int
main (void)
{
  return 77;
}

#else	/* PTRACE_SETREGS */

/* The minimal alignment we use for the random access ranges.  */
#define REGALIGN (sizeof (long))

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
  signal (SIGABRT, SIG_DFL);
  abort ();
}

int
main (void)
{
  long l;
  int status, i;
  pid_t pid;
  union
    {
      struct user_regs_struct user;
      unsigned char byte[sizeof (struct user_regs_struct)];
    } u, u2;
  int start;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  signal (SIGINT, handler_fail);
  i = alarm (10);
  assert (i == 0);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);

    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      // Prevent rt_sigprocmask() call called by glibc after raise().
      syscall (__NR_tkill, getpid (), SIGSTOP);
      assert (0);

    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Fetch U2 from the inferior.  */
  errno = 0;
# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, &u2.user, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, &u2.user);
# endif
  assert_perror (errno);
  assert (l == 0);

  /* Initialize U with a pattern.  */
  for (i = 0; i < sizeof u.byte; i++)
    u.byte[i] = i;
#ifdef __x86_64__
  /* non-EFLAGS modifications fail with EIO,  EFLAGS gets back different.  */
  u.user.eflags = u2.user.eflags;
  u.user.cs = u2.user.cs;
  u.user.ds = u2.user.ds;
  u.user.es = u2.user.es;
  u.user.fs = u2.user.fs;
  u.user.gs = u2.user.gs;
  u.user.ss = u2.user.ss;
  u.user.fs_base = u2.user.fs_base;
  u.user.gs_base = u2.user.gs_base;
  /* RHEL-4 refuses to set too high (and invalid) PC values.  */
  u.user.rip = (unsigned long) handler_fail;
  /* 2.6.25 always truncates and sign-extends orig_rax.  */
  u.user.orig_rax = (int) u.user.orig_rax;
#endif	/* __x86_64__ */
#ifdef __i386__
  /* These values get back different.  */
  u.user.xds = u2.user.xds;
  u.user.xes = u2.user.xes;
  u.user.xfs = u2.user.xfs;
  u.user.xgs = u2.user.xgs;
  u.user.xcs = u2.user.xcs;
  u.user.eflags = u2.user.eflags;
  u.user.xss = u2.user.xss;
  /* RHEL-4 refuses to set too high (and invalid) PC values.  */
  u.user.eip = (unsigned long) handler_fail;
#endif	/* __i386__ */
#ifdef __powerpc__
  /* These fields are constrained.  */
  u.user.msr = u2.user.msr;
# ifdef __powerpc64__
  u.user.softe = u2.user.softe;
# else
  u.user.mq = u2.user.mq;
# endif	/* __powerpc64__ */
  u.user.trap = u2.user.trap;
  u.user.dar = u2.user.dar;
  u.user.dsisr = u2.user.dsisr;
  u.user.result = u2.user.result;
#endif	/* __powerpc__ */

  /* Poke U.  */
# ifdef __sparc__
  l = ptrace (PTRACE_SETREGS, child, &u.user, NULL);
# else
  l = ptrace (PTRACE_SETREGS, child, NULL, &u.user);
# endif
  assert (l == 0);

  /* Peek into U2.  */
# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, &u2.user, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, &u2.user);
# endif
  assert (l == 0);

  /* Verify it matches.  */
  if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
    {
      for (start = 0; start + REGALIGN <= sizeof u.byte; start += REGALIGN)
	if (*(unsigned long *) (u.byte + start)
	    != *(unsigned long *) (u2.byte + start))
	  printf ("\
mismatch at offset %#x: SETREGS wrote %lx GETREGS read %lx\n",
		  start, *(unsigned long *) (u.byte + start),
		  *(unsigned long *) (u2.byte + start));
      return 1;
    }

  /* Reverse the pattern.  */
  for (i = 0; i < sizeof u.byte; i++)
    u.byte[i] ^= -1;
#ifdef __x86_64__
  /* non-EFLAGS modifications fail with EIO,  EFLAGS gets back different.  */
  u.user.eflags = u2.user.eflags;
  u.user.cs = u2.user.cs;
  u.user.ds = u2.user.ds;
  u.user.es = u2.user.es;
  u.user.fs = u2.user.fs;
  u.user.gs = u2.user.gs;
  u.user.ss = u2.user.ss;
  u.user.fs_base = u2.user.fs_base;
  u.user.gs_base = u2.user.gs_base;
  /* RHEL-4 refuses to set too high (and invalid) PC values.  */
  u.user.rip = (unsigned long) handler_fail;
  /* 2.6.25 always truncates and sign-extends orig_rax.  */
  u.user.orig_rax = (int) u.user.orig_rax;
#endif	/* __x86_64__ */
#ifdef __i386__
  /* These values get back different.  */
  u.user.xds = u2.user.xds;
  u.user.xes = u2.user.xes;
  u.user.xfs = u2.user.xfs;
  u.user.xgs = u2.user.xgs;
  u.user.xcs = u2.user.xcs;
  u.user.eflags = u2.user.eflags;
  u.user.xss = u2.user.xss;
  /* RHEL-4 refuses to set too high (and invalid) PC values.  */
  u.user.eip = (unsigned long) handler_fail;
#endif	/* __i386__ */
#ifdef __powerpc__
  /* These fields are constrained.  */
  u.user.msr = u2.user.msr;
# ifdef __powerpc64__
  u.user.softe = u2.user.softe;
# else
  u.user.mq = u2.user.mq;
# endif	/* __powerpc64__ */
  u.user.trap = u2.user.trap;
  u.user.dar = u2.user.dar;
  u.user.dsisr = u2.user.dsisr;
  u.user.result = u2.user.result;
#endif	/* __powerpc__ */

  /* Poke U.  */
# ifdef __sparc__
  l = ptrace (PTRACE_SETREGS, child, &u.user, NULL);
# else
  l = ptrace (PTRACE_SETREGS, child, NULL, &u.user);
# endif
  assert (l == 0);

  /* Peek into U2.  */
# ifdef __sparc__
  l = ptrace (PTRACE_GETREGS, child, &u2.user, NULL);
# else
  l = ptrace (PTRACE_GETREGS, child, NULL, &u2.user);
# endif
  assert (l == 0);

  /* Verify it matches.  */
  if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
    {
      for (start = 0; start + REGALIGN <= sizeof u.byte; start += REGALIGN)
	if (*(unsigned long *) (u.byte + start)
	    != *(unsigned long *) (u2.byte + start))
	  printf ("\
mismatch at offset %#x: SETREGS wrote %lx GETREGS read %lx\n",
		  start, *(unsigned long *) (u.byte + start),
		  *(unsigned long *) (u2.byte + start));
      return 1;
    }

  /* Now try poking arbitrary ranges and verifying it reads back right.
     We expect the U area is already a random enough pattern.  */
  for (start = 0; start + REGALIGN <= sizeof u.byte; start += REGALIGN)
    {
      for (i = start; i < start + REGALIGN; i++)
	u.byte[i]++;
#ifdef __x86_64__
      /* non-EFLAGS modifications fail with EIO,  EFLAGS gets back different.  */
      u.user.eflags = u2.user.eflags;
      u.user.cs = u2.user.cs;
      u.user.ds = u2.user.ds;
      u.user.es = u2.user.es;
      u.user.fs = u2.user.fs;
      u.user.gs = u2.user.gs;
      u.user.ss = u2.user.ss;
      u.user.fs_base = u2.user.fs_base;
      u.user.gs_base = u2.user.gs_base;
      /* RHEL-4 refuses to set too high (and invalid) PC values.  */
      u.user.rip = (unsigned long) handler_fail;
      /* 2.6.25 always truncates and sign-extends orig_rax.  */
      u.user.orig_rax = (int) u.user.orig_rax;
#endif	/* __x86_64__ */
#ifdef __i386__
      /* These values get back different.  */
      u.user.xds = u2.user.xds;
      u.user.xes = u2.user.xes;
      u.user.xfs = u2.user.xfs;
      u.user.xgs = u2.user.xgs;
      u.user.xcs = u2.user.xcs;
      u.user.eflags = u2.user.eflags;
      u.user.xss = u2.user.xss;
      /* RHEL-4 refuses to set too high (and invalid) PC values.  */
      u.user.eip = (unsigned long) handler_fail;
#endif	/* __i386__ */
#ifdef __powerpc__
      /* These fields are constrained.  */
      u.user.msr = u2.user.msr;
# ifdef __powerpc64__
      u.user.softe = u2.user.softe;
# else
      u.user.mq = u2.user.mq;
# endif	/* __powerpc64__ */
      u.user.trap = u2.user.trap;
      u.user.dar = u2.user.dar;
      u.user.dsisr = u2.user.dsisr;
      u.user.result = u2.user.result;
      if (start > offsetof (struct pt_regs, ccr))
	break;
#endif	/* __powerpc__ */

      /* Poke U.  */
      l = ptrace (PTRACE_POKEUSER, child, (void *) (unsigned long) start,
		  (void *) *(unsigned long *) (u.byte + start));
      if (l != 0)
	error (1, errno, "PTRACE_POKEUSER at %x", start);

      /* Peek into U2.  */
# ifdef __sparc__
      l = ptrace (PTRACE_GETREGS, child, &u2.user, NULL);
# else
      l = ptrace (PTRACE_GETREGS, child, NULL, &u2.user);
# endif
      assert (l == 0);

      /* Verify it matches.  */
      if (memcmp (&u.user, &u2.user, sizeof u.byte) != 0)
	{
	  printf ("mismatch at offset %#x: poked %lx but GETREGS read %lx\n",
		  start, *(unsigned long *) (u.byte + start),
		  *(unsigned long *) (u2.byte + start));
	  return 1;
	}
    }


  /* Now try peeking arbitrary ranges and verifying it is the same.
     We expect the U area is already a random enough pattern.  */
  for (start = 0; start + REGALIGN <= sizeof u.byte; start += REGALIGN)
    {
      /* Peek for the U comparation.  */
      errno = 0;
      l = ptrace (PTRACE_PEEKUSER, child, (void *) (unsigned long) start,
		  NULL);
      assert_perror (errno);

      /* Verify it matches.  */
      if (*(unsigned long *) (u.byte + start) != l)
	{
	  printf ("mismatch at offset %#x: poked %lx but peeked %lx\n",
		  start, *(unsigned long *) (u.byte + start), l);
	  return 1;
	}
    }


  return 0;
}

#endif	/* PTRACE_SETREGS */
