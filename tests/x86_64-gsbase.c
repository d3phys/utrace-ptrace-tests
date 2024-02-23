/* Test case for x86_64 ptrace access to fs_base/gs_base.

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
#include <sys/ptrace.h>
#include <stddef.h>
#include <errno.h>

#ifndef __x86_64__

int main (void)
{
  return 77;
}

#else

#include <asm/prctl.h>
#include <asm/unistd.h>

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

static volatile int check1, check2;

int main (void)
{
  pid_t got_pid;
  int i, status;
  long l;

  assert (&check1 + 1 < (int *) (1ULL << 32));
  assert (&check2 + 1 < (int *) (1ULL << 32));

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      break;

    case 0:

      errno = 0;
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      l = syscall (__NR_arch_prctl, ARCH_SET_GS, &check1);
      assert_perror (errno);
      assert (l == 0);

      asm volatile ("movl %0,%%gs:0" : : "ir" (0xbabe) : "memory");
      assert (check1 == 0xbabe);

      i = raise (SIGUSR1);
      assert (i == 0);

      assert (check1 == 0xbabe);
      asm volatile ("movl %0,%%gs:0" : : "ir" (0xd00d) : "memory");
      assert (check1 == 0xbabe);
      assert (check2 == 0xd00d);

      _exit (0);
      /* NOTREACHED */

    default:
      break;
    }

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  errno = 0;
  l = ptrace (PTRACE_PEEKUSER, child,
	      (void *) offsetof (struct user_regs_struct, gs_base), NULL);
  assert_perror (errno);
  assert (l == (unsigned long) &check1);

  l = ptrace (PTRACE_POKEUSER, child,
	      (void *) offsetof (struct user_regs_struct, gs_base), &check2);
  assert_perror (errno);
  assert (l == 0);

  l = ptrace (PTRACE_CONT, child, 0l, 0l);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFEXITED (status));
  assert (WEXITSTATUS (status) == 0);

  return 0;
}

#endif
