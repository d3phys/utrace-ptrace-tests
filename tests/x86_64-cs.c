/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Fedora 8 x86_64 and i386 reliable kernel crash for an unprivileged user.
   It changes the CS segment register.  PTRACE_SINGLESTEP is essential for the
   reproducibility.  */

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
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/wait.h>
#include <stddef.h>

#if !defined __i386__ && !defined __x86_64__

int main (void)
{
  return 77;
}

#else	/* defined __i386__ || defined __x86_64__ */

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

int main (int argc, char **argv)
{
  long l;
  int status, i;
  pid_t pid;
  long cs;

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  alarm (10);

  signal (SIGUSR1, SIG_IGN);
  signal (SIGUSR2, SIG_IGN);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);
    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);
      i = raise (SIGUSR1);
      assert (i == 0);
      i = raise (SIGUSR2);
      assert (i == 0);
      assert (0);
    default:
      break;
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  cs = 0xFFFF;

  l = ptrace (PTRACE_POKEUSER, child,
# ifdef __i386__
	      (void *) offsetof (struct user_regs_struct, xcs),
# else
	      (void *) offsetof (struct user_regs_struct, cs),
# endif
	      (void *) cs);
  assert (l == 0);

  l = ptrace (PTRACE_CONT, child, NULL, NULL);
  assert (l == 0);

  pid = waitpid (child, &status, 0);
  assert (pid == child);

  /* In fact any non-crashing kernel is a PASS, we just check the expected
     value here but even an unexpected value is still a PASS.  */

  if (WIFSIGNALED (status))
    {
# ifdef __i386__
      /* kernel-2.4.21-50.EL.ia32e  */
      if (WTERMSIG (status) == SIGKILL)
	return 0;
# endif
# ifdef __x86_64__
      /* kernel-2.6.23.17-88.fc7.x86_64 */
      if (WTERMSIG (status) == SIGSEGV)
	return 0;
# endif
      fprintf (stderr, "%s: WIFSIGNALED - WTERMSIG = %d\n",
	       argv[0], (int) WTERMSIG (status));
      return 0;
    }

  if (WIFSTOPPED (status))
    {
# ifdef __i386__
      /* Resuming with the bad %cs value causes a SIGSEGV.  */
      if (WSTOPSIG (status) == SIGSEGV)
	return 0;
# endif
# ifdef __x86_64__
      /* The %cs value is actually ignored on 64-bit, so it should be happy.  */
      if (WSTOPSIG (status) == SIGUSR2)
	return 0;
# endif
# ifdef __i386__
      /* linux-2.6.26.i386 */
      if (WTERMSIG (status) == SIGILL)
	return 0;
# endif
      fprintf (stderr, "%s: WIFSTOPPED - WSTOPSIG = %d\n",
	       argv[0], (int) WSTOPSIG (status));
      return 0;
    }

  fprintf (stderr, "%s: !WIFSIGNALED && !WIFSTOPPED: status %d\n", argv[0],
	   status);
  assert (0);
  /* NOTREACHED */
}

#endif	/* defined __i386__ || defined __x86_64__ */
