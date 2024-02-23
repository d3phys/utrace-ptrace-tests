/* This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.
   
   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

/* Here we fail on PTRACE_DETACH by ESRCH on kernel-2.6.20-1.3045.fc7.x86_64 .
   The test passes on kernel.org linux-2.6.20.4.x86_64 .  */

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

#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <error.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
#include <string.h>


static void
child_f (void)
{
  for (;;)
    pause ();
  /* NOTREACHED */
  abort ();
  /* NOTREACHED */
}

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
}

static void
handler (int signo)
{
  cleanup ();
  signal (signo, SIG_DFL);
  raise (signo);
}

static void
timeout (int signo)
{
  //  abort ();
  fprintf (stderr, "timeout\n");
  exit (1);
}

static void
expect_signal (pid_t pid, int signo)
{
  int status;
  pid_t i = waitpid (pid, &status, 0);
  if (i < 0)
    error (1, errno, "waitpid");
  else if (i != pid)
    error (1, 0, "waitpid -> %d != %d", i, pid);
  else if (!WIFSTOPPED (status))
    error (1, 0, "waitpid %d -> %#x, not WIFSTOPPED", i, status);
  else if (WSTOPSIG (status) != signo)
    error (1, 0, "waitpid %d -> WSTOPSIG %d, not %d",
	   i, WSTOPSIG (status), signo);
}

int main (void)
{
  int i;
  void (*handler_orig) (int signo);

  child = fork();
  switch (child)
    {
      case -1:
        perror ("fork()");
	exit (1);
	/* NOTREACHED */
      case 0:
        child_f ();
	/* NOTREACHED */
	abort ();
      default:;
	/* PASSTHRU */
    }
  /* Parent.  */

  atexit (cleanup);
  handler_orig = signal (SIGINT, handler);
  assert (handler_orig == SIG_DFL);
  handler_orig = signal (SIGABRT, handler);
  assert (handler_orig == SIG_DFL);
  handler_orig = signal (SIGALRM, timeout);
  assert (handler_orig == SIG_DFL);
  alarm (5);

  i = ptrace (PTRACE_ATTACH, child, NULL, NULL);
  //assert (i == 0);
  if (i != 0) error (1, errno, "PTRACE_ATTACH");

  expect_signal (child, SIGSTOP);

  i = ptrace (PTRACE_CONT, child, NULL, (void *) SIGSTOP);
  //assert (i == 0);
  if (i != 0) error (1, errno, "PTRACE_CONT SIGSTOP");

  expect_signal (child, SIGSTOP);

  // Here we fail on ESRCH on kernel-2.6.20-1.3045.fc7.x86_64 .
  i = ptrace (PTRACE_DETACH, child, NULL, NULL);
  //assert (i == 0);
  if (i != 0) error (1, errno, "PTRACE_DETACH");

  // Process should be left running (not stopped) here.

  //  puts ("OK");
  //return 0;
  exit (0);
}
