/* Test case for PTRACE_ATTACH of a SIGSTOPped debuggee still before a WAITPID.

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

#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stddef.h>
#include <errno.h>

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

static void
handler_ok (int signo)
{
  /* PASS */
  exit (0);
}

int main (void)
{
  pid_t got_pid;
  int i, status;
  long l;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);
  i = alarm (10);
  assert (i == 0);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      break;

    case 0:
      /* `kill (child, SIGSTOP)' does not reproduce the kernel bug.  */
      i = raise (SIGSTOP);
      assert (i == 0);

      assert (0);
      /* NOTREACHED */

    default:
      break;
    }

  i = sleep (1);
  assert (i == 0);

  errno = 0;
  l = ptrace (PTRACE_ATTACH, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  /* We should hang on the second WAITPID.  */

  signal (SIGALRM, handler_ok);
  i = alarm (1);
  assert (i > 0);

  got_pid = waitpid (child, &status, 0);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == 0);

  /* FAIL */
  return 1;
}
