/* Test case for PTRACE_DETACH after finished PTRACE_SINGLESTEP.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
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

int
main (void)
{
  pid_t got_pid;
  int status, i;
  long l;

  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);

  child = fork ();
  switch (child)
    {
    case -1:
      assert_perror (errno);
      assert (0);

    case 0:
      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert_perror (errno);
      assert (l == 0);

      i = raise (SIGUSR1);
      assert_perror (errno);
      assert (i == 0);

      _exit (0x23);

    default:
      break;
    }

  got_pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGUSR1);

  errno = 0;
  l = ptrace (PTRACE_SINGLESTEP, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (got_pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGTRAP);

  errno = 0;
  l = ptrace (PTRACE_DETACH, child, NULL, NULL);
  assert_perror (errno);
  assert (l == 0);

  got_pid = waitpid (child, &status, 0);
  assert_perror (errno);
  assert (got_pid == child);

  if (WIFEXITED (status) && WEXITSTATUS (status) == 0x23)
    return 0;

  if (WIFSIGNALED (status) && WTERMSIG (status) == SIGTRAP)
    return 1;

  fprintf (stderr, "unexpected status %#x\n", status);
  return 2;
}
