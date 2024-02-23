/* Simple test whether PTRACE_SINGLESTEP stops at all.

   Based on testcase by Wenji Huang <wenji.huang AT oracle.com>

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.
*/

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>

static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)

static pid_t child;

static void
cleanup (void)
{
  if (child > 0)
    kill (child, SIGKILL);
  child = 0;
  while (waitpid (-1, NULL, __WALL) > 0)
    continue;
}

static void
handler_fail (int signo)
{
  cleanup ();
  signal (SIGABRT, SIG_DFL);
  assert (0);
}

#define NUM_SINGLESTEPS 1

static void
reproduce (void)
{
  int i, status;
  pid_t pid;

  alarm (5);

  child = fork ();
  assert (child >= 0);
  if (child == 0)
    {
      errno = 0;
      ptrace (PTRACE_TRACEME, 0, (void *) 0, (void *) 0);
      raise (SIGSTOP);
      assert (!errno);
      /* Loop in userspace, just for singlestepping. */
#define x_10000      2845218640
#define x_100000      180235552
#define x_1000000    4074525504
#define x_10000000   1483440256
#define x_100000000  1116472576
#define x_1000000000 2621190656
      uint32_t x = 0;
      do
	x = x * 1664525 + 1013904223;
      while (x != x_10000);
      _exit (42);
    }

  errno = 0;
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  assert (WSTOPSIG (status) == SIGSTOP);

  for (i = 0; i < NUM_SINGLESTEPS; i++)
    {
      ptrace (PTRACE_SINGLESTEP, child, (void *) 0, (void *) 0);
      assert (!errno);
      pid = waitpid (child, &status, 0);
      assert (pid == child);
      /* Known bug in 2.6.28-rc7 + utrace patch:
       * child was left to run freely, and exited
       * Deterministic (happens even with NUM_SINGLESTEPS = 1)
       */
      if (WIFEXITED (status))
	{
	  VERBOSE("PTRACE_SINGLESTEP did not stop (step #%d)\n", i+1);
	  assert (WEXITSTATUS (status) == 42);
	  exit (1);
	}
      assert (WIFSTOPPED (status));
      assert (WSTOPSIG (status) == SIGTRAP);
    }

  alarm (0);
  cleanup ();
}

int
main (int argc, char **argv)
{
  verbose = (argc - 1);
  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGABRT, handler_fail);
  signal (SIGINT, handler_fail);
  signal (SIGALRM, handler_fail);

  reproduce ();

  return 0;
}
