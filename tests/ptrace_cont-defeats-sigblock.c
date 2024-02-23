/* Test whether signal injected by PTRACE_CONT can be blocked.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#ifdef __ia64__
# define ia64_fpreg ia64_fpreg_DISABLE
# define pt_all_user_regs pt_all_user_regs_DISABLE
#endif	/* __ia64__ */
#include <sys/ptrace.h>
#ifdef __ia64__
# undef ia64_fpreg
# undef pt_all_user_regs
#endif	/* __ia64__ */
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
# include <sys/debugreg.h>
#endif

#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <assert.h>
#include <sys/wait.h>
#include <sys/syscall.h>

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
  sigset_t set;
  signal (SIGABRT, SIG_DFL);
  signal (SIGALRM, SIG_DFL);
  /* SIGALRM may be blocked in sighandler, need to unblock */
  sigfillset (&set);
  sigprocmask (SIG_UNBLOCK, &set, NULL);
  /* Due to kernel bugs, waitpid may block. Need to have a timeout */
  alarm (1);
  cleanup ();
  assert (0);
}

/*
 * The bug is quite simple. Even if tracee has signal masked, PTRACE_CONT
 * with signal injection causes signal to be delivered and handled.
 *
 * Seems to be an utrace bug. Present on 2.6.29-0.28.rc1.fc11.x86_64 at least.
 * Vanilla 2.6.28 is ok.
 * The bug is deterministic.
 */

/* Test a few times, just for fun */
#define DEFAULT_LOOPS 30

/* If nothing strange happens, just returns.
 * Notable events (which are not bugs) print some sort of marker
 * is verbose is on, but still continue and return normally.
 * Known bugs also print a message if verbose, but they exit (1).
 * New bugs are likely to trip asserts or cause hang/kernel crash :)
 */
static void
reproduce (void)
{
  pid_t pid;
  long l;
  int status;

  VERBOSE (".");
  alarm (1);

  child = fork ();
  assert (child != -1);
  if (child == 0)
    {
      sigset_t sigset;

      l = ptrace (PTRACE_TRACEME, 0, NULL, NULL);
      assert (l == 0);

      sigemptyset (&sigset);
      sigaddset (&sigset, SIGUSR1);
      sigprocmask (SIG_BLOCK, &sigset, NULL);
      raise (SIGSTOP);
      raise (SIGSTOP);
      sigprocmask (SIG_UNBLOCK, &sigset, NULL);
      _exit (42);
    }

  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status));
  /* We are at the first raise (SIGSTOP). */
  assert (WSTOPSIG (status) == SIGSTOP);

  /* Restart, inject SIGUSR1.
   * It must be blocked by tracee and tracee stops on next SIGSTOP.
   */
  errno = 0;
  l = ptrace (PTRACE_CONT, child, (void *) (long) 0, (void *) (long) SIGUSR1);
  assert_perror (errno);
  assert (l == 0);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  // The bug this test was written for
  if (WIFSIGNALED (status))
    {
      assert (WTERMSIG (status) == SIGUSR1);
      VERBOSE ("signal was blocked but it still killed tracee!\n");
      exit(1);
    }
  /* We are at the second raise (SIGSTOP) */
  assert (WIFSTOPPED (status) && WSTOPSIG (status) == SIGSTOP);

  /* Restart without injecting signal.
   * Tracee unblocks pending SIGUSR1 and immediately has it raised.
   */
  l = ptrace (PTRACE_CONT, child, (void *) (long) 0, (void *) (long) 0);
  assert_perror (errno);
  assert (l == 0);
  pid = waitpid (child, &status, 0);
  assert (pid == child);
  assert (WIFSTOPPED (status) && WSTOPSIG (status) == SIGUSR1);

  cleanup ();
}

int
main (int argc, char **argv)
{
  int i;
#if defined DEFAULT_TESTTIME || defined DEFAULT_LOOPS
  char *env_testtime = getenv ("TESTTIME"); /* misnomer */
  int testtime = (env_testtime ? atoi (env_testtime) : 1);
#endif

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  verbose = (argc - 1);

#if defined DEFAULT_TESTTIME
  testtime *= DEFAULT_TESTTIME;
  for (i = 0; i < testtime; i++)
    {
      time_t t = time (NULL);
      while (t == time (NULL))
        reproduce ();
    }
  VERBOSE ("\n");
#elif defined DEFAULT_LOOPS
  testtime *= DEFAULT_LOOPS;
  for (i = 0; i < testtime; i++)
    reproduce ();
  VERBOSE ("\n");
#else
  reproduce ();
#endif

  return 0;
}
