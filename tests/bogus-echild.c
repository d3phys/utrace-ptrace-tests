/* Repeatedly fork+exit and wait for its death - all while both parent
   and child are ptraced.
   Bug we look for is waitpid returning bogus ECHILD.

   This software is provided 'as-is', without any express or implied
   warranty.  In no event will the authors be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely.  */

#define _GNU_SOURCE 1
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <sched.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
/* #include <pthread.h> */
/* Dance around ptrace.h + user.h incompatibility */
#ifdef __ia64__
# define ia64_fpreg ia64_fpreg_DISABLE
# define pt_all_user_regs pt_all_user_regs_DISABLE
#endif
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#ifdef __ia64__
# undef ia64_fpreg
# undef pt_all_user_regs
#endif
#include <sys/user.h>
#if defined __i386__ || defined __x86_64__
# include <sys/debugreg.h>
#endif

static int verbose;

#define VERBOSE(...) do { \
  if (verbose) \
    { \
      printf (__VA_ARGS__); \
      fflush (stdout); \
    } \
} while (0)

static pid_t child;
static pid_t grandchild;

static void
sigkill (pid_t * pp)
{
  pid_t pid = *pp;
  *pp = 0;
  if (pid > 0)
    kill (pid, SIGKILL);
}

static void
cleanup (void)
{
  sigkill (&grandchild);
  sigkill (&child);
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

/****************** Standard scaffolding ends here ****************/

/*
 * Extended commentary of the entire test.
 *
 * The bug was introduced in kernel 3.0 and fixed in 3.2.
 * The bug is not deterministic:
 * it is a race condition when not-yet-waited-for ptraced zombie
 * could be skipped by the waitpid logic, resulting in ECHILD return.
 * Single forking+waitpid'ing process under ptrace triggers the bug
 * in ~30 seconds on 4-core Intel Core i7-2620M machine.
 *
 * TODO: make it run many instances, at least one per core -
 * this triggers the bug much faster.
 */

/* If the test is not deterministic:
 * Amount of seconds needed to almost 100% catch it */
#define DEFAULT_TESTTIME 60

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
  int status;

  VERBOSE (".");
  alarm (2);

  child = fork();
  assert(child >= 0);
  if (child == 0)
    {
      time_t t = time (NULL);
      while (t == time (NULL))
        {
          grandchild = fork();
          assert(grandchild >= 0);
	  if (grandchild == 0)
	    _exit(0);
          /* The observed bug is waitpid sometimes reporting ECHILD
	   * under ptrace, even though child does exist.
	   * (Child must be ptraced too).
	   */
	  if (waitpid(-1, NULL, 0) < 0)
            {
	      VERBOSE("BUG: waitpid in tracee: %m\n");
	      _exit(1);
	    }
	}
      _exit(42);
    }

  assert(ptrace(PTRACE_ATTACH, child, 0, 0) == 0);
  assert(waitpid(-1, NULL, 0) == child);
  assert(ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACEFORK) == 0);

  pid = child;
  do
    {
      ptrace(PTRACE_CONT, pid, 0, 0);
      pid = waitpid(-1, &status, 0);
      if (pid > 0 && WIFEXITED(status))
        {
          if (pid == child && WEXITSTATUS(status) == 42)
            return; /* child did not see errors */
          if (/*pid == grandchild (WRONG!) && */ WEXITSTATUS(status) == 0)
            continue; /* grandchild exited */
          _exit(WEXITSTATUS(status)); /* child did see error */
        }
    }
  while (pid > 0);

  VERBOSE("tracer's waitpid ended unexpectedly\n");
  _exit(1);
}

int
main (int argc, char **argv)
{
  int i;
  char *env_testtime = getenv ("TESTTIME");	/* misnomer */
  int testtime = (env_testtime ? atoi (env_testtime) : DEFAULT_TESTTIME);

  setbuf (stdout, NULL);
  atexit (cleanup);
  signal (SIGINT, handler_fail);
  signal (SIGABRT, handler_fail);
  signal (SIGALRM, handler_fail);
  verbose = (argc - 1);

  for (i = 0; i < testtime; i++)
    {
      /* One-second run is implemented in reproduce function instead.
      time_t t = time (NULL);
      while (t == time (NULL))
	reproduce ();
      */
      reproduce ();
    }
  VERBOSE ("\n");

  return 0;
}
